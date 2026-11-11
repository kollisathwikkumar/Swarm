from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from app.scanners.code_engines import is_test_file_path, prioritize_repo_files
from app.services.git_workspace import resolve_within_dir

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request\.|req\.(?:body|query|params|headers)|Body\(|Query\(|Form\(|Header\(|input\(|sys\.argv|os\.environ)"
)
_PATH_SANITIZER_RE = re.compile(r"resolve_within_dir|\.resolve\s*\(|os\.path\.commonpath|secure_filename")
_SQL_SINK_RE = re.compile(r"\.(?:execute|executemany)\s*\(")
_AUTH_GUARD_RE = re.compile(
    r"\b(?:Depends\s*\(.*(?:user|auth|token|session|role|perm)|requireAuth|verifyToken|authenticate|Authorization)\b",
    re.IGNORECASE,
)
_PUBLIC_ROUTE_RE = re.compile(r"/(?:login|signin|signup|register|oauth|callback|webhook|health|docs|openapi)", re.IGNORECASE)
_RANDOM_TOKEN_RE = re.compile(r"\b(?:tok|token|secret|key|password|otp|nonce|session|csrf|salt|auth)\b", re.IGNORECASE)


def _node_contains_name(node: ast.AST, tainted_vars: set[str]) -> str | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted_vars:
            return sub.id
    return None


def _is_dynamic_sql_expr(expr: ast.AST) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return bool(any(isinstance(v, ast.FormattedValue) for v in expr.values))
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Mod, ast.Add)):
        return True
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "format"
    )


def _analyze_python_security(rel_path: str, src: str) -> tuple[list[dict[str, Any]], set[str]]:
    findings: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return findings, surfaces

    has_path_sanitizer_in_file = bool(_PATH_SANITIZER_RE.search(src))

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        fn_src = ast.get_source_segment(src, node) or ""
        tainted: set[str] = set()

        # Identify route handler parameters / request sources
        decs = [ast.unparse(d) if hasattr(ast, "unparse") else "" for d in node.decorator_list]
        dec_joined = " ".join(decs)
        is_route = bool(re.search(r"\b(?:router|app|bp)\.(?:get|post|put|patch|delete|route)\s*\(", dec_joined))
        if is_route:
            surfaces.add("api_endpoints")
            for arg in node.args.args:
                if arg.arg not in ("self", "cls", "db", "session"):
                    tainted.add(arg.arg)
            is_mutating = bool(re.search(r"\b(?:router|app|bp)\.(?:post|put|patch|delete)\s*\(", dec_joined))
            is_public = bool(_PUBLIC_ROUTE_RE.search(dec_joined))
            if is_mutating and not is_public and not _AUTH_GUARD_RE.search(dec_joined + "\n" + fn_src):
                surfaces.add("auth_and_sessions")
                findings.append(
                    {
                        "tool": "security-taint",
                        "rule_id": "AUTHZ-MISSING-ROUTE-GUARD",
                        "file_path": rel_path,
                        "line_number": node.lineno,
                        "severity": "Medium",
                        "title": f"Mutating endpoint `{node.name}` lacks explicit auth dependency/check",
                        "evidence": dec_joined[:220] or f"def {node.name}(...)",
                        "description": "State-changing API route has no detected Depends(auth/user) or authorization validation.",
                    }
                )

        # Collect tainted local assignments inside the function
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign):
                rhs_text = ast.get_source_segment(src, stmt.value) or ""
                src_match = _TAINT_SOURCE_RE.search(rhs_text) or _node_contains_name(stmt.value, tainted)
                if src_match:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            tainted.add(tgt.id)

        # Trace data-flow from tainted variables / dynamic expressions into sinks
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            call_line = getattr(call, "lineno", node.lineno)
            call_txt = (ast.get_source_segment(src, call) or "")[:200]

            # 1. SQL injection sink
            if isinstance(call.func, ast.Attribute) and call.func.attr in ("execute", "executemany") and call.args:
                surfaces.add("sql_or_db")
                sql_arg = call.args[0]
                if _is_dynamic_sql_expr(sql_arg) and "SELECT" in (ast.get_source_segment(src, sql_arg) or "").upper() or (
                    _is_dynamic_sql_expr(sql_arg) and _node_contains_name(sql_arg, tainted)
                ):
                    t_var = _node_contains_name(sql_arg, tainted) or "interpolated expression"
                    findings.append(
                        {
                            "tool": "security-taint",
                            "rule_id": "TAINT-SQL-INJECTION",
                            "file_path": rel_path,
                            "line_number": call_line,
                            "severity": "Critical",
                            "title": "Tainted dynamic SQL query construction",
                            "evidence": f"Source `{t_var}` flows into `{call_txt}`",
                            "description": "Dynamically interpolated SQL string executed directly instead of parameterized bindings.",
                        }
                    )

            # 2. Subprocess / eval / exec / unsafe deserialization sinks
            fn_name = ""
            if isinstance(call.func, ast.Name):
                fn_name = call.func.id
            elif isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
                fn_name = f"{call.func.value.id}.{call.func.attr}"

            if fn_name in ("eval", "exec", "os.system", "os.popen", "pickle.loads"):
                surfaces.add("command_or_eval")
                t_var = _node_contains_name(call, tainted)
                if t_var or fn_name in ("pickle.loads", "eval", "os.system"):
                    findings.append(
                        {
                            "tool": "security-taint",
                            "rule_id": "TAINT-DANGEROUS-SINK",
                            "file_path": rel_path,
                            "line_number": call_line,
                            "severity": "High",
                            "title": f"Dangerous execution/deserialization sink `{fn_name}`",
                            "evidence": f"Sink `{call_txt}`" + (f" receives tainted `{t_var}`" if t_var else ""),
                            "description": f"Use of `{fn_name}` exposes arbitrary code execution or unsafe deserialization.",
                        }
                    )

            if fn_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"):
                surfaces.add("command_or_eval")
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in call.keywords
                )
                t_var = _node_contains_name(call, tainted)
                if shell_true and (t_var or is_route):
                    findings.append(
                        {
                            "tool": "security-taint",
                            "rule_id": "TAINT-CMD-INJECTION",
                            "file_path": rel_path,
                            "line_number": call_line,
                            "severity": "Critical",
                            "title": "Tainted command injection via subprocess(shell=True)",
                            "evidence": f"Source `{t_var or 'route parameter'}` reaches `{call_txt}`",
                            "description": "Untrusted input flows into shell=True subprocess execution.",
                        }
                    )

            # 3. Path traversal sink
            if fn_name in ("open", "Path") and call.args and not has_path_sanitizer_in_file:
                surfaces.add("file_system_io")
                t_var = _node_contains_name(call.args[0], tainted)
                if t_var and (is_route or _TAINT_SOURCE_RE.search(fn_src)):
                    findings.append(
                        {
                            "tool": "security-taint",
                            "rule_id": "TAINT-PATH-TRAVERSAL",
                            "file_path": rel_path,
                            "line_number": call_line,
                            "severity": "High",
                            "title": f"Unconstrained file path operation using `{t_var}`",
                            "evidence": f"Input `{t_var}` reaches `{call_txt}` without path containment check",
                            "description": "File access uses request-derived path without `.resolve()` boundary containment check.",
                        }
                    )

            # 4. Cryptography weaknesses
            if fn_name in ("hashlib.md5", "hashlib.sha1"):
                surfaces.add("cryptography")
                used_non_sec = any(
                    kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                    for kw in call.keywords
                )
                if not used_non_sec:
                    findings.append(
                        {
                            "tool": "security-taint",
                            "rule_id": "CRYPTO-WEAK-HASH",
                            "file_path": rel_path,
                            "line_number": call_line,
                            "severity": "Medium",
                            "title": f"Weak cryptographic hash `{fn_name}`",
                            "evidence": call_txt,
                            "description": "MD5/SHA1 should not be used for security-sensitive digests (pass usedforsecurity=False for checksums).",
                        }
                    )

            if fn_name in ("random.choice", "random.randint", "random.randrange", "random.random") and _RANDOM_TOKEN_RE.search(fn_src):
                surfaces.add("cryptography")
                findings.append(
                    {
                        "tool": "security-taint",
                        "rule_id": "CRYPTO-INSECURE-RANDOM",
                        "file_path": rel_path,
                        "line_number": call_line,
                        "severity": "High",
                        "title": "Non-cryptographic `random` used in security/token context",
                        "evidence": f"`{call_txt}` inside `{node.name}` handling token/secret data",
                        "description": "Replace `random.*` with `secrets.token_urlsafe` / `secrets.choice` for cryptographic unpredictability.",
                    }
                )

    return findings, surfaces


def _analyze_ts_js_security(rel_path: str, src: str) -> tuple[list[dict[str, Any]], set[str]]:
    findings: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    lines = src.splitlines()
    has_req_source = bool(re.search(r"req\.(?:body|query|params|headers)", src))
    for idx, ln in enumerate(lines, start=1):
        stripped = ln.strip()
        if stripped.startswith(("//", "/*", "*")):
            continue
        if re.search(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:", ln) or ".innerHTML =" in ln:
            surfaces.add("xss_dom")
            findings.append(
                {
                    "tool": "security-taint",
                    "rule_id": "TAINT-DOM-XSS",
                    "file_path": rel_path,
                    "line_number": idx,
                    "severity": "High",
                    "title": "Direct HTML injection sink (`dangerouslySetInnerHTML` / `innerHTML`)",
                    "evidence": stripped[:220],
                    "description": "Raw HTML assignment can trigger DOM XSS unless strictly sanitized.",
                }
            )
        if re.search(r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)", ln):
            surfaces.add("cryptography")
            findings.append(
                {
                    "tool": "security-taint",
                    "rule_id": "CRYPTO-WEAK-HASH",
                    "file_path": rel_path,
                    "line_number": idx,
                    "severity": "Medium",
                    "title": "Weak MD5/SHA1 digest via `crypto.createHash`",
                    "evidence": stripped[:220],
                    "description": "Use SHA-256 or stronger cryptographic digests.",
                }
            )
        if has_req_source and re.search(r"\.(?:query|execute)\s*\(\s*`[^`]*\$\{", ln):
            surfaces.add("sql_or_db")
            findings.append(
                {
                    "tool": "security-taint",
                    "rule_id": "TAINT-SQL-INJECTION",
                    "file_path": rel_path,
                    "line_number": idx,
                    "severity": "Critical",
                    "title": "Template-interpolated SQL query with request input",
                    "evidence": stripped[:220],
                    "description": "Untrusted request properties flow directly into template SQL execution.",
                }
            )
    return findings, surfaces


def run_taint_and_threat_analysis(
    workspace_dir: Path,
    target_files: list[str],
    *,
    structure_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Deterministic Security Taint, Data-Flow, Authz Boundary, Cryptography, and Threat-Surface Analyzer.
    """
    candidates = [
        rel
        for rel in prioritize_repo_files(target_files)
        if not is_test_file_path(rel)
    ][:30]

    findings: list[dict[str, Any]] = []
    threat_surfaces: set[str] = set()

    for rel in candidates:
        p = resolve_within_dir(workspace_dir, rel)
        if p is None or not p.is_file() or p.stat().st_size > 200_000:
            continue
        src = p.read_text(encoding="utf-8", errors="replace")
        if rel.endswith((".py", ".pyi")):
            f_list, surf = _analyze_python_security(rel, src)
            findings.extend(f_list)
            threat_surfaces.update(surf)
        elif rel.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            f_list, surf = _analyze_ts_js_security(rel, src)
            findings.extend(f_list)
            threat_surfaces.update(surf)

    graphs = (structure_index or {}).get("graphs") or {}
    callers = graphs.get("called_by") or {}
    # Attach caller exposure counts to security findings for reachability/exploitability triage
    for item in findings:
        fp = item["file_path"]
        matching_callers = sum(len(v) for k, v in callers.items() if k.startswith(f"{fp}::"))
        if matching_callers:
            item["reachability_callers"] = matching_callers

    return {
        "status": "completed",
        "findings": findings[:40],
        "threat_surfaces": sorted(threat_surfaces),
        "error": "",
    }
