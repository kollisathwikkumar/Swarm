from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from app.cache.review_cache import (
    SCANNER_CACHE_SCHEMA_VERSION,
    ReviewCache,
    hash_files_content,
)
from app.scanners.code_engines import prioritize_repo_files, verify_code_syntax
from app.scanners.tool_runner import (
    get_tool_version,
    resolve_binary,
    resolve_workspace_binary,
    run_command_capture,
)

_CAMEL_NAME_RE = re.compile(r"^[a-z]+[A-Z][A-Za-z0-9]*$")
_SNAKE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _max_control_depth(node: ast.AST, depth: int = 0) -> int:
    max_d = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.Try)):
            max_d = max(max_d, _max_control_depth(child, depth + 1))
        else:
            max_d = max(max_d, _max_control_depth(child, depth))
    return max_d


def _check_unreachable_in_block(stmts: list[ast.stmt], rel_path: str, out: list[dict[str, Any]]) -> None:
    term_idx: int | None = None
    for idx, stmt in enumerate(stmts):
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            term_idx = idx
            break
    if term_idx is not None and term_idx + 1 < len(stmts):
        dead_stmt = stmts[term_idx + 1]
        out.append(
            {
                "tool": "dead-code-analyzer",
                "rule_id": "DEAD-UNREACHABLE-CODE",
                "file_path": rel_path,
                "line_number": getattr(dead_stmt, "lineno", 1),
                "severity": "Medium",
                "message": f"Unreachable statement at line {getattr(dead_stmt, 'lineno', 1)} after return/raise/break/continue.",
            }
        )
    for stmt in stmts:
        for attr in ("body", "orelse", "finalbody"):
            sub = getattr(stmt, attr, None)
            if isinstance(sub, list) and sub and all(isinstance(s, ast.stmt) for s in sub):
                _check_unreachable_in_block(sub, rel_path, out)


def _check_dead_and_conventions(
    rel_path: str,
    tree: ast.Module,
    src: str,
    structure_index: dict[str, Any] | None,
    style_issues: list[dict[str, Any]],
    dead_code: list[dict[str, Any]],
) -> None:
    # Unreachable code blocks inside functions and module body
    _check_unreachable_in_block(tree.body, rel_path, dead_code)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_unreachable_in_block(node.body, rel_path, dead_code)

    # Unreferenced module-private helper functions (`_helper` defined without @decorator and never referenced)
    used_names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("_")
            and not node.name.startswith("__")
            and not node.decorator_list
            and node.name not in used_names
            and f"{node.name}" not in src.replace(f"def {node.name}", "")
        ):
            dead_code.append(
                {
                    "tool": "dead-code-analyzer",
                    "rule_id": "DEAD-UNUSED-PRIVATE-SYMBOL",
                    "file_path": rel_path,
                    "line_number": node.lineno,
                    "severity": "Low",
                    "message": f"Private function `{node.name}` appears unreferenced within `{rel_path}`.",
                }
            )

    # Existing-pattern & naming convention checks against repository StructureIndex
    if structure_index:
        symbol_by_id = structure_index.get("symbol_by_id") or {}
        py_names = [
            str(s.get("name") or "")
            for s in symbol_by_id.values()
            if str(s.get("file_path") or "").endswith(".py")
            and isinstance(s.get("name"), str)
            and "." not in str(s.get("name"))
            and not str(s.get("name")).startswith("_")
        ]
        snake_cnt = sum(1 for n in py_names if _SNAKE_NAME_RE.match(n))
        camel_cnt = sum(1 for n in py_names if _CAMEL_NAME_RE.match(n))
        repo_prefers_snake = snake_cnt >= max(3, camel_cnt * 2)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                if repo_prefers_snake and _CAMEL_NAME_RE.match(node.name):
                    style_issues.append(
                        {
                            "tool": "ast-style-checker",
                            "rule_id": "STYLE-NAMING-CONVENTION",
                            "file_path": rel_path,
                            "line_number": node.lineno,
                            "severity": "Low",
                            "message": f"Function `{node.name}` uses camelCase while repository Python convention is snake_case.",
                        }
                    )
                # Check existing-pattern duplicate helper across other modules
                other_matches = [
                    s["file_path"]
                    for s in symbol_by_id.values()
                    if s.get("name") == node.name
                    and s.get("file_path") != rel_path
                    and not str(s.get("file_path") or "").endswith((".test.py", "_test.py"))
                ]
                if other_matches and len(node.name) >= 8:
                    style_issues.append(
                        {
                            "tool": "ast-style-checker",
                            "rule_id": "STYLE-EXISTING-PATTERN",
                            "file_path": rel_path,
                            "line_number": node.lineno,
                            "severity": "Low",
                            "message": f"Helper `{node.name}` mirrors an existing symbol in `{other_matches[0]}`; check whether the shared helper can be reused.",
                        }
                    )


def _analyze_code_style_and_duplicates(
    workspace_dir: Path,
    target_files: list[str],
    *,
    structure_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    style_issues: list[dict[str, Any]] = []
    dead_code: list[dict[str, Any]] = []
    block_hashes: dict[str, list[tuple[str, int]]] = {}

    code_exts = (".py", ".ts", ".tsx", ".js", ".jsx")
    candidates = prioritize_repo_files(
        [
            rel
            for rel in target_files
            if rel.endswith(code_exts)
            and (workspace_dir / rel).exists()
            and (workspace_dir / rel).is_file()
        ]
    )
    if not candidates:
        candidates = prioritize_repo_files(
            [
                str(p.relative_to(workspace_dir))
                for p in workspace_dir.rglob("*")
                if p.is_file()
                and p.suffix in code_exts
                and ".git" not in p.parts
                and "node_modules" not in p.parts
                and ".venv" not in p.parts
            ]
        )[:40]

    for rel in candidates[:30]:
        p = workspace_dir / rel
        if p.stat().st_size > 200_000:
            continue
        source = p.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()

        long_lines = [idx + 1 for idx, line in enumerate(lines) if len(line) > 120]
        if long_lines:
            style_issues.append(
                {
                    "tool": "ast-style-checker",
                    "rule_id": "STYLE-LINE-LEN",
                    "file_path": rel,
                    "line_number": long_lines[0],
                    "severity": "Low",
                    "message": f"{len(long_lines)} line(s) exceed 120 characters (first at line {long_lines[0]}).",
                }
            )

        normalized = [
            (i + 1, ln.strip())
            for i, ln in enumerate(lines)
            if ln.strip() and not ln.strip().startswith(("#", "//", "/*"))
        ]
        for i in range(max(0, len(normalized) - 5)):
            window = "\n".join(x[1] for x in normalized[i : i + 6])
            if len(window) < 90:
                continue
            h = hashlib.sha256(window.encode("utf-8")).hexdigest()[:16]
            block_hashes.setdefault(h, []).append((rel, normalized[i][0]))

        if rel.endswith(".py"):
            try:
                tree = ast.parse(source)
                import_count = sum(
                    1 for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                )
                if import_count >= 15:
                    style_issues.append(
                        {
                            "tool": "ast-complexity",
                            "rule_id": "STYLE-HIGH-COUPLING",
                            "file_path": rel,
                            "line_number": 1,
                            "severity": "Low",
                            "message": f"High module coupling ({import_count} import statements); consider splitting responsibilities.",
                        }
                    )
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fn_len = (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno + 1
                        if fn_len > 60:
                            style_issues.append(
                                {
                                    "tool": "ast-complexity",
                                    "rule_id": "STYLE-LONG-FUNCTION",
                                    "file_path": rel,
                                    "line_number": node.lineno,
                                    "severity": "Medium",
                                    "message": f"Function '{node.name}' spans {fn_len} lines (>60); extract focused helpers.",
                                }
                            )
                        depth = _max_control_depth(node)
                        if depth >= 4:
                            style_issues.append(
                                {
                                    "tool": "ast-complexity",
                                    "rule_id": "STYLE-DEEP-NESTING",
                                    "file_path": rel,
                                    "line_number": node.lineno,
                                    "severity": "Medium",
                                    "message": f"Function '{node.name}' has deep control-flow nesting (depth={depth}); use early returns.",
                                }
                            )
                        branches = sum(
                            1
                            for child in ast.walk(node)
                            if isinstance(
                                child,
                                (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.BoolOp),
                            )
                        )
                        if branches >= 8:
                            style_issues.append(
                                {
                                    "tool": "ast-complexity",
                                    "rule_id": "STYLE-COMPLEXITY",
                                    "file_path": rel,
                                    "line_number": node.lineno,
                                    "severity": "Medium",
                                    "message": f"Function '{node.name}' has high branch complexity ({branches} branch nodes).",
                                }
                            )
                _check_dead_and_conventions(rel, tree, source, structure_index, style_issues, dead_code)
            except SyntaxError as exc:
                style_issues.append(
                    {
                        "tool": "python-ast",
                        "rule_id": "SYNTAX-ERROR",
                        "file_path": rel,
                        "line_number": exc.lineno or 1,
                        "severity": "High",
                        "message": f"Python syntax error: {exc.msg}",
                    }
                )
        elif rel.endswith((".ts", ".tsx", ".js", ".jsx")):
            console_lines = [idx + 1 for idx, ln in enumerate(lines) if "console.log(" in ln]
            if console_lines:
                style_issues.append(
                    {
                        "tool": "js-style-checker",
                        "rule_id": "STYLE-CONSOLE-LOG",
                        "file_path": rel,
                        "line_number": console_lines[0],
                        "severity": "Low",
                        "message": f"{len(console_lines)} debug console.log() call(s) found (first at line {console_lines[0]}).",
                    }
                )
            if len(lines) > 500:
                style_issues.append(
                    {
                        "tool": "js-style-checker",
                        "rule_id": "STYLE-FILE-SIZE",
                        "file_path": rel,
                        "line_number": 1,
                        "severity": "Medium",
                        "message": f"Large source file ({len(lines)} lines); consider splitting responsibilities into smaller modules.",
                    }
                )
            import_hits: dict[str, list[int]] = {}
            for idx, ln in enumerate(lines, start=1):
                if "await import(" in ln or "import(" in ln:
                    import_hits.setdefault(ln.strip(), []).append(idx)
            for stmt, hit_lines in import_hits.items():
                if len(hit_lines) >= 3:
                    style_issues.append(
                        {
                            "tool": "js-style-checker",
                            "rule_id": "STYLE-REPEATED-DYNAMIC-IMPORT",
                            "file_path": rel,
                            "line_number": hit_lines[0],
                            "severity": "Low",
                            "message": f"Dynamic import '{stmt[:90]}' is repeated {len(hit_lines)} times (lines {', '.join(map(str, hit_lines[:5]))}); extract a shared helper.",
                        }
                    )

    duplicates: list[dict[str, Any]] = []
    for occurrences in block_hashes.values():
        if len(occurrences) > 1:
            first, second = occurrences[0], occurrences[1]
            duplicates.append(
                {
                    "tool": "duplicate-detector",
                    "rule_id": "STYLE-DUPLICATION",
                    "file_path": second[0],
                    "line_number": second[1],
                    "severity": "Low",
                    "message": f"Duplicated 6+ line code block matching {first[0]}:{first[1]}.",
                }
            )

    return {
        "complexity_and_style": style_issues[:35],
        "duplicates": duplicates[:15],
        "dead_code": dead_code[:25],
    }


async def run_eslint(workspace_dir: Path, targets: list[str]) -> dict[str, Any]:
    """Optional ESLint JSON runner preferring repo-local node_modules/.bin/eslint."""
    js_targets = [t for t in targets if t.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))]
    if not js_targets:
        return {"status": "skipped_no_js_files", "findings": [], "error": ""}
    eslint_bin = resolve_workspace_binary(workspace_dir, "eslint")
    if not eslint_bin:
        return {"status": "optional_unavailable", "findings": [], "error": ""}
    res = await run_command_capture(
        [eslint_bin, "--format", "json", *js_targets[:25]],
        cwd=workspace_dir,
        timeout=60,
    )
    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            items = json.loads(res["stdout"])
            for entry in items:
                raw_fp = str(entry.get("filePath") or "")
                try:
                    rel_fp = str(Path(raw_fp).resolve().relative_to(workspace_dir.resolve()))
                except ValueError:
                    rel_fp = raw_fp
                for msg in entry.get("messages", []) or []:
                    if not msg.get("ruleId"):
                        continue
                    findings.append(
                        {
                            "tool": "eslint",
                            "rule_id": str(msg["ruleId"]),
                            "file_path": rel_fp,
                            "line_number": int(msg.get("line") or 1),
                            "end_line": msg.get("endLine"),
                            "severity": "High" if int(msg.get("severity") or 1) >= 2 else "Medium",
                            "message": str(msg.get("message") or "ESLint violation")[:240],
                        }
                    )
            return {"status": "completed", "findings": findings[:35], "error": ""}
        except json.JSONDecodeError:
            pass
    if res["returncode"] in (0, 1):
        return {"status": "completed", "findings": findings, "error": ""}
    return {"status": "optional_unavailable", "findings": [], "error": res["stderr"][:300]}


async def run_pylint(workspace_dir: Path, targets: list[str]) -> dict[str, Any]:
    """Optional Pylint JSON runner when installed."""
    py_targets = [t for t in targets if t.endswith(".py") and (workspace_dir / t).exists()]
    if not py_targets:
        return {"status": "skipped_no_python_files", "findings": [], "error": ""}
    pylint_bin = resolve_workspace_binary(workspace_dir, "pylint")
    if not pylint_bin:
        return {"status": "optional_unavailable", "findings": [], "error": ""}
    res = await run_command_capture(
        [pylint_bin, "--output-format=json", "--score=n", *py_targets[:20]],
        cwd=workspace_dir,
        timeout=60,
    )
    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            raw = json.loads(res["stdout"])
            for item in raw:
                msg_type = str(item.get("type") or "warning").lower()
                findings.append(
                    {
                        "tool": "pylint",
                        "rule_id": str(item.get("message-id") or item.get("symbol") or "PYLINT"),
                        "file_path": str(item.get("path") or ""),
                        "line_number": int(item.get("line") or 1),
                        "end_line": item.get("endLine"),
                        "severity": "High" if msg_type in ("error", "fatal") else "Medium" if msg_type == "warning" else "Low",
                        "message": str(item.get("message") or "Pylint finding")[:240],
                    }
                )
            return {"status": "completed", "findings": findings[:35], "error": ""}
        except json.JSONDecodeError:
            pass
    return {"status": "completed", "findings": findings, "error": ""}


async def run_style_scanners(
    workspace_dir: Path,
    changed_file_paths: list[str],
    *,
    cache: ReviewCache | None = None,
    commit_context: str = "HEAD",
    config_hash: str = "default",
    plan: dict[str, Any] | None = None,
    structure_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if plan and plan.get("skip_scanners"):
        return {
            "ruff": {
                "status": "skipped_by_plan",
                "error": "",
                "findings": [],
                "note": "Skipped by ReviewPlanner (low-risk/docs-only change)",
            },
            "eslint": {"status": "skipped_by_plan", "error": "", "findings": []},
            "pylint": {"status": "skipped_by_plan", "error": "", "findings": []},
            "dead_code": {"status": "skipped_by_plan", "findings": []},
            "ast_checks": {
                "status": "skipped_by_plan",
                "findings": [],
                "note": "Skipped by ReviewPlanner (low-risk/docs-only change)",
            },
            "cache_hit": False,
        }

    existing_targets = [
        rel
        for rel in changed_file_paths
        if (workspace_dir / rel).exists() and (workspace_dir / rel).is_file()
    ]

    content_hash = ""
    tool_version = ""
    if cache is not None and existing_targets:
        content_hash = hash_files_content(workspace_dir, existing_targets)
        ruff_ver = await get_tool_version("ruff")
        tool_version = f"{SCANNER_CACHE_SCHEMA_VERSION}|ruff={ruff_ver}"
        cached = cache.get(
            "style_scanners",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=config_hash or "default",
            commit_context=commit_context,
        )
        if isinstance(cached, dict):
            return {**cached, "cache_hit": True}

    ruff_bin = resolve_binary("ruff")
    ruff_findings: list[dict[str, Any]] = []
    ruff_status = "completed"
    ruff_error = ""

    py_targets = [f for f in existing_targets if f.endswith((".py", ".pyi"))]
    if not py_targets:
        py_targets = [
            str(p.relative_to(workspace_dir))
            for p in workspace_dir.rglob("*.py")
            if ".git" not in p.parts and ".venv" not in p.parts
        ][:50]

    run_ruff_flag = plan.get("run_ruff", True) if plan else True
    if not run_ruff_flag and not py_targets:
        ruff_status = "skipped_by_plan"
    elif ruff_bin and py_targets:
        res = await run_command_capture(
            [ruff_bin, "check", "--output-format", "json", "--no-fix", *py_targets],
            cwd=workspace_dir,
            timeout=60,
        )
        if res["timed_out"]:
            ruff_status = "incomplete"
            ruff_error = "ruff scan timed out"
        elif res["stdout"].strip():
            try:
                raw_items = json.loads(res["stdout"])
                for item in raw_items:
                    fname = item.get("filename", "")
                    try:
                        rel_path = str(Path(fname).resolve().relative_to(workspace_dir.resolve()))
                    except ValueError:
                        rel_path = fname
                    loc = item.get("location") or {}
                    code = item.get("code") or "RUFF"
                    ruff_findings.append(
                        {
                            "tool": "ruff",
                            "rule_id": code,
                            "file_path": rel_path,
                            "line_number": loc.get("row", 1),
                            "end_line": (item.get("end_location") or {}).get("row"),
                            "severity": "High" if code.startswith(("F82", "E9")) else "Medium" if code.startswith(("F", "B", "E7")) else "Low",
                            "message": item.get("message", "Ruff style violation"),
                        }
                    )
                ruff_status = "completed"
            except json.JSONDecodeError:
                ruff_status = "error"
                ruff_error = res["stderr"] or res["stdout"]
        elif res["returncode"] in (0, 1):
            ruff_status = "completed"
        else:
            ruff_status = "error"
            ruff_error = res["stderr"]
    elif not py_targets:
        ruff_status = "skipped_no_python_files"
    elif not ruff_bin:
        ruff_status = "tool_unavailable"
        ruff_error = "ruff binary not found"

    eslint_res = (
        await run_eslint(workspace_dir, existing_targets)
        if (plan.get("run_eslint", True) if plan else True)
        else {"status": "skipped_by_plan", "findings": [], "error": ""}
    )
    pylint_res = (
        await run_pylint(workspace_dir, existing_targets)
        if (plan.get("run_pylint", True) if plan else True)
        else {"status": "skipped_by_plan", "findings": [], "error": ""}
    )
    ast_res = _analyze_code_style_and_duplicates(
        workspace_dir, existing_targets, structure_index=structure_index
    )

    # Run Node/TypeScript syntax verification on changed JS/TS files so broken syntax is always caught deterministically
    for rel in prioritize_repo_files(existing_targets)[:20]:
        if rel.endswith((".ts", ".mts", ".cts", ".js", ".mjs", ".cjs")):
            target = workspace_dir / rel
            if target.exists() and target.is_file() and target.stat().st_size < 160_000:
                src = target.read_text(encoding="utf-8", errors="replace")
                ok, msg = await verify_code_syntax(rel, src, workspace_dir)
                if not ok:
                    ast_res["complexity_and_style"].append(
                        {
                            "tool": "ts-syntax-checker",
                            "rule_id": "SYNTAX-ERROR",
                            "file_path": rel,
                            "line_number": 1,
                            "severity": "High",
                            "message": msg,
                        }
                    )

    payload = {
        "ruff": {
            "status": ruff_status,
            "error": ruff_error,
            "findings": ruff_findings,
        },
        "eslint": eslint_res,
        "pylint": pylint_res,
        "dead_code": {
            "status": "completed",
            "findings": ast_res["dead_code"],
        },
        "ast_checks": {
            "status": "completed",
            "findings": ast_res["complexity_and_style"] + ast_res["duplicates"],
        },
    }
    if cache is not None and existing_targets and ruff_status in (
        "completed",
        "skipped_no_python_files",
        "skipped_by_plan",
        "tool_unavailable",
    ):
        cache.set(
            "style_scanners",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=config_hash or "default",
            commit_context=commit_context,
            value=payload,
        )
    return {**payload, "cache_hit": False}
