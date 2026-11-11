from __future__ import annotations

import ast
import copy
import hashlib
import re
from pathlib import Path
from typing import Any

from app.scanners.tool_runner import run_command_capture
from app.services.git_workspace import resolve_within_dir, validate_git_ref

_ENV_OR_CONFIG_RE = re.compile(
    r"\b(?:os\.getenv|os\.environ|process\.env|SettingsConfigDict|CORS|ALLOWED_ORIGINS|chmod|sudo)\b"
)
_ROUTE_OR_EXPORT_RE = re.compile(
    r"^\s*(?:@(?:router|app)\.(?:get|post|put|patch|delete)|export\s+(?:async\s+)?(?:function|class|interface|type)|"
    r"app\.(?:get|post|put|patch|delete)\s*\()",
    re.MULTILINE,
)
_PERMISSION_TOKEN_RE = re.compile(
    r"\b(?:Depends|auth|role|admin|rbac|permission|token|jwt|oauth|verify|validate|sanitize|hmac)\b",
    re.IGNORECASE,
)
_TS_SIG_RE = re.compile(
    r"^\s*(export\s+)?(?:async\s+)?(?:function\*?|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(\([^)]*\))?",
    re.MULTILINE,
)


class _VarNormalizer(ast.NodeTransformer):
    """Normalize local variable identifiers so variable-only renames produce matching AST fingerprints."""

    def visit_Name(self, node: ast.Name) -> ast.AST:
        return ast.copy_location(ast.Name(id="_VAR", ctx=node.ctx), node)

    def visit_arg(self, node: ast.arg) -> ast.AST:
        copied = copy.copy(node)
        copied.arg = "_ARG"
        return copied


def _extract_python_symbol_map(src: str) -> dict[str, dict[str, Any]]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}

    lines = src.splitlines()
    symbols: dict[str, dict[str, Any]] = {}

    def _signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        args = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
        decs = [ast.unparse(d) if hasattr(ast, "unparse") else "" for d in fn.decorator_list]
        prefix = " ".join(f"@{d}" for d in decs if d)
        return f"{prefix} def {fn.name}({', '.join(args)})".strip()

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end_ln = getattr(node, "end_lineno", node.lineno) or node.lineno
            raw_dump = ast.dump(node, include_attributes=False)
            norm_node = _VarNormalizer().visit(copy.deepcopy(node))
            # Exclude function body docstring when checking cosmetic vs algorithmic edit
            norm_dump = ast.dump(norm_node, include_attributes=False)
            symbols[node.name] = {
                "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                "line": node.lineno,
                "end_line": end_ln,
                "signature": _signature(node),
                "header_line": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else node.name,
                "raw_hash": hashlib.sha256(raw_dump.encode("utf-8")).hexdigest()[:16],
                "norm_hash": hashlib.sha256(norm_dump.encode("utf-8")).hexdigest()[:16],
                "body_text": "\n".join(lines[node.lineno - 1 : end_ln]),
            }
        elif isinstance(node, ast.ClassDef):
            end_ln = getattr(node, "end_lineno", node.lineno) or node.lineno
            symbols[node.name] = {
                "kind": "class",
                "line": node.lineno,
                "end_line": end_ln,
                "signature": f"class {node.name}",
                "header_line": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else node.name,
                "raw_hash": hashlib.sha256(ast.dump(node).encode("utf-8")).hexdigest()[:16],
                "norm_hash": hashlib.sha256(
                    ast.dump(_VarNormalizer().visit(copy.deepcopy(node))).encode("utf-8")
                ).hexdigest()[:16],
                "body_text": "\n".join(lines[node.lineno - 1 : min(end_ln, node.lineno + 30)]),
            }
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qname = f"{node.name}.{child.name}"
                    c_end = getattr(child, "end_lineno", child.lineno) or child.lineno
                    symbols[qname] = {
                        "kind": "method",
                        "line": child.lineno,
                        "end_line": c_end,
                        "signature": _signature(child),
                        "header_line": lines[child.lineno - 1].strip() if child.lineno <= len(lines) else qname,
                        "raw_hash": hashlib.sha256(ast.dump(child).encode("utf-8")).hexdigest()[:16],
                        "norm_hash": hashlib.sha256(
                            ast.dump(_VarNormalizer().visit(copy.deepcopy(child))).encode("utf-8")
                        ).hexdigest()[:16],
                        "body_text": "\n".join(lines[child.lineno - 1 : c_end]),
                    }
    return symbols


def _extract_ts_symbol_map(src: str) -> dict[str, dict[str, Any]]:
    symbols: dict[str, dict[str, Any]] = {}
    lines = src.splitlines()
    for m in _TS_SIG_RE.finditer(src):
        exported = bool(m.group(1))
        name = m.group(2)
        params = (m.group(3) or "").strip()
        line_no = src[: m.start()].count("\n") + 1
        sig = f"{'export ' if exported else ''}{name}{params}".strip()
        snippet = "\n".join(lines[max(0, line_no - 1) : min(len(lines), line_no + 25)])
        symbols[name] = {
            "kind": "ts_exported" if exported else "ts_decl",
            "line": line_no,
            "end_line": min(len(lines), line_no + 25),
            "signature": sig[:160],
            "header_line": lines[line_no - 1].strip() if line_no <= len(lines) else name,
            "raw_hash": hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:16],
            "norm_hash": hashlib.sha256(re.sub(r"\s+", " ", snippet).encode("utf-8")).hexdigest()[:16],
            "body_text": snippet,
        }
    return symbols


async def _read_base_file(workspace_dir: Path, base_commit: str, rel_path: str) -> str | None:
    if not (workspace_dir / ".git").exists():
        return None
    if not base_commit or base_commit in ("HEAD", "WORKING_TREE", "EMPTY_TREE"):
        ref = "HEAD"
    else:
        try:
            ref = validate_git_ref(base_commit)
        except ValueError:
            return None
    res = await run_command_capture(
        ["git", "show", f"{ref}:{rel_path}"],
        cwd=workspace_dir,
        timeout=10,
    )
    if res["returncode"] == 0:
        return res["stdout"]
    return None


async def analyze_ast_and_contract_diff(
    workspace_dir: Path,
    *,
    base_commit: str,
    target_commit: str,
    changed_files: list[dict[str, Any]],
    structure_index: dict[str, Any] | None = None,
    diff_text: str = "",
) -> dict[str, Any]:
    """
    Deterministic AST-aware diff, semantic change classifier, API contract detector,
    configuration/dependency impact analyzer, and downstream blast-radius mapper.
    """
    ast_symbol_changes: list[dict[str, Any]] = []
    api_contract_changes: list[dict[str, Any]] = []
    config_impacts: list[dict[str, Any]] = []
    downstream_impact: dict[str, Any] = {}
    semantic_counts = {
        "added_symbols": 0,
        "removed_symbols": 0,
        "signature_or_contract_changes": 0,
        "permission_or_guard_edits": 0,
        "algorithm_or_logic_edits": 0,
        "cosmetic_or_variable_renames": 0,
    }

    graphs = (structure_index or {}).get("graphs") or {}
    imported_by = graphs.get("imported_by") or {}
    called_by = graphs.get("called_by") or {}
    test_links = graphs.get("test_links") or {}

    for ch in changed_files[:40]:
        rel = str(ch.get("path") or "").strip()
        if not rel:
            continue

        # Downstream consumers per changed file & symbol
        importers = imported_by.get(rel, [])
        linked_tests = test_links.get(rel, [])
        downstream_impact[rel] = {
            "imported_by": importers[:10],
            "linked_tests": linked_tests[:10],
            "blast_radius_count": len(importers),
        }

        # Config / environment / dependency surface changes
        fname = Path(rel).name
        is_cfg_file = fname in {
            "package.json",
            "package-lock.json",
            "pyproject.toml",
            "requirements.txt",
            "poetry.lock",
            "Dockerfile",
            ".env",
            ".env.example",
        } or rel.endswith((".yml", ".yaml", ".toml", ".ini"))
        target_p = resolve_within_dir(workspace_dir, rel)
        target_src = ""
        if target_p and target_p.is_file() and target_p.stat().st_size <= 250_000:
            target_src = target_p.read_text(encoding="utf-8", errors="replace")

        patch_chunk = str(ch.get("patch") or "")
        env_hits = _ENV_OR_CONFIG_RE.findall(patch_chunk or target_src[:8000])
        if is_cfg_file or env_hits:
            config_impacts.append(
                {
                    "file_path": rel,
                    "is_config_or_dependency_file": is_cfg_file,
                    "config_signals": sorted(set(env_hits))[:10],
                }
            )

        is_py = rel.endswith((".py", ".pyi"))
        is_ts_js = rel.endswith((".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"))
        if not (is_py or is_ts_js):
            continue

        base_src = await _read_base_file(workspace_dir, base_commit, rel)
        extractor = _extract_python_symbol_map if is_py else _extract_ts_symbol_map
        base_syms = extractor(base_src) if base_src else {}
        target_syms = extractor(target_src) if target_src else {}

        changed_line_set = set(int(x) for x in (ch.get("changed_lines") or []) if isinstance(x, int))

        # Identify removed symbols
        for name, b_info in base_syms.items():
            if name not in target_syms:
                semantic_counts["removed_symbols"] += 1
                entry = {
                    "file_path": rel,
                    "symbol": name,
                    "change_type": "removed_symbol",
                    "line_number": 1,
                    "old_signature": b_info["signature"],
                    "new_signature": None,
                }
                ast_symbol_changes.append(entry)
                if not name.startswith("_") or b_info["kind"] == "ts_exported" or _ROUTE_OR_EXPORT_RE.search(b_info["header_line"]):
                    api_contract_changes.append(
                        {
                            "file_path": rel,
                            "symbol": name,
                            "line_number": 1,
                            "reason": f"Public symbol or endpoint `{name}` was removed.",
                            "severity": "High" if importers else "Medium",
                        }
                    )

        # Identify added & modified symbols with semantic distinction
        for name, t_info in target_syms.items():
            sym_id = f"{rel}::{name}"
            callers = called_by.get(sym_id, [])
            overlaps_diff = bool(
                changed_line_set
                and any(t_info["line"] <= ln <= t_info["end_line"] for ln in changed_line_set)
            )
            if base_src is not None and name not in base_syms:
                semantic_counts["added_symbols"] += 1
                ast_symbol_changes.append(
                    {
                        "file_path": rel,
                        "symbol": name,
                        "change_type": "added_symbol",
                        "line_number": t_info["line"],
                        "old_signature": None,
                        "new_signature": t_info["signature"],
                        "callers": callers[:6],
                    }
                )
            elif name in base_syms:
                b_info = base_syms[name]
                if b_info["raw_hash"] == t_info["raw_hash"] and not overlaps_diff:
                    continue
                sig_changed = b_info["signature"] != t_info["signature"]
                perm_base = len(_PERMISSION_TOKEN_RE.findall(b_info["body_text"]))
                perm_tgt = len(_PERMISSION_TOKEN_RE.findall(t_info["body_text"]))

                if sig_changed:
                    semantic_kind = "signature_or_contract_change"
                    semantic_counts["signature_or_contract_changes"] += 1
                    api_contract_changes.append(
                        {
                            "file_path": rel,
                            "symbol": name,
                            "line_number": t_info["line"],
                            "reason": f"Signature changed from `{b_info['signature']}` to `{t_info['signature']}`.",
                            "severity": "High" if callers or importers else "Medium",
                        }
                    )
                elif perm_base != perm_tgt:
                    semantic_kind = "permission_or_guard_edit"
                    semantic_counts["permission_or_guard_edits"] += 1
                elif b_info["norm_hash"] == t_info["norm_hash"]:
                    semantic_kind = "cosmetic_or_variable_rename"
                    semantic_counts["cosmetic_or_variable_renames"] += 1
                else:
                    semantic_kind = "algorithm_or_logic_edit"
                    semantic_counts["algorithm_or_logic_edits"] += 1

                ast_symbol_changes.append(
                    {
                        "file_path": rel,
                        "symbol": name,
                        "change_type": semantic_kind,
                        "line_number": t_info["line"],
                        "old_signature": b_info["signature"],
                        "new_signature": t_info["signature"],
                        "callers": callers[:6],
                    }
                )
            elif overlaps_diff:
                semantic_counts["algorithm_or_logic_edits"] += 1
                ast_symbol_changes.append(
                    {
                        "file_path": rel,
                        "symbol": name,
                        "change_type": "modified_in_diff",
                        "line_number": t_info["line"],
                        "new_signature": t_info["signature"],
                        "callers": callers[:6],
                    }
                )

    # Surface concrete API breakage / high blast-radius contract changes as deterministic findings
    det_findings: list[dict[str, Any]] = []
    for api_chg in api_contract_changes[:10]:
        if api_chg.get("severity") == "High":
            det_findings.append(
                {
                    "tool": "diff-ast-engine",
                    "rule_id": "DIFF-API-CONTRACT-CHANGE",
                    "file_path": api_chg["file_path"],
                    "line_number": api_chg["line_number"],
                    "severity": "Medium",
                    "title": f"Breaking/Public API contract change in `{api_chg['symbol']}`",
                    "evidence": api_chg["reason"],
                }
            )

    if diff_text and not changed_files:
        _ = len(diff_text)

    return {
        "status": "completed",
        "base_commit": base_commit,
        "target_commit": target_commit,
        "semantic_counts": semantic_counts,
        "ast_symbol_changes": ast_symbol_changes[:50],
        "api_contract_changes": api_contract_changes[:25],
        "config_and_dependency_impacts": config_impacts[:20],
        "downstream_impact": downstream_impact,
        "findings": det_findings,
    }
