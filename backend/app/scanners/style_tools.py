from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from app.scanners.code_engines import prioritize_repo_files, verify_code_syntax
from app.scanners.tool_runner import resolve_binary, run_command_capture


def _analyze_code_style_and_duplicates(
    workspace_dir: Path, target_files: list[str]
) -> dict[str, Any]:
    style_issues: list[dict[str, Any]] = []
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
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
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

    return {"complexity_and_style": style_issues[:25], "duplicates": duplicates[:15]}


async def run_style_scanners(
    workspace_dir: Path, changed_file_paths: list[str]
) -> dict[str, Any]:
    existing_targets = [
        rel
        for rel in changed_file_paths
        if (workspace_dir / rel).exists() and (workspace_dir / rel).is_file()
    ]
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

    if ruff_bin and py_targets:
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

    ast_res = _analyze_code_style_and_duplicates(workspace_dir, existing_targets)

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

    return {
        "ruff": {
            "status": ruff_status,
            "error": ruff_error,
            "findings": ruff_findings,
        },
        "ast_checks": {
            "status": "completed",
            "findings": ast_res["complexity_and_style"] + ast_res["duplicates"],
        },
    }
