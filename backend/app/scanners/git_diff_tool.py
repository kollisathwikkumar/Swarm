from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.scanners.code_engines import extract_polyglot_file_facts
from app.scanners.tool_runner import run_command_capture


@dataclass
class ChangedFileSummary:
    path: str
    status: str  # added | modified | deleted | renamed
    additions: int = 0
    deletions: int = 0
    changed_lines: list[int] = field(default_factory=list)
    patch: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "additions": self.additions,
            "deletions": self.deletions,
            "changed_lines": self.changed_lines,
            "patch": self.patch,
        }


_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.*?) b/(.*?)$")
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff_text: str) -> list[ChangedFileSummary]:
    if not diff_text or not diff_text.strip():
        return []

    files: list[ChangedFileSummary] = []
    current: ChangedFileSummary | None = None
    current_patch_lines: list[str] = []
    new_line_no = 0
    in_hunk = False

    for line in diff_text.splitlines():
        m_hdr = _DIFF_HEADER_RE.match(line)
        if m_hdr:
            if current is not None:
                current.patch = "\n".join(current_patch_lines)
                files.append(current)
            a_path, b_path = m_hdr.group(1), m_hdr.group(2)
            current = ChangedFileSummary(path=b_path if b_path != "/dev/null" else a_path, status="modified")
            current_patch_lines = [line]
            in_hunk = False
            continue

        if current is None:
            continue

        current_patch_lines.append(line)

        if line.startswith("new file mode"):
            current.status = "added"
        elif line.startswith("deleted file mode"):
            current.status = "deleted"
        elif line.startswith("rename from"):
            current.status = "renamed"
        elif line.startswith("--- /dev/null"):
            current.status = "added"
        elif line.startswith("+++ /dev/null"):
            current.status = "deleted"

        m_hunk = _HUNK_RE.match(line)
        if m_hunk:
            new_line_no = int(m_hunk.group(3))
            in_hunk = True
            continue

        if in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                current.additions += 1
                current.changed_lines.append(new_line_no)
                new_line_no += 1
            elif line.startswith("-") and not line.startswith("---"):
                current.deletions += 1
            elif line.startswith(" ") or line == "":
                new_line_no += 1

    if current is not None:
        current.patch = "\n".join(current_patch_lines)
        files.append(current)

    return files


def _python_ast_summary(file_path: Path) -> dict[str, Any]:
    try:
        src = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except (OSError, SyntaxError, ValueError):
        return {}
    functions = []
    classes = []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append({"name": node.name, "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno)})
        elif isinstance(node, ast.ClassDef):
            classes.append({"name": node.name, "line": node.lineno})
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return {"functions": functions[:30], "classes": classes[:20], "imports": sorted(set(imports))[:30]}


async def collect_diff_context(
    workspace_dir: Path,
    *,
    base_commit: str,
    target_commit: str,
    diff_text: str,
    changed_files: list[dict[str, Any]],
) -> dict[str, Any]:
    parsed = parse_unified_diff(diff_text)
    if not parsed and changed_files:
        for cf in changed_files:
            patch = cf.get("patch", "")
            sub_parsed = parse_unified_diff(
                f"diff --git a/{cf['path']} b/{cf['path']}\n--- a/{cf['path']}\n+++ b/{cf['path']}\n{patch}"
                if patch and not patch.startswith("diff --git")
                else patch
            )
            if sub_parsed:
                parsed.extend(sub_parsed)
            else:
                parsed.append(
                    ChangedFileSummary(
                        path=cf["path"],
                        status=cf.get("status", "modified"),
                        additions=int(cf.get("additions", 0)),
                        deletions=int(cf.get("deletions", 0)),
                        changed_lines=list(cf.get("changed_lines", [])),
                        patch=patch,
                    )
                )

    git_stat = ""
    if (workspace_dir / ".git").exists() and base_commit and target_commit not in ("WORKING_TREE", "STAGED", "UNSTAGED"):
        res = await run_command_capture(
            ["git", "diff", "--stat", f"{base_commit}..{target_commit}"],
            cwd=workspace_dir,
            timeout=30,
        )
        if res["returncode"] == 0:
            git_stat = res["stdout"].strip()

    ast_symbols: dict[str, Any] = {}
    for f in parsed:
        if f.path.endswith(".py") and f.status != "deleted":
            p = workspace_dir / f.path
            if p.exists():
                ast_symbols[f.path] = _python_ast_summary(p)

    active_paths = [f.path for f in parsed if f.status != "deleted"]
    polyglot_symbols = extract_polyglot_file_facts(workspace_dir, active_paths, limit=40)

    return {
        "base_commit": base_commit,
        "target_commit": target_commit,
        "total_files": len(parsed),
        "total_additions": sum(f.additions for f in parsed),
        "total_deletions": sum(f.deletions for f in parsed),
        "git_stat": git_stat,
        "files": [f.to_dict() for f in parsed],
        "python_ast_symbols": ast_symbols,
        "polyglot_symbols": polyglot_symbols,
    }
