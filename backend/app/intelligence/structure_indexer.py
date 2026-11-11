from __future__ import annotations

import ast
import importlib.util
import logging
import os
import re
from pathlib import Path
from typing import Any

from app.cache.review_cache import (
    STRUCTURE_INDEX_SCHEMA_VERSION,
    ReviewCache,
    hash_config_dict,
    hash_text,
)
from app.scanners.code_engines import (
    CODE_EXTENSIONS,
    extract_file_facts,
    is_test_file_path,
    prioritize_repo_files,
)
from app.services.git_workspace import is_excluded_path, resolve_within_dir

logger = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    "dist",
    "build",
    "coverage",
    "_cache",
}

_TS_JS_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_PY_EXTENSIONS = (".py", ".pyi")

_TS_DECL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:async\s+)?"
    r"(function\*?|class|interface|type|enum|const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
)
_TS_METHOD_RE = re.compile(
    r"^\s*(?:public\s+|private\s+|protected\s+|static\s+|readonly\s+|async\s+)*"
    r"([a-z_$][A-Za-z0-9_$]*)\s*\([^;{}]*\)\s*(?::\s*[^{]+)?\{"
)
_TS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]+?\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]"""
)
_CALL_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALL_STOPWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "throw",
    "new",
    "typeof",
    "await",
    "yield",
    "function",
    "class",
    "import",
    "require",
    "super",
    "print",
    "len",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "isinstance",
    "getattr",
    "hasattr",
}


def is_tree_sitter_available() -> bool:
    """Detect whether optional tree_sitter bindings are installed in this environment."""
    return importlib.util.find_spec("tree_sitter") is not None


def _detect_language(rel_path: str) -> str:
    lower = rel_path.lower()
    if lower.endswith(_PY_EXTENSIONS):
        return "python"
    if lower.endswith((".ts", ".tsx", ".mts", ".cts")):
        return "typescript"
    if lower.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if lower.endswith((".md", ".mdx", ".rst")):
        return "markdown"
    if lower.endswith((".json", ".yml", ".yaml", ".toml", ".ini")):
        return "config"
    if lower.endswith(".sql"):
        return "sql"
    if lower.endswith((".go", ".rs", ".java", ".kt", ".rb", ".php")):
        return Path(lower).suffix.lstrip(".")
    return "text"


def _package_name_for_path(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if len(parts) <= 1:
        return "."
    if len(parts) == 2:
        return parts[0]
    return "/".join(parts[:2])


def _extract_calls_from_slice(lines: list[str], start_line: int, end_line: int) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    slice_lines = lines[max(0, start_line - 1) : max(0, end_line)]
    for raw in slice_lines:
        for match in _CALL_IDENT_RE.finditer(raw):
            name = match.group(1)
            if name in _CALL_STOPWORDS or name in seen:
                continue
            seen.add(name)
            found.append(name)
            if len(found) >= 25:
                return found
    return found


def _parse_python_module(rel_path: str, src: str, lines: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    symbols: list[dict[str, Any]] = []
    imports: set[str] = set()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return symbols, []

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            prefix = "." * getattr(node, "level", 0)
            if prefix or mod:
                imports.add(f"{prefix}{mod}".rstrip(".") if mod else prefix)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end_ln = getattr(node, "end_lineno", node.lineno) or node.lineno
            calls = _extract_python_calls(node)
            symbols.append(
                {
                    "symbol_id": f"{rel_path}::{node.name}",
                    "name": node.name,
                    "kind": "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                    "file_path": rel_path,
                    "start_line": node.lineno,
                    "end_line": end_ln,
                    "signature": lines[node.lineno - 1].strip()[:140] if node.lineno <= len(lines) else node.name,
                    "calls": calls,
                }
            )
        elif isinstance(node, ast.ClassDef):
            cls_end = getattr(node, "end_lineno", node.lineno) or node.lineno
            symbols.append(
                {
                    "symbol_id": f"{rel_path}::{node.name}",
                    "name": node.name,
                    "kind": "class",
                    "file_path": rel_path,
                    "start_line": node.lineno,
                    "end_line": min(cls_end, node.lineno + 15),
                    "class_end_line": cls_end,
                    "signature": lines[node.lineno - 1].strip()[:140] if node.lineno <= len(lines) else node.name,
                    "calls": [],
                }
            )
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m_end = getattr(child, "end_lineno", child.lineno) or child.lineno
                    calls = _extract_python_calls(child)
                    qual_name = f"{node.name}.{child.name}"
                    symbols.append(
                        {
                            "symbol_id": f"{rel_path}::{qual_name}",
                            "name": qual_name,
                            "short_name": child.name,
                            "kind": "method",
                            "file_path": rel_path,
                            "start_line": child.lineno,
                            "end_line": m_end,
                            "signature": (
                                lines[child.lineno - 1].strip()[:140]
                                if child.lineno <= len(lines)
                                else qual_name
                            ),
                            "calls": calls,
                        }
                    )

    # Also catch deeper imports inside functions
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)

    return symbols[:250], sorted(imports)[:80]


def _extract_python_calls(node: ast.AST) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            target_name = ""
            if isinstance(sub.func, ast.Name):
                target_name = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                target_name = sub.func.attr
            if target_name and target_name not in _CALL_STOPWORDS and target_name not in seen:
                seen.add(target_name)
                calls.append(target_name)
                if len(calls) >= 25:
                    break
    return calls


def _find_brace_block_end(lines: list[str], start_idx_zero: int) -> int:
    """Estimate the closing line (1-based) of a brace-delimited TS/JS declaration."""
    depth = 0
    seen_open = False
    max_scan = min(len(lines), start_idx_zero + 250)
    for i in range(start_idx_zero, max_scan):
        ln = lines[i]
        # Skip single-line comments to minimize brace skew
        stripped = ln.strip()
        if stripped.startswith(("//", "*")):
            continue
        opens = ln.count("{")
        closes = ln.count("}")
        if opens > 0:
            seen_open = True
        depth += opens - closes
        if seen_open and depth <= 0:
            return i + 1
        if not seen_open and ln.rstrip().endswith(";"):
            return i + 1
    return min(len(lines), start_idx_zero + 30)


def _parse_ts_js_module(rel_path: str, src: str, lines: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    symbols: list[dict[str, Any]] = []
    imports: set[str] = set()
    for match in _TS_IMPORT_RE.finditer(src):
        imports.add(match.group(1))

    for idx, ln in enumerate(lines, start=1):
        m = _TS_DECL_RE.match(ln)
        if m:
            kind = m.group(1).rstrip("*")
            name = m.group(2)
            end_ln = _find_brace_block_end(lines, idx - 1)
            # For classes, keep class header span compact unless small
            display_end = min(end_ln, idx + 15) if kind == "class" and end_ln - idx > 25 else end_ln
            calls = [] if kind == "class" else _extract_calls_from_slice(lines, idx, end_ln)
            symbols.append(
                {
                    "symbol_id": f"{rel_path}::{name}",
                    "name": name,
                    "kind": kind,
                    "file_path": rel_path,
                    "start_line": idx,
                    "end_line": display_end,
                    "signature": ln.strip()[:140],
                    "calls": calls,
                }
            )
            continue

        m2 = _TS_METHOD_RE.match(ln)
        if m2 and m2.group(1) not in _CALL_STOPWORDS:
            name = m2.group(1)
            end_ln = _find_brace_block_end(lines, idx - 1)
            calls = _extract_calls_from_slice(lines, idx, end_ln)
            symbols.append(
                {
                    "symbol_id": f"{rel_path}::{name}",
                    "name": name,
                    "kind": "method",
                    "file_path": rel_path,
                    "start_line": idx,
                    "end_line": end_ln,
                    "signature": ln.strip()[:140],
                    "calls": calls,
                }
            )
        if len(symbols) >= 250:
            break

    return symbols, sorted(imports)[:80]


def _parse_markdown_or_config(rel_path: str, lines: list[str], lang: str) -> tuple[list[dict[str, Any]], list[str]]:
    symbols: list[dict[str, Any]] = []
    if lang == "markdown":
        for idx, ln in enumerate(lines, start=1):
            if ln.startswith(("# ", "## ", "### ")):
                heading = ln.lstrip("#").strip()[:100]
                symbols.append(
                    {
                        "symbol_id": f"{rel_path}::{heading}",
                        "name": heading,
                        "kind": "heading",
                        "file_path": rel_path,
                        "start_line": idx,
                        "end_line": min(len(lines), idx + 20),
                        "signature": ln.strip()[:120],
                        "calls": [],
                    }
                )
            if len(symbols) >= 25:
                break
    elif lines:
        symbols.append(
            {
                "symbol_id": f"{rel_path}::<module>",
                "name": Path(rel_path).name,
                "kind": lang,
                "file_path": rel_path,
                "start_line": 1,
                "end_line": min(len(lines), 80),
                "signature": Path(rel_path).name,
                "calls": [],
            }
        )
    return symbols, []


def _collect_workspace_paths(
    workspace_dir: Path,
    changed_files: list[dict[str, Any]],
    *,
    max_files: int = 180,
) -> list[str]:
    changed_paths = [
        str(c.get("path")).strip()
        for c in changed_files
        if c.get("path") and not is_excluded_path(str(c.get("path")))
    ]
    discovered: list[str] = []
    ws_resolved = workspace_dir.resolve()

    if ws_resolved.exists():
        for root_str, dirs, files in os.walk(ws_resolved):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
            root_path = Path(root_str)
            for fname in sorted(files):
                rel = str((root_path / fname).resolve().relative_to(ws_resolved)).replace("\\", "/")
                if is_excluded_path(rel):
                    continue
                if rel.endswith((*CODE_EXTENSIONS, ".md", ".yml", ".yaml", ".json", ".toml", ".sql")):
                    discovered.append(rel)
                if len(discovered) >= max_files * 2:
                    break
            if len(discovered) >= max_files * 2:
                break

    prioritized_all = prioritize_repo_files(discovered)
    ordered = list(dict.fromkeys(changed_paths + prioritized_all))
    return ordered[:max_files]


def _resolve_import_target(
    importer_path: str,
    raw_import: str,
    module_paths_set: set[str],
    module_stem_map: dict[str, list[str]],
) -> str | None:
    if not raw_import:
        return None
    # Relative TS/JS import (e.g., ./redaction, ../utils/url)
    if raw_import.startswith(".") and not raw_import.endswith("."):
        base_dir = Path(importer_path).parent
        rel_candidate = os.path.normpath(str(base_dir / raw_import)).replace("\\", "/")
        for suffix in ("", ".ts", ".tsx", ".js", ".jsx", ".py", "/index.ts", "/index.tsx", "/index.js"):
            cand = f"{rel_candidate}{suffix}"
            if cand in module_paths_set:
                return cand

    # Strip JS extension or alias prefix like @/lib/types
    cleaned = raw_import.removeprefix("@/").removeprefix("~/")
    slash_ver = cleaned.replace(".", "/")
    for suffix in ("", ".py", ".ts", ".tsx", ".js", ".jsx"):
        cand = f"{slash_ver}{suffix}"
        if cand in module_paths_set:
            return cand
        for prefix in ("backend/", "src/", "frontend/src/"):
            if f"{prefix}{cand}" in module_paths_set:
                return f"{prefix}{cand}"

    last_part = raw_import.split(".")[-1].split("/")[-1]
    if last_part in module_stem_map and len(module_stem_map[last_part]) == 1:
        candidate = module_stem_map[last_part][0]
        if candidate != importer_path:
            return candidate
    return None


def _index_single_file(
    workspace_dir: Path,
    rel_path: str,
    *,
    cache: ReviewCache | None,
    tool_version: str,
    commit_context: str,
) -> dict[str, Any] | None:
    target = resolve_within_dir(workspace_dir, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return None
    try:
        if target.stat().st_size > 250_000:
            return None
        src = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    content_hash = hash_text(f"{rel_path}\n{src}")
    cfg_hash = hash_config_dict({"rel_path": rel_path, "max_bytes": 250_000})

    if cache is not None:
        cached = cache.get(
            "structure_index",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=cfg_hash,
            commit_context=commit_context,
        )
        if isinstance(cached, dict) and cached.get("file_path") == rel_path:
            return cached

    lines = src.splitlines()
    lang = _detect_language(rel_path)
    if lang == "python":
        symbols, imports = _parse_python_module(rel_path, src, lines)
    elif lang in ("typescript", "javascript"):
        symbols, imports = _parse_ts_js_module(rel_path, src, lines)
    else:
        symbols, imports = _parse_markdown_or_config(rel_path, lines, lang)

    # Fallback module symbol if code file has top-level script without declarations
    if not symbols and lines:
        symbols.append(
            {
                "symbol_id": f"{rel_path}::<top>",
                "name": Path(rel_path).name,
                "kind": "module",
                "file_path": rel_path,
                "start_line": 1,
                "end_line": min(len(lines), 80),
                "signature": Path(rel_path).name,
                "calls": _extract_calls_from_slice(lines, 1, min(len(lines), 120)),
            }
        )

    facts = extract_file_facts(workspace_dir, rel_path)
    guards = facts.get("implemented_guards_in_full_file", {})

    entry = {
        "file_path": rel_path,
        "package": _package_name_for_path(rel_path),
        "language": lang,
        "is_test": is_test_file_path(rel_path),
        "total_lines": len(lines),
        "content_hash": content_hash[:16],
        "imports": imports,
        "symbols": symbols,
        "implemented_guards": guards,
    }

    if cache is not None:
        cache.set(
            "structure_index",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=cfg_hash,
            commit_context=commit_context,
            value=entry,
        )

    return entry


def build_structure_index(
    workspace_dir: Path,
    changed_files: list[dict[str, Any]],
    *,
    cache: ReviewCache | None = None,
    commit_context: str = "HEAD",
    max_files: int = 180,
) -> dict[str, Any]:
    """
    Build a STAIR-style 4-level hierarchical Table of Contents + dependency/call graph:
      Repository -> Package -> Module -> Symbol (with exact line spans & guards).
    """
    tree_sitter_active = is_tree_sitter_available()
    tool_version = f"{STRUCTURE_INDEX_SCHEMA_VERSION}|ts={int(tree_sitter_active)}"
    rel_paths = _collect_workspace_paths(workspace_dir, changed_files, max_files=max_files)

    modules: dict[str, dict[str, Any]] = {}
    packages: dict[str, list[str]] = {}
    languages: set[str] = set()
    symbol_by_id: dict[str, dict[str, Any]] = {}
    symbol_name_to_ids: dict[str, list[str]] = {}
    module_stem_map: dict[str, list[str]] = {}

    for rel in rel_paths:
        mod = _index_single_file(
            workspace_dir,
            rel,
            cache=cache,
            tool_version=tool_version,
            commit_context=commit_context,
        )
        if not mod:
            continue
        modules[rel] = mod
        pkg = mod["package"]
        packages.setdefault(pkg, []).append(rel)
        languages.add(mod["language"])
        stem = Path(rel).stem
        module_stem_map.setdefault(stem, []).append(rel)

        for sym in mod.get("symbols", []):
            sid = sym["symbol_id"]
            symbol_by_id[sid] = sym
            short = sym.get("short_name") or sym["name"].split(".")[-1]
            symbol_name_to_ids.setdefault(short, []).append(sid)
            if "." in sym["name"]:
                symbol_name_to_ids.setdefault(sym["name"], []).append(sid)

    module_paths_set = set(modules.keys())
    imports_graph: dict[str, list[str]] = {}
    imported_by_graph: dict[str, list[str]] = {}
    calls_graph: dict[str, list[str]] = {}
    called_by_graph: dict[str, list[str]] = {}
    test_links: dict[str, list[str]] = {}
    edges_count = 0

    for rel, mod in modules.items():
        resolved_imports: list[str] = []
        for imp in mod.get("imports", []):
            tgt = _resolve_import_target(rel, imp, module_paths_set, module_stem_map)
            if tgt and tgt != rel and tgt not in resolved_imports:
                resolved_imports.append(tgt)
                imported_by_graph.setdefault(tgt, [])
                if rel not in imported_by_graph[tgt]:
                    imported_by_graph[tgt].append(rel)
                edges_count += 1
        if resolved_imports:
            imports_graph[rel] = resolved_imports

        # Test links: map test modules back to source modules they import or name-match
        if mod["is_test"]:
            for tgt in resolved_imports:
                if not modules[tgt]["is_test"]:
                    test_links.setdefault(tgt, [])
                    if rel not in test_links[tgt]:
                        test_links[tgt].append(rel)
            test_stem = Path(rel).stem.removeprefix("test_").removesuffix("_test").removesuffix(".test").removesuffix(".spec")
            for cand in module_stem_map.get(test_stem, []):
                if cand != rel and not modules[cand]["is_test"]:
                    test_links.setdefault(cand, [])
                    if rel not in test_links[cand]:
                        test_links[cand].append(rel)

        # Symbol call graph edges
        for sym in mod.get("symbols", []):
            sid = sym["symbol_id"]
            resolved_callees: list[str] = []
            for call_name in sym.get("calls", []):
                candidates = symbol_name_to_ids.get(call_name, [])
                # Prefer same-file or imported-file matches
                preferred = [
                    c for c in candidates
                    if c != sid and (
                        c.startswith(f"{rel}::")
                        or any(c.startswith(f"{imp_file}::") for imp_file in resolved_imports)
                    )
                ]
                chosen = preferred[:3] if preferred else ([c for c in candidates if c != sid][:2] if len(candidates) <= 3 else [])
                for c_id in chosen:
                    if c_id not in resolved_callees:
                        resolved_callees.append(c_id)
                        called_by_graph.setdefault(c_id, [])
                        if sid not in called_by_graph[c_id]:
                            called_by_graph[c_id].append(sid)
                        edges_count += 1
            if resolved_callees:
                calls_graph[sid] = resolved_callees

    return {
        "schema_version": STRUCTURE_INDEX_SCHEMA_VERSION,
        "tree_sitter_active": tree_sitter_active,
        "files_indexed": len(modules),
        "symbols_indexed": len(symbol_by_id),
        "edges_indexed": edges_count,
        "languages": sorted(languages),
        "packages": {pkg: sorted(paths) for pkg, paths in sorted(packages.items())},
        "modules": modules,
        "symbol_by_id": symbol_by_id,
        "graphs": {
            "imports": imports_graph,
            "imported_by": imported_by_graph,
            "calls": calls_graph,
            "called_by": called_by_graph,
            "test_links": test_links,
        },
        "cache_stats": cache.stats.to_dict() if cache is not None else {},
    }
