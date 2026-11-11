from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.services.git_workspace import resolve_within_dir

_SECURITY_KEYWORD_RE = re.compile(
    r"auth|token|secret|password|hash|jwt|oauth|session|perm|role|sql|query|"
    r"exec|subprocess|shell|url|fetch|ssrf|redirect|validate|sanitize|redact|parse|verify",
    re.IGNORECASE,
)

_API_KEYWORD_RE = re.compile(
    r"router|endpoint|route|schema|model|handler|export|interface|type|public|config|env|settings",
    re.IGNORECASE,
)


def _approx_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _overlap_score(
    sym_start: int,
    sym_end: int,
    target_lines: list[int],
    *,
    margin: int = 2,
) -> int:
    for ln in target_lines:
        if (sym_start - margin) <= ln <= (sym_end + margin):
            return 1
    return 0


def _read_line_slice(
    workspace_dir: Path,
    rel_path: str,
    start_line: int,
    end_line: int,
    *,
    focus_lines: list[int] | None = None,
    max_lines: int = 95,
) -> str:
    target = resolve_within_dir(workspace_dir, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return ""
    try:
        all_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not all_lines:
        return ""

    s = max(1, start_line)
    e = min(len(all_lines), max(s, end_line))
    if (e - s + 1) <= max_lines:
        return "\n".join(f"L{idx}: {all_lines[idx - 1]}" for idx in range(s, e + 1))

    # For very large symbols, preserve header + window around the first focus line inside the symbol
    header_end = min(e, s + 12)
    picked_ranges: list[tuple[int, int]] = [(s, header_end)]
    hits = [ln for ln in (focus_lines or []) if s <= ln <= e]
    center = hits[0] if hits else (s + e) // 2
    half_win = max(15, (max_lines - 18) // 2)
    win_start = max(header_end + 1, center - half_win)
    win_end = min(e, win_start + max_lines - 16)
    if win_start <= win_end:
        if win_start == header_end + 1:
            picked_ranges = [(s, win_end)]
        else:
            picked_ranges.append((win_start, win_end))

    rendered: list[str] = []
    for idx, (rs, re_ln) in enumerate(picked_ranges):
        if idx > 0:
            rendered.append(f"... ({rs - picked_ranges[idx - 1][1] - 1} lines omitted) ...")
        for ln_no in range(rs, re_ln + 1):
            rendered.append(f"L{ln_no}: {all_lines[ln_no - 1]}")
    return "\n".join(rendered)


def _extract_changed_lines_map(changed_files: list[dict[str, Any]]) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for ch in changed_files:
        fp = str(ch.get("path") or "").strip()
        if not fp:
            continue
        raw_lines = ch.get("changed_lines") or []
        lines: list[int] = []
        for ln in raw_lines:
            try:
                lines.append(int(ln))
            except (TypeError, ValueError):
                continue
        out[fp] = lines
    return out


def _collect_hit_lines_by_file(
    evidence_items: list[dict[str, Any]] | None,
    findings: list[dict[str, Any]] | None,
) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for item in (evidence_items or []) + (findings or []):
        if not isinstance(item, dict):
            continue
        fp = str(item.get("file_path") or "").strip()
        ln = item.get("line_number")
        if not fp:
            continue
        hits.setdefault(fp, [])
        try:
            if ln is not None:
                hits[fp].append(int(ln))
        except (TypeError, ValueError):
            continue
    return hits


def retrieve_relevant_context(
    *,
    role: str,
    workspace_dir: Path,
    structure_index: dict[str, Any],
    changed_files: list[dict[str, Any]],
    diff_text: str = "",
    evidence_items: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    target_files: list[str] | None = None,
    max_slices: int = 18,
) -> dict[str, Any]:
    """
    STAIR-inspired hierarchical retrieval:
      1. Localize packages & modules matching diff, scanner evidence, or role.
      2. Expand 1-hop graph neighbors (callers, callees, imports, linked tests).
      3. Select top symbols and extract bounded line slices around exact lines.
    """
    modules: dict[str, dict[str, Any]] = structure_index.get("modules") or {}
    symbol_by_id: dict[str, dict[str, Any]] = structure_index.get("symbol_by_id") or {}
    graphs: dict[str, Any] = structure_index.get("graphs") or {}
    imports_graph: dict[str, list[str]] = graphs.get("imports") or {}
    imported_by_graph: dict[str, list[str]] = graphs.get("imported_by") or {}
    calls_graph: dict[str, list[str]] = graphs.get("calls") or {}
    called_by_graph: dict[str, list[str]] = graphs.get("called_by") or {}
    test_links: dict[str, list[str]] = graphs.get("test_links") or {}

    if not modules:
        return {"toc_tree": [], "slices": [], "selected_modules": []}

    changed_lines_map = _extract_changed_lines_map(changed_files)
    hit_lines_map = _collect_hit_lines_by_file(evidence_items, findings)
    target_file_set = set(target_files or [])
    changed_file_set = set(changed_lines_map.keys()) | target_file_set

    # Level 1 & 2: Score modules in the STAIR ToC
    module_scores: dict[str, int] = {}
    module_reasons: dict[str, list[str]] = {}
    for rel, mod in modules.items():
        score = 0
        reasons: list[str] = []
        if rel in changed_file_set:
            score += 60
            reasons.append("modified_in_diff")
        if rel in hit_lines_map:
            score += 55
            reasons.append("scanner_or_finding_hit")
        if rel in target_file_set:
            score += 70
            reasons.append("explicit_target")
        guards = mod.get("implemented_guards") or {}
        if guards and role in ("security_agent", "reviewer_manager", "fix_suggestion_agent"):
            score += 30
            reasons.append(f"guards:{len(guards)}")
        if mod.get("is_test") and role in ("test_coverage_agent", "fix_suggestion_agent"):
            score += 20
            reasons.append("test_module")
        if score > 0:
            module_scores[rel] = score
            module_reasons[rel] = reasons

    # 1-hop dependency/test expansion from seed modules
    seed_modules = list(module_scores.keys())
    for rel in seed_modules:
        for imp_tgt in imports_graph.get(rel, []):
            module_scores[imp_tgt] = max(module_scores.get(imp_tgt, 0), 32)
            module_reasons.setdefault(imp_tgt, [])
            if "imported_dependency" not in module_reasons[imp_tgt]:
                module_reasons[imp_tgt].append(f"imported_by:{Path(rel).name}")
        for caller_mod in imported_by_graph.get(rel, []):
            module_scores[caller_mod] = max(module_scores.get(caller_mod, 0), 28)
            module_reasons.setdefault(caller_mod, [])
            if "downstream_consumer" not in module_reasons[caller_mod]:
                module_reasons[caller_mod].append(f"imports:{Path(rel).name}")
        for tst_mod in test_links.get(rel, []):
            boost = 48 if role in ("test_coverage_agent", "fix_suggestion_agent") else 24
            module_scores[tst_mod] = max(module_scores.get(tst_mod, 0), boost)
            module_reasons.setdefault(tst_mod, [])
            if "linked_test" not in module_reasons[tst_mod]:
                module_reasons[tst_mod].append(f"tests:{Path(rel).name}")

    # Level 3: Score symbols inside relevant modules
    symbol_scores: dict[str, int] = {}
    symbol_reasons: dict[str, list[str]] = {}
    seed_symbols: list[str] = []

    for rel, m_score in sorted(module_scores.items(), key=lambda kv: kv[1], reverse=True):
        mod = modules.get(rel) or {}
        chg_lines = changed_lines_map.get(rel, [])
        hit_lines = hit_lines_map.get(rel, [])
        guards = mod.get("implemented_guards") or {}
        guard_lines = [ln for glines in guards.values() for ln in glines]
        lang = mod.get("language", "text")

        for sym in mod.get("symbols", []):
            sid = sym["symbol_id"]
            s_start = int(sym.get("start_line") or 1)
            s_end = int(sym.get("end_line") or s_start)
            sig = str(sym.get("signature") or sym.get("name") or "")
            s_score = m_score // 4
            reasons = list(module_reasons.get(rel, []))

            if _overlap_score(s_start, s_end, chg_lines, margin=2):
                s_score += 100
                reasons.append("diff_hunk_symbol")
                seed_symbols.append(sid)
            if _overlap_score(s_start, s_end, hit_lines, margin=3):
                s_score += 110
                reasons.append("finding_or_scanner_symbol")
                seed_symbols.append(sid)
            if _overlap_score(s_start, s_end, guard_lines, margin=1):
                guard_boost = 55 if role in ("security_agent", "reviewer_manager") else 20
                s_score += guard_boost
                reasons.append("contains_defensive_guard")
            if role == "security_agent" and _SECURITY_KEYWORD_RE.search(sig):
                s_score += 35
                reasons.append("security_surface")
            if role == "diff_agent" and _API_KEYWORD_RE.search(sig):
                s_score += 25
                reasons.append("api_contract_symbol")
            if role == "style_agent" and (s_end - s_start) >= 35:
                s_score += 28
                reasons.append("complex_or_long_symbol")
            if role == "test_coverage_agent" and mod.get("is_test"):
                s_score += 25
            if lang == "python" and role == "security_agent" and sym.get("kind") == "method":
                s_score += 5

            # Minor penalty only against bare class stub when methods inside exist
            if sym.get("kind") == "class" and s_end - s_start <= 15:
                s_score -= 10

            if s_score > 12:
                symbol_scores[sid] = max(symbol_scores.get(sid, 0), s_score)
                symbol_reasons[sid] = list(dict.fromkeys(reasons))

    # Symbol-level 1-hop call-graph expansion around modified / scanner-hit symbols
    for sid in list(dict.fromkeys(seed_symbols))[:20]:
        for caller_id in called_by_graph.get(sid, []):
            if caller_id in symbol_by_id:
                symbol_scores[caller_id] = max(symbol_scores.get(caller_id, 0), 75)
                symbol_reasons.setdefault(caller_id, [])
                caller_note = f"calls:{symbol_by_id[sid]['name']}"
                if caller_note not in symbol_reasons[caller_id]:
                    symbol_reasons[caller_id].append(caller_note)
        for callee_id in calls_graph.get(sid, []):
            if callee_id in symbol_by_id:
                symbol_scores[callee_id] = max(symbol_scores.get(callee_id, 0), 68)
                symbol_reasons.setdefault(callee_id, [])
                callee_note = f"called_by:{symbol_by_id[sid]['name']}"
                if callee_note not in symbol_reasons[callee_id]:
                    symbol_reasons[callee_id].append(callee_note)

    # Also prioritize guard lines even if they live outside a named function (top-level code)
    # Already covered for modules with <top> or top-level slices via module fallback below.
    ranked_sids = sorted(
        symbol_scores.keys(),
        key=lambda sid: (
            -symbol_scores[sid],
            str(symbol_by_id[sid]["file_path"]),
            int(symbol_by_id[sid]["start_line"]),
        ),
    )

    slices: list[dict[str, Any]] = []
    seen_spans: set[tuple[str, int, int]] = set()
    for sid in ranked_sids:
        sym = symbol_by_id.get(sid)
        if not sym:
            continue
        fp = str(sym["file_path"])
        s_ln = int(sym["start_line"])
        e_ln = int(sym["end_line"])
        span_key = (fp, s_ln, e_ln)
        if span_key in seen_spans:
            continue
        seen_spans.add(span_key)

        focus = (
            changed_lines_map.get(fp, [])
            + hit_lines_map.get(fp, [])
            + [ln for gl in (modules[fp].get("implemented_guards") or {}).values() for ln in gl]
        )
        code = _read_line_slice(workspace_dir, fp, s_ln, e_ln, focus_lines=focus)
        if not code:
            continue

        callers = [symbol_by_id[c]["symbol_id"] for c in called_by_graph.get(sid, []) if c in symbol_by_id][:4]
        callees = [symbol_by_id[c]["symbol_id"] for c in calls_graph.get(sid, []) if c in symbol_by_id][:4]
        mod = modules.get(fp) or {}
        toc_path = f"{mod.get('package', '.')} -> {fp} -> {sym['name']} (L{s_ln}-L{e_ln})"

        slices.append(
            {
                "symbol_id": sid,
                "toc_path": toc_path,
                "file_path": fp,
                "symbol_name": sym["name"],
                "kind": sym["kind"],
                "start_line": s_ln,
                "end_line": e_ln,
                "score": symbol_scores[sid],
                "reasons": symbol_reasons.get(sid, [])[:5],
                "callers": callers,
                "callees": callees,
                "imports": imports_graph.get(fp, [])[:5],
                "tests": test_links.get(fp, [])[:3],
                "implemented_guards": mod.get("implemented_guards") or {},
                "code": code,
                "tokens": _approx_tokens(code) + 25,
            }
        )
        if len(slices) >= max_slices:
            break

    # Compact ToC summary across top scored modules so agents see full structure without truncation blindness
    ranked_mods = sorted(module_scores.keys(), key=lambda m: (-module_scores[m], m))[:15]
    toc_tree: list[dict[str, Any]] = []
    for rel in ranked_mods:
        mod = modules.get(rel) or {}
        syms_summary = [
            f"{s['name']}({s['start_line']}-{s['end_line']})"
            for s in (mod.get("symbols") or [])[:12]
        ]
        toc_tree.append(
            {
                "package": mod.get("package", "."),
                "file_path": rel,
                "total_lines": mod.get("total_lines", 0),
                "language": mod.get("language", "text"),
                "reasons": module_reasons.get(rel, [])[:4],
                "symbols": syms_summary,
                "guards": mod.get("implemented_guards") or {},
            }
        )

    # Suppress unused-arg lint warning while preserving diff_text extensibility
    if diff_text and not toc_tree and not slices:
        return {"toc_tree": [], "slices": [], "selected_modules": ranked_mods}

    return {
        "toc_tree": toc_tree,
        "slices": slices,
        "selected_modules": ranked_mods,
    }
