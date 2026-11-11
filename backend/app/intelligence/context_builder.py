from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence.stair_retriever import retrieve_relevant_context
from app.scanners.code_engines import read_prioritized_workspace_files

AGENT_TOKEN_BUDGETS: dict[str, int] = {
    "diff_agent": 3000,
    "style_agent": 2000,
    "security_agent": 5000,
    "test_coverage_agent": 3500,
    "reviewer_manager": 3000,
    "fix_suggestion_agent": 4000,
}


def _approx_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _format_toc_section(toc_tree: list[dict[str, Any]]) -> str:
    if not toc_tree:
        return ""
    lines = ["=== STAIR HIERARCHICAL CODE INDEX (Repository -> Package -> Module -> Symbol) ==="]
    for item in toc_tree[:12]:
        sym_list = ", ".join(item.get("symbols") or []) or "<module-level>"
        reasons = ", ".join(item.get("reasons") or [])
        guards = item.get("guards") or {}
        guard_str = f" | guards={json.dumps(guards)}" if guards else ""
        lines.append(
            f"- [{item.get('package')}] {item.get('file_path')} "
            f"({item.get('total_lines')} lines, {item.get('language')}) "
            f"[{reasons}]: symbols=[{sym_list}]{guard_str}"
        )
    return "\n".join(lines)


def build_agent_context(
    *,
    role: str,
    workspace_dir: Path,
    structure_index: dict[str, Any] | None,
    changed_files: list[dict[str, Any]],
    diff_text: str = "",
    evidence_items: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    target_files: list[str] | None = None,
    token_budget: int | None = None,
    expand_for_high_risk: bool = False,
) -> dict[str, Any]:
    """
    Build a strictly token-budgeted, STAIR hierarchy-aware context payload for an agent.
    Falls back cleanly to prioritized whole-file reading when no structural slices exist.
    """
    base_budget = token_budget or AGENT_TOKEN_BUDGETS.get(role, 3000)
    effective_budget = int(base_budget * 1.3) if expand_for_high_risk else base_budget

    retrieved = (
        retrieve_relevant_context(
            role=role,
            workspace_dir=workspace_dir,
            structure_index=structure_index,
            changed_files=changed_files,
            diff_text=diff_text,
            evidence_items=evidence_items,
            findings=findings,
            target_files=target_files,
        )
        if structure_index and structure_index.get("modules")
        else {"toc_tree": [], "slices": [], "selected_modules": []}
    )

    slices: list[dict[str, Any]] = retrieved.get("slices") or []
    toc_tree: list[dict[str, Any]] = retrieved.get("toc_tree") or []

    # Fallback to linear prioritized reader for binary/unsupported/empty-AST repos
    if not slices:
        changed_paths = [str(c.get("path")) for c in changed_files if c.get("path")]
        extra_paths = [p for p in (target_files or []) if p not in changed_paths]
        max_chars = max(2000, effective_budget * 4)
        fallback_files = read_prioritized_workspace_files(
            workspace_dir,
            changed_paths + extra_paths,
            max_files=8,
            max_total_chars=max_chars,
        )
        fallback_text = (
            f"=== FALLBACK PRIORITIZED FILES (budget={effective_budget} tokens) ===\n"
            f"{json.dumps(fallback_files, indent=2)[:max_chars]}"
        )
        return {
            "role": role,
            "context_text": fallback_text,
            "toc_tree": toc_tree,
            "selected_slices": [],
            "token_estimate": _approx_tokens(fallback_text),
            "token_budget": effective_budget,
            "fallback_used": True,
        }

    toc_text = _format_toc_section(toc_tree)
    toc_tokens = _approx_tokens(toc_text)
    used_tokens = toc_tokens

    selected_slices: list[dict[str, Any]] = []
    slice_blocks: list[str] = []

    for sl in slices:
        header_parts = [f"### {sl['toc_path']} (score={sl['score']}, reasons={','.join(sl['reasons'])})"]
        if sl.get("callers"):
            header_parts.append(f"Callers: {', '.join(sl['callers'])}")
        if sl.get("callees"):
            header_parts.append(f"Callees: {', '.join(sl['callees'])}")
        if sl.get("imports"):
            header_parts.append(f"Imports: {', '.join(sl['imports'])}")
        if sl.get("tests"):
            header_parts.append(f"Linked Tests: {', '.join(sl['tests'])}")
        block = "\n".join(header_parts) + "\n" + sl["code"]
        block_tokens = _approx_tokens(block)

        if selected_slices and used_tokens + block_tokens > effective_budget:
            # Stop before exceeding budget unless nothing fits yet
            continue
        if not selected_slices and used_tokens + block_tokens > effective_budget:
            # Trim first huge slice so we never exceed hard budget
            remaining_chars = max(600, (effective_budget - used_tokens) * 4)
            block = block[:remaining_chars] + "\n... [truncated to token budget]"
            block_tokens = _approx_tokens(block)

        used_tokens += block_tokens
        slice_blocks.append(block)
        selected_slices.append(
            {
                "symbol_id": sl["symbol_id"],
                "file_path": sl["file_path"],
                "start_line": sl["start_line"],
                "end_line": sl["end_line"],
                "score": sl["score"],
                "reasons": sl["reasons"],
            }
        )
        if used_tokens >= effective_budget:
            break

    sections = [s for s in (toc_text, "=== STAIR RETRIEVED CODE & DEPENDENCY SLICES ===", *slice_blocks) if s]
    context_text = "\n\n".join(sections)
    return {
        "role": role,
        "context_text": context_text,
        "toc_tree": toc_tree,
        "selected_slices": selected_slices,
        "token_estimate": _approx_tokens(context_text),
        "token_budget": effective_budget,
        "fallback_used": False,
    }
