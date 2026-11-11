from __future__ import annotations

from typing import Any

EVIDENCE_GROUNDING_CONTRACT = """
EVIDENCE & VERIFICATION CONTRACT (MANDATORY FOR ALL AGENTS):
1. Do NOT self-certify findings as "Verified". Emit an honest numeric `confidence` (0.0 to 1.0); independent EvidenceGuard verification establishes `"Verified"` status from deterministic scanners and verified file lines.
2. NEVER cite a deterministic scanner name (`bandit`, `semgrep`, `gitleaks`, `osv-scanner`, `security-guard`, `ruff`, `pytest`, `vitest`, `ast-complexity`) in `tool_name` unless an exact matching hit appears in that tool's deterministic output above. For structural or logic observations found directly in source slices, set `tool_name` to `"llm-review"` (or `"git-diff"` for Diff Agent).
3. Cite exact `file_path` and 1-based `line_number` observed inside the STAIR context slices or scanner hits, plus a short verbatim `evidence` quote.
4. Check `implemented_guards` and caller/callee context in the STAIR index before claiming missing validation or sanitization elsewhere in the file.
""".strip()

SKILL_GUIDELINES: dict[str, str] = {
    "diff_agent": (
        "Skills: AST-aware change detection (changed functions/classes/signatures), semantic diffing "
        "(logic/permission edits vs harmless refactors), API contract drift, and downstream caller impact."
    ),
    "style_agent": (
        "Skills: deterministic lint synthesis (Ruff/JS AST), complexity/smell detection, dead-code checks, "
        "repository pattern consistency, and small local refactor guidance without redundant clutter."
    ),
    "security_agent": (
        "Skills: SAST/secret/CVE triage, source-to-sink trace validation across callers/callees, auth/RBAC boundary "
        "inspection, and verifying whether existing guards mitigate or fail to mitigate an exploit path."
    ),
    "test_coverage_agent": (
        "Skills: deterministic test execution diagnosis, changed-symbol vs test-file mapping, missing negative/boundary "
        "test detection, and error-handling path verification."
    ),
    "reviewer_manager": (
        "Skills: semantic deduplication across agents, contradiction refutation against full-file guards, strict separation "
        "of deterministic evidence vs LLM hypotheses, and deterministic policy compliance."
    ),
    "fix_suggestion_agent": (
        "Skills: minimal surgical patches strictly for EvidenceGuard-Verified defects, preserving public signatures and "
        "existing test contracts while introducing zero new lint or security issues."
    ),
}


def format_agent_contract(agent_key: str, plan_entry: dict[str, Any] | None = None) -> str:
    """Compose shared evidence grounding + role-specific skills + active planner focus hints."""
    parts = [SKILL_GUIDELINES.get(agent_key, ""), EVIDENCE_GROUNDING_CONTRACT]
    if plan_entry:
        focus = plan_entry.get("focus_skills") or []
        mode = plan_entry.get("mode", "standard")
        if focus:
            parts.append(f"Active Plan Mode: {mode} | Focus Skills: {', '.join(focus)}")
    return "\n\n".join(p for p in parts if p)
