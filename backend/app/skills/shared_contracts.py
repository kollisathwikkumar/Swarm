from __future__ import annotations

from typing import Any

from app.skills.permissions import get_agent_capabilities

EVIDENCE_GROUNDING_CONTRACT = """
EVIDENCE & VERIFICATION CONTRACT (MANDATORY FOR ALL AGENTS):
1. Do NOT self-certify findings as "Verified". Emit an honest numeric `confidence` (0.0 to 1.0); independent EvidenceGuard verification establishes `"Verified"` status from deterministic scanners and verified file lines.
2. NEVER cite a deterministic scanner name (`bandit`, `semgrep`, `gitleaks`, `osv-scanner`, `security-guard`, `security-taint`, `ruff`, `eslint`, `pylint`, `dead-code-analyzer`, `ast-complexity`, `diff-ast-engine`, `pytest`, `vitest`) unless an exact matching hit appears in that tool's deterministic output above AND your role is permitted to use that engine. For reasoning-only observations, set `tool_name` to `"llm-review"` (or `"git-diff"` for Diff Agent).
3. Cite exact `file_path` and 1-based `line_number` observed inside the STAIR context slices or scanner hits, plus a short verbatim `evidence` quote.
4. NEVER claim that you ran tests, type-checks, or mutation tests when only inspecting static code or when runner telemetry shows disabled/unavailable.
5. Check `implemented_guards` and caller/callee context in the STAIR index before claiming missing validation or sanitization elsewhere in the file.
""".strip()

SKILL_GUIDELINES: dict[str, str] = {
    "diff_agent": (
        "Skills: AST-aware change detection (changed functions/classes/signatures), semantic diffing "
        "(rename vs algorithm/permission edits), API contract drift, config/env impact, and caller impact risk."
    ),
    "style_agent": (
        "Skills: deterministic lint triage (Ruff/ESLint/Pylint/AST), code smell & deep-nesting/long-function "
        "detection, dead-code checks, repo naming/pattern consistency, and small local refactors."
    ),
    "security_agent": (
        "Skills: taint & data-flow tracing, auth/RBAC boundary audit, injection/path-traversal checks, secret/CVE "
        "triage, weak crypto detection, trust-boundary threat modelling, and reachability/exploitability proof."
    ),
    "test_coverage_agent": (
        "Skills: selective impacted test discovery, test-to-code mapping, coverage gap diagnosis, regression & "
        "property-based/mutation candidate identification, failure triage (code vs env/dep), and minimal repro."
    ),
    "reviewer_manager": (
        "Skills: exact provenance tracking & matching, semantic deduplication, cross-agent contradiction detection, "
        "confidence calibration vs Verified proof, consistent severity normalization, and incomplete-review gating."
    ),
    "fix_suggestion_agent": (
        "Skills: root-cause analysis, minimal AST-safe patch generation strictly for EvidenceGuard-Verified defects, "
        "repo pattern reuse, stale-hash conflict detection, regression test synthesis, and type/test/security revalidation."
    ),
}


def format_agent_contract(agent_key: str, plan_entry: dict[str, Any] | None = None) -> str:
    """Compose shared evidence grounding + role-specific skills + explicit permission boundaries + planner hints."""
    parts = [SKILL_GUIDELINES.get(agent_key, ""), EVIDENCE_GROUNDING_CONTRACT]
    caps = get_agent_capabilities(agent_key)
    if caps is not None:
        parts.append(
            f"Permitted Engines: {', '.join(caps.allowed_engines)} | "
            f"Can Propose Patches: {caps.can_propose_patches} | "
            f"Can Commit Directly: {caps.can_commit_directly} | "
            f"Can Verify Test Execution: {caps.can_verify_test_execution}"
        )
    if plan_entry:
        focus = plan_entry.get("focus_skills") or []
        mode = plan_entry.get("mode", "standard")
        if focus:
            parts.append(f"Active Plan Mode: {mode} | Focus Skills: {', '.join(focus)}")
    return "\n\n".join(p for p in parts if p)
