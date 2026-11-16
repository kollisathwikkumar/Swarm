from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import LLM_FALLBACK_EXCEPTIONS, MissingAPIKeyError, run_structured_agent
from app.intelligence.context_builder import build_agent_context
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import AgentExecutionOutput, ReviewState
from app.scanners.code_engines import is_test_fixture_hit
from app.skills.shared_contracts import format_agent_contract
from app.verification.evidence_guard import (
    build_evidence_store,
    check_finding_contradiction,
    detect_cross_agent_contradictions,
    normalize_severity_with_criteria,
    verify_finding_provenance,
)

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_is_harness_noise = check_finding_contradiction

SYSTEM_PROMPT = """You are the Reviewer Manager (Fan-In Adversarial Verification & Decision Engine) in Swarm.
You receive:
1. Candidate findings from the four parallel agents (Diff, Style, Security, Test-Coverage).
2. Immutable `EvidenceStore` records (`EV-001`, `EV-002`, ...) from deterministic scanners, Cross-File Test-Import Coverage Map (`test_import_map`), Polyglot Symbols/Guards (`polyglot_symbols`), and STAIR retrieved ground-truth source slices.

Your strict verification & consolidation duties:
1. **Cross-Examine Every Candidate Against Ground-Truth Code & Maps**:
   - Check `implemented_guards` in STAIR / `polyglot_symbols`, and `test_import_map` BEFORE keeping any claim.
   - **REJECT** any finding that contradicts the actual code on disk or `test_import_map` — for example:
     * Claims a validation, URL check, or citation check is missing when it is implemented in ground-truth slices or `implemented_guards_in_full_file`.
     * Claims a test suite "only tests happy paths" when error/edge tests exist in `test_import_map.test_suites` or the test slices.
     * Claims a module has no test coverage when `test_import_map.source_file_test_map[file].has_any_unmocked_test` is true.
     * Complains about Swarm's own test runner (`pytest` finding 0 Python tests on a TS repo).
   - Record every discarded finding cleanly in `"rejected_false_positives"` with exact contradictory evidence.
2. **Deduplicate Overlapping Findings**:
   - Merge findings covering the same underlying defect + file + line/module into one canonical finding, listing all contributing sources in `deduplicated_sources`, preserving `evidence_ids`, and assigning an honest `confidence` (`0.0–1.0`).
3. **Honest Evidence Provenance (`EvidenceGuard` enforces `"Verified"` independently)**:
   - Cite matching `evidence_ids` (e.g. `["EV-001"]`) ONLY when directly backed by an `EvidenceStore` entry at that file and line range.
   - Pure LLM reasoning (`git-diff`, `llm-*`) must keep `tool_name="llm-review"` (or `"git-diff"`) and must NEVER fabricate deterministic scanner attribution.
   - Downgrade Gitleaks/secret hits flagged `is_test_fixture: true` in unit-test files to `"Low"` informational.
4. **Priority & Executive Summary**:
   - Order verified Critical/High security & correctness bugs at top (`priority_rank` starting at 1).

Return strict JSON:
{
  "executive_summary": "Concise consolidated engineering review summary.",
  "rejected_false_positives": [
    {
      "title": "Rejected claim title",
      "file_path": "path/to/file",
      "reason": "Exact contradiction observed in ground_truth_files or test_import_map"
    }
  ],
  "consolidated_findings": [
    {
      "agent": "Security Agent",
      "category": "security|code_quality|testing|change_risk",
      "severity": "Critical|High|Medium|Low",
      "title": "Canonical finding title",
      "description": "Clear description",
      "file_path": "exact/path.py",
      "line_number": 24,
      "evidence": "Verified evidence snippet from the actual file or deterministic tool",
      "evidence_ids": ["EV-001"],
      "confidence": 0.95,
      "tool_name": "bandit|semgrep|gitleaks|osv-scanner|security-guard|ruff|ast-complexity|js-style-checker|ts-syntax-checker|duplicate-detector|pytest|vitest|coverage.py|test-mapper|git-diff|llm-review",
      "rule_id": "optional rule id",
      "recommendation": "Actionable fix guidance",
      "deduplicated_sources": ["Security Agent", "Diff Agent"],
      "priority_rank": 1
    }
  ]
}"""


_PRIMARY_TOOL_RANK = {
    "bandit": 0,
    "semgrep": 1,
    "gitleaks": 2,
    "osv-scanner": 3,
    "codeql": 4,
    "trivy": 5,
    "ruff": 6,
    "eslint": 7,
    "pylint": 8,
    "pytest": 9,
    "vitest": 10,
    "security-taint": 15,
    "security-guard": 16,
    "diff-ast-engine": 17,
}


def _deterministic_deduplicate(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, int, str], dict[str, Any]] = {}
    for f in raw_findings:
        fp = str(f.get("file_path") or "").strip()
        ln = int(f.get("line_number") or 0)
        cat = str(f.get("category") or "general")
        sev = str(f.get("severity") or "Low").title()
        key = (fp, ln, cat)
        src = str(f.get("agent") or "Agent")
        if f.get("tool_name"):
            src = f"{src} ({f['tool_name']})"
        ev_ids = [str(e) for e in (f.get("evidence_ids") or []) if e]
        try:
            conf = float(f.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        if key not in merged:
            copy = dict(f)
            copy["severity"] = sev
            copy["deduplicated_sources"] = [src]
            copy["evidence_ids"] = list(dict.fromkeys(ev_ids))
            copy["confidence"] = max(0.0, min(1.0, conf))
            merged[key] = copy
        else:
            existing = merged[key]
            if src not in existing["deduplicated_sources"]:
                existing["deduplicated_sources"].append(src)
            for eid in ev_ids:
                if eid not in existing["evidence_ids"]:
                    existing["evidence_ids"].append(eid)
            existing["confidence"] = max(float(existing.get("confidence", 0.5)), conf)
            # Prefer industry-primary SAST/linter tool_name when merging same-line duplicates
            cur_tool = str(existing.get("tool_name") or "")
            new_tool = str(f.get("tool_name") or "")
            if _PRIMARY_TOOL_RANK.get(new_tool, 99) < _PRIMARY_TOOL_RANK.get(cur_tool, 99):
                existing["tool_name"] = new_tool
                if f.get("rule_id"):
                    existing["rule_id"] = f["rule_id"]
            if SEVERITY_ORDER.get(sev, 3) < SEVERITY_ORDER.get(
                str(existing.get("severity") or "Low").title(), 3
            ):
                existing["severity"] = sev
            if f.get("verification_status") == "Verified":
                existing["verification_status"] = "Verified"
    result = list(merged.values())
    result.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(str(x.get("severity") or "Low").title(), 3),
            x.get("file_path", ""),
            x.get("line_number") or 0,
        )
    )
    for idx, item in enumerate(result, start=1):
        item["priority_rank"] = idx
    return result


def _agent_field(agent: AgentExecutionOutput | dict[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(agent, dict):
        return agent.get(key, default)
    return getattr(agent, key, default)


def _evaluate_review_policy(
    state: ReviewState,
    findings: list[dict[str, Any]],
    agent_outputs: list[AgentExecutionOutput] | list[dict[str, Any]],
) -> tuple[str, str, list[dict[str, Any]]]:
    policy = state.policy or {}
    block_critical = bool(policy.get("block_on_critical", True))
    block_high = bool(policy.get("block_on_high", True))
    require_tests_pass = bool(policy.get("require_tests_pass", True))
    require_all_scans = bool(policy.get("require_all_mandatory_scans", True))

    stopped_agents = [
        str(_agent_field(a, "agent_label") or _agent_field(a, "agent_name") or "Agent")
        for a in agent_outputs
        if _agent_field(a, "status") == "stopped"
    ]
    incomplete_agents = [
        str(_agent_field(a, "agent_label") or _agent_field(a, "agent_name") or "Agent")
        for a in agent_outputs
        if _agent_field(a, "status") in ("incomplete", "failed")
    ]
    test_agent = next(
        (a for a in agent_outputs if _agent_field(a, "agent_name") == "test_coverage_agent"),
        None,
    )
    test_tr = (_agent_field(test_agent, "tool_results") or {}) if test_agent else {}
    tests_failed = int(test_tr.get("failed") or 0)

    blocking_reasons: list[str] = []
    for f in findings:
        sev = str(f.get("severity") or "Low").title()
        f["severity"] = sev
        verified = f.get("verification_status") == "Verified"
        is_block = verified and ((sev == "Critical" and block_critical) or (sev == "High" and block_high))
        f["is_blocking"] = is_block
        if is_block:
            blocking_reasons.append(f"{sev}: {f.get('title')} ({f.get('file_path')}:{f.get('line_number') or 1})")

    # Priority 1: Stop Operation or mandatory agent/scanner timeout, failure, or missing API key
    if is_review_cancelled(state.review_id) or stopped_agents:
        return (
            "Incomplete",
            "Stopped by user before completion.",
            findings,
        )
    if require_all_scans and incomplete_agents:
        return (
            "Incomplete",
            f"Mandatory analysis incomplete for: {', '.join(incomplete_agents)}.",
            findings,
        )
    # Priority 2: Mandatory test suite failure
    if require_tests_pass and tests_failed > 0:
        return (
            "Request Changes",
            f"Mandatory test suite failed ({tests_failed} failing test(s)) and {len(blocking_reasons)} blocking finding(s).",
            findings,
        )
    # Priority 3: Verified Critical / High blocking finding
    if blocking_reasons:
        return (
            "Request Changes",
            f"{len(blocking_reasons)} verified blocking finding(s) found (top: {blocking_reasons[0]}).",
            findings,
        )
    # Priority 4: Clean pass
    return (
        "Approve",
        "No verified Critical/High blocking findings and all mandatory checks passed.",
        findings,
    )


class ReviewerManagerExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="reviewer_manager")
        self._emit = emit_event

    @handler
    async def handle(
        self,
        results: list[AgentExecutionOutput],
        ctx: WorkflowContext[ReviewState],
    ) -> None:
        t0 = time.perf_counter()
        state: ReviewState = ctx.get_state("review_state")
        cfg = state.agent_configs["reviewer_manager"]

        await self._emit(
            state.review_id,
            "fan_in_started",
            {
                "agent_name": "reviewer_manager",
                "agent_label": cfg.label,
                "model": cfg.model,
                "completed_parallel_agents": [r.agent_name for r in results],
            },
        )

        all_raw_findings: list[dict[str, Any]] = []
        for res in results:
            state.agent_results[res.agent_name] = res.to_dict()
            if res.agent_name == "diff_agent":
                if res.summary and not res.error_message:
                    state.diff_summary = res.summary
                state.diff_context = res.tool_results
            for f in res.findings:
                all_raw_findings.append(f.to_dict())

        # Surface deterministic scanner findings cleanly regardless of specialist status
        existing_sig = {
            (str(f.get("file_path") or ""), int(f.get("line_number") or 0), str(f.get("rule_id") or ""))
            for f in all_raw_findings
        }
        existing_tool_sig = {
            (str(f.get("file_path") or ""), int(f.get("line_number") or 0), str(f.get("tool_name") or ""))
            for f in all_raw_findings
        }

        def _append_det_if_new(candidate: dict[str, Any]) -> None:
            fp_c = str(candidate.get("file_path") or "")
            ln_c = int(candidate.get("line_number") or 0)
            rid_c = str(candidate.get("rule_id") or "")
            t_c = str(candidate.get("tool_name") or "")
            sig1 = (fp_c, ln_c, rid_c)
            sig2 = (fp_c, ln_c, t_c)
            if (rid_c and sig1 in existing_sig) or (not rid_c and t_c and sig2 in existing_tool_sig):
                return
            if rid_c:
                existing_sig.add(sig1)
            if t_c:
                existing_tool_sig.add(sig2)
            all_raw_findings.append(candidate)

        for res in results:
            tr = res.tool_results or {}
            if res.agent_name == "diff_agent":
                for item in (tr.get("ast_diff") or {}).get("findings", []) or []:
                    _append_det_if_new(
                        {
                            "agent": "Diff Agent",
                            "category": "change_risk",
                            "severity": item.get("severity", "Medium"),
                            "title": item.get("title", "API Contract Change"),
                            "description": item.get("evidence", ""),
                            "file_path": item.get("file_path", ""),
                            "line_number": item.get("line_number"),
                            "end_line": None,
                            "evidence": item.get("evidence", ""),
                            "recommendation": "Verify downstream callers match the updated signature or interface.",
                            "verification_status": "Verified",
                            "tool_name": item.get("tool", "diff-ast-engine"),
                            "rule_id": item.get("rule_id"),
                        }
                    )
            elif res.agent_name == "security_agent":
                for sec_key, def_tool in (
                    ("bandit", "bandit"),
                    ("semgrep", "semgrep"),
                    ("gitleaks", "gitleaks"),
                    ("osv_scanner", "osv-scanner"),
                    ("deterministic_guards", "security-guard"),
                    ("taint_analysis", "security-taint"),
                    ("codeql", "codeql"),
                    ("trivy", "trivy"),
                ):
                    guard_items = (tr.get(sec_key) or {}).get("findings", []) or []
                    for item in guard_items:
                        _append_det_if_new(
                            {
                                "agent": "Security Agent",
                                "category": "security",
                                "severity": item.get("severity", "High" if sec_key in ("bandit", "semgrep", "gitleaks", "osv_scanner") else "Medium"),
                                "title": item.get("title", "Deterministic Security Finding"),
                                "description": item.get("description", ""),
                                "file_path": item.get("file_path", ""),
                                "line_number": item.get("line_number"),
                                "end_line": item.get("end_line"),
                                "evidence": item.get("evidence", ""),
                                "recommendation": item.get("description", "Remediate detected security vulnerability."),
                                "verification_status": "Verified",
                                "tool_name": item.get("tool", def_tool),
                                "rule_id": item.get("rule_id"),
                            }
                        )
            elif res.agent_name == "style_agent":
                for style_key in ("ruff", "eslint", "pylint", "dead_code", "ast_checks"):
                    for item in (tr.get(style_key) or {}).get("findings", []) or []:
                        _append_det_if_new(
                            {
                                "agent": "Style Agent",
                                "category": "code_quality",
                                "severity": item.get("severity", "Low"),
                                "title": f"{item.get('rule_id', 'STYLE')}: {str(item.get('message', ''))[:80]}",
                                "description": item.get("message", ""),
                                "file_path": item.get("file_path", ""),
                                "line_number": item.get("line_number"),
                                "end_line": item.get("end_line"),
                                "evidence": item.get("message", ""),
                                "recommendation": "Resolve linter, complexity, or dead-code violation.",
                                "verification_status": "Verified",
                                "tool_name": item.get("tool", style_key.replace("_", "-")),
                                "rule_id": item.get("rule_id"),
                            }
                        )
            if res.agent_name == "test_coverage_agent" and int(tr.get("failed") or 0) > 0:
                failed_cnt = int(tr.get("failed") or 0)
                runner_name = str(tr.get("runner") or "pytest")
                test_file_hint = str((tr.get("test_files") or [""])[0] or "")
                has_test_failure = any(
                    str(f.get("tool_name") or "") in ("pytest", "vitest")
                    and "fail" in f"{f.get('title', '')} {f.get('description', '')}".lower()
                    for f in all_raw_findings
                )
                if not has_test_failure:
                    all_raw_findings.append(
                        {
                            "agent": "Test-Coverage Agent",
                            "category": "testing",
                            "severity": "High",
                            "title": f"{runner_name} suite reported {failed_cnt} failing test(s)",
                            "description": f"Deterministic {runner_name} execution failed with {failed_cnt} failing test(s).",
                            "file_path": test_file_hint,
                            "line_number": 1 if test_file_hint else None,
                            "end_line": None,
                            "evidence": str(tr.get("output") or "")[-400:],
                            "recommendation": "Fix the failing unit/integration tests before merging.",
                            "verification_status": "Verified",
                            "tool_name": runner_name,
                            "rule_id": "TEST-SUITE-FAILED",
                        }
                    )

        evidence_records, extras = build_evidence_store(
            results,
            state.workspace_dir,
            state.target_commit,
        )
        state.evidence_store = list(extras["evidence_store"])

        # Aggregate incremental cache telemetry from structure_indexer + parallel scanner runs
        agg_cache = dict(state.cache_stats or {})
        for res in results:
            c_stats = (res.tool_results or {}).get("cache_stats")
            if isinstance(c_stats, dict):
                for key in ("hits", "misses", "writes", "invalidations"):
                    agg_cache[key] = int(agg_cache.get(key, 0)) + int(c_stats.get(key, 0))
        state.cache_stats = agg_cache

        rejected_auto: list[dict[str, Any]] = []
        fabricated_claims = 0

        # Pre-LLM deterministic provenance grounding & contradiction rejection via EvidenceGuard
        verified_raw: list[dict[str, Any]] = []
        referenced_files: list[str] = []
        for f in all_raw_findings:
            noise_reason = check_finding_contradiction(f, extras)
            if noise_reason:
                rejected_auto.append(
                    {
                        "title": f.get("title", ""),
                        "file_path": f.get("file_path", ""),
                        "reason": noise_reason,
                    }
                )
                continue

            fp = str(f.get("file_path") or "").strip()
            ln = f.get("line_number")
            if fp:
                referenced_files.append(fp)

            guarded, fabricated = verify_finding_provenance(
                f,
                evidence_records,
                state.workspace_dir,
                execution_telemetry=extras.get("test_telemetry"),
            )
            if fabricated:
                fabricated_claims += 1
            if guarded.get("tool_name") == "gitleaks" and is_test_fixture_hit(
                state.workspace_dir, fp, ln, str(guarded.get("evidence") or "")
            ):
                guarded["is_test_fixture"] = True
            guarded["severity"] = normalize_severity_with_criteria(guarded)

            verified_raw.append(guarded)

        contradictions = detect_cross_agent_contradictions(verified_raw, extras)

        test_suites = ((extras.get("test_import_map") or {}).get("test_suites") or {}).keys()
        manager_plan = (state.review_plan.get("agent_plans") or {}).get("reviewer_manager") or {}
        fanout_clean = all(r.status == "completed" for r in results)
        skip_manager_llm = bool(
            cfg.api_key.strip()
            and fanout_clean
            and len(verified_raw) == 0
            and len(evidence_records) == 0
            and (state.review_plan.get("docs_only") or state.review_plan.get("risk_tier") == "low")
        )

        consolidated: list[dict[str, Any]] = []
        rejected_llm: list[dict[str, Any]] = []
        manager_summary = ""
        manager_status = "completed"
        manager_error: str | None = None
        llm_degraded_reason: str | None = None
        manager_raw: dict[str, Any] = {}
        token_usage: dict[str, int] | None = None
        stair_ctx: dict[str, Any] = {
            "token_estimate": 0,
            "fallback_used": False,
            "selected_slices": [],
        }

        _DET_STYLE_TOOLS = {
            "ruff",
            "eslint",
            "pylint",
            "dead-code",
            "ast-style-checker",
            "dead_code",
            "ast_checks",
        }
        contradiction_titles = {
            str(c.get("finding_title") or "").strip().lower()
            for c in contradictions
            if isinstance(c, dict)
        }
        passthrough_verified: list[dict[str, Any]] = []
        adjudication_candidates: list[dict[str, Any]] = []
        for item in verified_raw:
            t_low = str(item.get("tool_name") or "").lower()
            title_low = str(item.get("title") or "").strip().lower()
            is_trivial_verified_style = (
                item.get("verification_status") == "Verified"
                and item.get("category") == "code_quality"
                and str(item.get("severity") or "Low").title() == "Low"
                and t_low in _DET_STYLE_TOOLS
                and title_low not in contradiction_titles
            )
            if is_trivial_verified_style:
                passthrough_verified.append(item)
            else:
                adjudication_candidates.append(item)

        adjudication_candidates.sort(
            key=lambda x: (
                0 if x.get("verification_status") == "Needs Verification" else 1,
                SEVERITY_ORDER.get(str(x.get("severity") or "Low").title(), 3),
                int(x.get("priority_rank") or 999),
            )
        )
        adjudication_prompt_items = adjudication_candidates[:35]

        if skip_manager_llm:
            manager_summary = (
                f"All 4 specialist agents completed cleanly with 0 candidate findings on a "
                f"{state.review_plan.get('risk_tier', 'low')}-risk change; Reviewer Manager LLM skipped (token saver)."
            )
            manager_raw = {"executive_summary": manager_summary, "llm_skipped_token_saver": True}
        else:
            adj_files = [
                str(f.get("file_path") or "").strip()
                for f in adjudication_prompt_items
                if f.get("file_path")
            ]
            stair_budget = min(2200, int(manager_plan.get("token_budget") or 2200))
            has_unverified_adj = any(
                f.get("verification_status") == "Needs Verification" for f in adjudication_prompt_items
            )
            stair_ctx = build_agent_context(
                role="reviewer_manager",
                workspace_dir=state.workspace_dir,
                structure_index=state.structure_index,
                changed_files=state.changed_files,
                diff_text=state.diff_text,
                evidence_items=state.evidence_store[:45],
                findings=adjudication_prompt_items,
                target_files=list(dict.fromkeys(adj_files + list(test_suites))) or list(dict.fromkeys(referenced_files + list(test_suites))),
                token_budget=stair_budget,
                expand_for_high_risk=bool(has_unverified_adj and state.review_plan.get("risk_tier") == "high"),
            )
            contract_block = format_agent_contract("reviewer_manager", manager_plan)
            relevant_files_set = set(adj_files or referenced_files) | {
                str(c.get("path") or "") for c in state.changed_files if c.get("path")
            }
            scoped_polyglot = {
                k: v for k, v in (extras.get("polyglot_symbols") or {}).items() if k in relevant_files_set
            } or (extras.get("polyglot_symbols") or {})
            has_testing_claims = any(f.get("category") == "testing" for f in adjudication_prompt_items)
            raw_tmap = extras.get("test_import_map") or {}
            scoped_tmap = (
                raw_tmap
                if has_testing_claims
                else {"source_file_test_map": raw_tmap.get("source_file_test_map") or {}}
            )
            adj_ev_ids = {
                eid for c in adjudication_prompt_items for eid in (c.get("evidence_ids") or [])
            }
            prompt_evidence = [
                rec for rec in state.evidence_store if rec.get("evidence_id") in adj_ev_ids
            ][:45] or state.evidence_store[:35]

            try:
                if is_review_cancelled(state.review_id):
                    raise ReviewCancelledError("Review stopped by user.")
                user_prompt = (
                    f"Repository: {state.repository_name}\n"
                    f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')} | Auto-Passed Low Lints: {len(passthrough_verified)}\n"
                    f"Diff Summary: {state.diff_summary[:1800]}\n"
                    f"Agent Execution Statuses: {json.dumps({r.agent_name: r.status for r in results}, separators=(',', ':'))}\n\n"
                    f"{contract_block}\n\n"
                    f"Immutable EvidenceStore ({len(prompt_evidence)} of {len(state.evidence_store)} records):\n"
                    f"{json.dumps(prompt_evidence, separators=(',', ':'))[:6000]}\n\n"
                    f"Polyglot Symbols & Guards (across complete files):\n"
                    f"{json.dumps(scoped_polyglot, separators=(',', ':'))[:4500]}\n\n"
                    f"Cross-File Test-Import Coverage Map:\n"
                    f"{json.dumps(scoped_tmap, separators=(',', ':'))[:4000]}\n\n"
                    f"{stair_ctx['context_text']}\n\n"
                    f"Adjudication Candidates ({len(adjudication_prompt_items)} of {len(verified_raw)} total):\n"
                    f"{json.dumps(adjudication_prompt_items, separators=(',', ':'))[:10000]}"
                )
                manager_raw = await run_structured_agent(
                    cfg,
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    timeout_seconds=105.0,
                    max_tokens=2200,
                )
                token_usage = manager_raw.pop("_token_usage", None)
                manager_summary = str(manager_raw.get("executive_summary") or "").strip()
                rejected_llm = list(manager_raw.get("rejected_false_positives") or [])

                for idx, item in enumerate(manager_raw.get("consolidated_findings", []) or [], start=1):
                    noise_reason = check_finding_contradiction(item, extras)
                    if noise_reason:
                        rejected_auto.append(
                            {"title": item.get("title", ""), "file_path": item.get("file_path", ""), "reason": noise_reason}
                        )
                        continue

                    # Force EvidenceGuard provenance verification + permission check regardless of what LLM claims
                    guarded_item, fabricated = verify_finding_provenance(
                        item,
                        evidence_records,
                        state.workspace_dir,
                        execution_telemetry=extras.get("test_telemetry"),
                    )
                    if fabricated:
                        fabricated_claims += 1

                    fp = str(guarded_item.get("file_path") or "").strip()
                    ln = guarded_item.get("line_number")
                    if guarded_item.get("tool_name") == "gitleaks" and is_test_fixture_hit(
                        state.workspace_dir, fp, ln, str(guarded_item.get("evidence") or "")
                    ):
                        guarded_item["is_test_fixture"] = True
                    sev = normalize_severity_with_criteria(guarded_item)

                    consolidated.append(
                        {
                            "agent": str(guarded_item.get("agent") or "Reviewer Manager"),
                            "category": str(guarded_item.get("category") or "general"),
                            "severity": sev,
                            "title": str(guarded_item.get("title") or "Finding"),
                            "description": str(guarded_item.get("description") or ""),
                            "file_path": fp,
                            "line_number": ln,
                            "end_line": guarded_item.get("end_line"),
                            "evidence": str(guarded_item.get("evidence") or ""),
                            "tool_name": guarded_item.get("tool_name"),
                            "rule_id": guarded_item.get("rule_id"),
                            "recommendation": str(guarded_item.get("recommendation") or ""),
                            "verification_status": guarded_item["verification_status"],
                            "evidence_ids": list(guarded_item.get("evidence_ids") or []),
                            "confidence": float(guarded_item.get("confidence", 0.5)),
                            "deduplicated_sources": list(
                                guarded_item.get("deduplicated_sources")
                                or [guarded_item.get("agent") or "Reviewer Manager"]
                            ),
                            "priority_rank": int(guarded_item.get("priority_rank") or idx),
                        }
                    )

                # Never let LLM truncation/omission silently drop Verified deterministic EV-NNN findings (including passthrough Low style hits)
                covered_ev_ids = {
                    eid for cf in consolidated for eid in (cf.get("evidence_ids") or [])
                }
                rejected_sigs = {
                    (str(r.get("file_path") or "").strip(), str(r.get("title") or "").strip().lower())
                    for r in rejected_llm
                }
                for vf in verified_raw:
                    if vf.get("verification_status") != "Verified":
                        continue
                    vf_evs = list(vf.get("evidence_ids") or [])
                    if any(eid in covered_ev_ids for eid in vf_evs):
                        continue
                    vf_sig = (str(vf.get("file_path") or "").strip(), str(vf.get("title") or "").strip().lower())
                    if vf_sig in rejected_sigs:
                        continue
                    consolidated.append(dict(vf))
                    covered_ev_ids.update(vf_evs)

                if not consolidated and verified_raw and not rejected_llm:
                    consolidated = _deterministic_deduplicate(verified_raw)
                else:
                    consolidated = _deterministic_deduplicate(consolidated)
                    consolidated.sort(
                        key=lambda x: (
                            0 if x.get("verification_status") == "Verified" else 1,
                            SEVERITY_ORDER.get(str(x.get("severity") or "Low").title(), 3),
                            int(x.get("priority_rank") or 999),
                        )
                    )
                    for rank_idx, cf in enumerate(consolidated, start=1):
                        cf["priority_rank"] = rank_idx
            except (ReviewCancelledError, asyncio.CancelledError):
                raise
            except MissingAPIKeyError as exc:
                manager_status = "completed"
                manager_error = None
                llm_degraded_reason = str(exc)
                consolidated = _deterministic_deduplicate(verified_raw)
                manager_summary = (
                    f"EvidenceGuard deterministically verified & consolidated {len(consolidated)} finding(s); "
                    "LLM adjudication bypassed (offline/no API key mode)."
                )
            except LLM_FALLBACK_EXCEPTIONS as exc:
                err_reason = str(exc) or type(exc).__name__
                logger.warning("Reviewer Manager LLM fallback to deterministic consolidation: %s", err_reason)
                llm_degraded_reason = err_reason
                manager_status = "completed"
                manager_error = None
                consolidated = _deterministic_deduplicate(verified_raw)
                manager_summary = (
                    f"EvidenceGuard deterministically verified & consolidated {len(consolidated)} finding(s); "
                    f"LLM adjudication fell back cleanly ({err_reason[:110]})."
                )

        all_rejected = rejected_auto + rejected_llm
        all_outputs_for_policy = results + [
            AgentExecutionOutput(
                agent_name="reviewer_manager",
                agent_label=cfg.label,
                model_used=cfg.model,
                status=manager_status,
                summary=manager_summary,
                error_message=manager_error,
            )
        ]
        recommendation, reason, evaluated_findings = _evaluate_review_policy(
            state, consolidated, all_outputs_for_policy
        )
        state.findings = evaluated_findings
        state.recommendation = recommendation
        state.recommendation_reason = reason

        rm_tool_results: dict[str, Any] = {
            "consolidated_count": len(evaluated_findings),
            "verified_count": len([f for f in evaluated_findings if f.get("verification_status") == "Verified"]),
            "rejected_false_positives_count": len(all_rejected),
            "rejected_false_positives": all_rejected[:20],
            "evidence_store_count": len(evidence_records),
            "fabricated_tool_claims_count": fabricated_claims,
            "cross_agent_contradictions_count": len(contradictions),
            "cross_agent_contradictions": contradictions[:15],
            "stair_context_tokens": stair_ctx["token_estimate"],
            "stair_fallback_used": stair_ctx["fallback_used"],
            "adjudicated_candidates_count": len(adjudication_prompt_items),
            "passthrough_verified_count": len(passthrough_verified),
            "llm_skipped_token_saver": skip_manager_llm,
            "recommendation": recommendation,
        }
        if token_usage:
            rm_tool_results["token_usage"] = token_usage
        if llm_degraded_reason:
            rm_tool_results["llm_degraded"] = {"reason": llm_degraded_reason, "fallback": "evidence_guard_deterministic"}

        duration_ms = int((time.perf_counter() - t0) * 1000)
        state.agent_results["reviewer_manager"] = AgentExecutionOutput(
            agent_name="reviewer_manager",
            agent_label=cfg.label,
            model_used=cfg.model,
            status=manager_status,
            summary=manager_summary or reason,
            tool_results=rm_tool_results,
            raw_output=manager_raw,
            error_message=manager_error,
            duration_ms=duration_ms,
        ).to_dict()

        await self._emit(
            state.review_id,
            "reviewer_manager_completed",
            {
                "agent_name": "reviewer_manager",
                "agent_label": cfg.label,
                "status": manager_status,
                "model": cfg.model,
                "duration_ms": duration_ms,
                "recommendation": recommendation,
                "findings_count": len(evaluated_findings),
                "rejected_false_positives": len(all_rejected),
                "summary": manager_summary or reason,
                "tool_results": rm_tool_results,
            },
        )
        await ctx.send_message(state)
