from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.intelligence.context_builder import build_agent_context
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import AgentExecutionOutput, ReviewState
from app.scanners.code_engines import is_test_fixture_hit
from app.skills.shared_contracts import format_agent_contract
from app.verification.evidence_guard import (
    build_evidence_store,
    check_finding_contradiction,
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
    tests_failed = int(test_tr.get("failed", 0))

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

        # Surface deterministic scanner findings directly if an analysis agent failed/missed API key
        # or if security_agent didn't forward deterministic_guards hits
        existing_sig = {
            (str(f.get("file_path") or ""), int(f.get("line_number") or 0), str(f.get("rule_id") or ""))
            for f in all_raw_findings
        }
        for res in results:
            tr = res.tool_results or {}
            if res.agent_name == "security_agent":
                guard_items = (tr.get("deterministic_guards") or {}).get("findings", []) or []
                for item in guard_items:
                    sig = (str(item.get("file_path") or ""), int(item.get("line_number") or 0), str(item.get("rule_id") or ""))
                    if sig not in existing_sig:
                        all_raw_findings.append(
                            {
                                "agent": "Security Agent",
                                "category": "security",
                                "severity": item.get("severity", "Medium"),
                                "title": item.get("title", "Deterministic Security Guard Finding"),
                                "description": item.get("description", ""),
                                "file_path": item.get("file_path", ""),
                                "line_number": item.get("line_number"),
                                "end_line": None,
                                "evidence": item.get("evidence", ""),
                                "recommendation": item.get("description", "Remediate detected guard gap."),
                                "verification_status": "Verified",
                                "tool_name": "security-guard",
                                "rule_id": item.get("rule_id"),
                            }
                        )
            if res.status in ("incomplete", "failed") and tr:
                if res.agent_name == "security_agent":
                    for tool_key in ("bandit", "semgrep", "gitleaks", "osv_scanner"):
                        for item in (tr.get(tool_key) or {}).get("findings", []):
                            all_raw_findings.append(
                                {
                                    "agent": "Security Agent",
                                    "category": "security",
                                    "severity": item.get("severity", "High"),
                                    "title": item.get("title", "Deterministic Security Finding"),
                                    "description": item.get("description", ""),
                                    "file_path": item.get("file_path", ""),
                                    "line_number": item.get("line_number"),
                                    "end_line": item.get("end_line"),
                                    "evidence": item.get("evidence", ""),
                                    "recommendation": "Remediate detected security issue.",
                                    "verification_status": "Verified",
                                    "tool_name": item.get("tool", tool_key),
                                    "rule_id": item.get("rule_id"),
                                }
                            )
                elif res.agent_name == "style_agent":
                    for section in ("ruff", "ast_checks"):
                        for item in (tr.get(section) or {}).get("findings", []):
                            all_raw_findings.append(
                                {
                                    "agent": "Style Agent",
                                    "category": "code_quality",
                                    "severity": item.get("severity", "Low"),
                                    "title": item.get("rule_id", "Style Violation"),
                                    "description": item.get("message", ""),
                                    "file_path": item.get("file_path", ""),
                                    "line_number": item.get("line_number"),
                                    "end_line": item.get("end_line"),
                                    "evidence": item.get("message", ""),
                                    "recommendation": "Fix code style/complexity issue.",
                                    "verification_status": "Verified",
                                    "tool_name": item.get("tool", "ruff"),
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
            )
            if fabricated:
                fabricated_claims += 1
            if guarded.get("tool_name") == "gitleaks" and is_test_fixture_hit(
                state.workspace_dir, fp, ln, str(guarded.get("evidence") or "")
            ):
                guarded["severity"] = "Low"
                guarded["is_test_fixture"] = True

            verified_raw.append(guarded)

        test_suites = ((extras.get("test_import_map") or {}).get("test_suites") or {}).keys()
        manager_plan = (state.review_plan.get("agent_plans") or {}).get("reviewer_manager") or {}
        stair_ctx = build_agent_context(
            role="reviewer_manager",
            workspace_dir=state.workspace_dir,
            structure_index=state.structure_index,
            changed_files=state.changed_files,
            diff_text=state.diff_text,
            evidence_items=state.evidence_store,
            findings=verified_raw,
            target_files=list(dict.fromkeys(referenced_files + list(test_suites))),
            token_budget=manager_plan.get("token_budget"),
            expand_for_high_risk=state.review_plan.get("risk_tier") == "high",
        )
        contract_block = format_agent_contract("reviewer_manager", manager_plan)

        consolidated: list[dict[str, Any]] = []
        rejected_llm: list[dict[str, Any]] = []
        manager_summary = ""
        manager_status = "completed"
        manager_error: str | None = None
        manager_raw: dict[str, Any] = {}

        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')}\n"
                f"Diff Summary: {state.diff_summary[:2000]}\n"
                f"Agent Execution Statuses: {json.dumps({r.agent_name: r.status for r in results})}\n\n"
                f"{contract_block}\n\n"
                f"Immutable EvidenceStore ({len(state.evidence_store)} records):\n"
                f"{json.dumps(state.evidence_store[:60], indent=2)[:8000]}\n\n"
                f"Polyglot Symbols & Guards (across complete files):\n"
                f"{json.dumps(extras['polyglot_symbols'], indent=2)[:6000]}\n\n"
                f"Cross-File Test-Import Coverage Map:\n"
                f"{json.dumps(extras['test_import_map'], indent=2)[:6000]}\n\n"
                f"{stair_ctx['context_text']}\n\n"
                f"Candidate Findings ({len(verified_raw)}):\n"
                f"{json.dumps(verified_raw, indent=2)[:14000]}"
            )
            manager_raw = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=95.0
            )
            manager_summary = str(manager_raw.get("executive_summary") or "").strip()
            rejected_llm = list(manager_raw.get("rejected_false_positives") or [])

            for idx, item in enumerate(manager_raw.get("consolidated_findings", []) or [], start=1):
                noise_reason = check_finding_contradiction(item, extras)
                if noise_reason:
                    rejected_auto.append(
                        {"title": item.get("title", ""), "file_path": item.get("file_path", ""), "reason": noise_reason}
                    )
                    continue

                # Force EvidenceGuard provenance verification regardless of what LLM claims
                guarded_item, fabricated = verify_finding_provenance(
                    item,
                    evidence_records,
                    state.workspace_dir,
                )
                if fabricated:
                    fabricated_claims += 1

                fp = str(guarded_item.get("file_path") or "").strip()
                ln = guarded_item.get("line_number")
                sev = str(guarded_item.get("severity") or "Medium").title()
                if guarded_item.get("tool_name") == "gitleaks" and is_test_fixture_hit(
                    state.workspace_dir, fp, ln, str(guarded_item.get("evidence") or "")
                ):
                    sev = "Low"

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
            if not consolidated and verified_raw and not rejected_llm:
                consolidated = _deterministic_deduplicate(verified_raw)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            manager_status = "incomplete"
            manager_error = str(exc)
            consolidated = _deterministic_deduplicate(verified_raw)
            manager_summary = "Reviewer Manager LLM API key is missing; deterministic consolidation applied."
        except Exception as exc:
            logger.exception("Reviewer Manager LLM failed")
            manager_status = "failed"
            manager_error = str(exc)
            consolidated = _deterministic_deduplicate(verified_raw)
            manager_summary = f"Reviewer Manager LLM error: {exc}"

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

        duration_ms = int((time.perf_counter() - t0) * 1000)
        state.agent_results["reviewer_manager"] = AgentExecutionOutput(
            agent_name="reviewer_manager",
            agent_label=cfg.label,
            model_used=cfg.model,
            status=manager_status,
            summary=manager_summary or reason,
            tool_results={
                "consolidated_count": len(evaluated_findings),
                "rejected_false_positives_count": len(all_rejected),
                "rejected_false_positives": all_rejected[:20],
                "evidence_store_count": len(evidence_records),
                "fabricated_tool_claims_count": fabricated_claims,
                "stair_context_tokens": stair_ctx["token_estimate"],
                "stair_fallback_used": stair_ctx["fallback_used"],
                "recommendation": recommendation,
            },
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
            },
        )
        await ctx.send_message(state)
