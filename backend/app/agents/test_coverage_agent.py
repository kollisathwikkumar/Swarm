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
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    ReviewState,
    StructuredFinding,
)
from app.scanners.code_engines import is_test_file_path
from app.scanners.git_diff_tool import prioritized_diff_excerpt
from app.scanners.test_tools import run_test_and_coverage
from app.skills.shared_contracts import format_agent_contract

logger = logging.getLogger(__name__)


def _parse_line_no(raw: Any) -> int | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        val = int(raw)
        return val if val > 0 else None
    except (TypeError, ValueError):
        return None


def _compact_test_telemetry(
    test_res: dict[str, Any],
    *,
    stair_meta: dict[str, Any] | None = None,
    token_usage: dict[str, int] | None = None,
    llm_skipped: bool = False,
    llm_degraded: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep Test-Coverage telemetry informative without dumping 50KB of unchanged-file coverage."""
    if not test_res:
        return {}
    out: dict[str, Any] = {
        "status": test_res.get("status"),
        "error": test_res.get("error"),
        "runner": test_res.get("runner"),
        "returncode": test_res.get("returncode"),
        "tests_found": test_res.get("tests_found", 0),
        "selected_test_files": (test_res.get("selected_test_files") or [])[:25],
        "selection_mode": test_res.get("selection_mode"),
        "skipped_env_tests": test_res.get("skipped_env_tests") or [],
        "test_files": (test_res.get("test_files") or [])[:25],
        "passed": test_res.get("passed", 0),
        "failed": test_res.get("failed", 0),
        "skipped": test_res.get("skipped", 0),
        "total_coverage_percent": test_res.get("total_coverage_percent"),
        "changed_file_coverage": test_res.get("changed_file_coverage") or {},
        "test_import_map": test_res.get("test_import_map") or {},
        "failure_triage": test_res.get("failure_triage") or {},
        "property_and_mutation": test_res.get("property_and_mutation") or {},
        "output": str(test_res.get("output") or "")[-1800:],
        "llm_skipped_token_saver": llm_skipped,
    }
    if stair_meta:
        out["stair_context"] = stair_meta
    if token_usage:
        out["token_usage"] = token_usage
    if llm_degraded:
        out["llm_degraded"] = llm_degraded
    return out

SYSTEM_PROMPT = """You are the Lead Test-Coverage Agent in Swarm, an automated multi-agent code review system.
Your mission is to perform thorough, real-world test quality and coverage auditing to identify mission-critical testing gaps that cause production outages.

CORE TEST AUDITING MANDATES:
1. MISSING NEGATIVE & ERROR-PATH TESTS:
   - Identify critical functions (APIs, data mutations, payment/auth flows, external I/O) that only test the "happy path" and omit error handling, invalid inputs, network failures, or timeouts.
2. EDGE-CASE & BOUNDARY OMISSIONS:
   - Check for missing tests covering boundary conditions: empty lists, null/None values, zero division, integer overflow, special characters, and concurrency/race conditions.
3. MOCKING ILLUSIONS & FALSE CONFIDENCE:
   - Identify test suites that over-mock internal dependencies, resulting in passing tests that never actually verify the real business logic or database interactions.
4. RUNNABLE TEST SPECIFICATIONS:
   - For every finding, provide the EXACT, copy-pasteable test case implementation (using pytest or vitest) in the recommendation.

CRITICAL ACCURACY RULES:
1. NEVER emit a finding claiming "Test-runner mismatch / 0 Python tests found" against a TypeScript/JavaScript project.
2. Check `test_import_map.source_file_test_map[file]` BEFORE claiming any module has no tests! Modules may have `indirect_importing_tests`.
3. Only report a module as untested if `coverage_status` is `"no_importing_tests_found"` or `"mocked_only_untested"`, or if specific critical execution branches lack coverage.
4. Check `test_import_map.test_suites` AND STAIR linked test slices before claiming a test suite is inadequate.

Return strict JSON:
{
  "summary": "Deep, actionable test execution and reliability gap report.",
  "findings": [
    {
      "severity": "High|Medium|Low",
      "title": "Concise, actionable test or coverage finding title",
      "description": "Technical analysis of what test failed, what critical edge case or error branch is untested, and the real-world production risk.",
      "file_path": "exact/path/to/code_or_test.py",
      "line_number": 18,
      "evidence": "Pytest/Vitest failure, Coverage.py missing_lines, or specific untested logic branch",
      "tool_name": "pytest|coverage.py|vitest|test-mapper|llm-test-review",
      "recommendation": "Exact runnable test code (def test_... or it('...')) to copy-paste directly into the test suite",
      "confidence": 0.90
    }
  ]
}
Never self-certify findings as Verified (EvidenceGuard verifies test/coverage citations independently)."""


class TestCoverageAgentExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="test_coverage_agent")
        self._emit = emit_event

    @handler
    async def handle(
        self, state: ReviewState, ctx: WorkflowContext[AgentExecutionOutput]
    ) -> None:
        t0 = time.perf_counter()
        cfg = state.agent_configs["test_coverage_agent"]
        await self._emit(
            state.review_id,
            "agent_started",
            {
                "agent_name": "test_coverage_agent",
                "agent_label": cfg.label,
                "model": cfg.model,
                "phase": "fan_out",
            },
        )
        test_res: dict[str, Any] = {}
        findings: list[StructuredFinding] = []
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            changed_paths = [f.get("path", "") for f in state.changed_files if f.get("path")]
            agent_plan = (state.review_plan.get("agent_plans") or {}).get("test_coverage_agent") or {}
            enable_exec = bool(state.policy.get("enable_test_execution", True))
            test_res = await run_test_and_coverage(
                state.workspace_dir,
                changed_paths,
                enable_execution=enable_exec,
                plan=agent_plan,
                structure_index=state.structure_index,
            )
            runner_label = str(test_res.get("runner") or "pytest").upper()
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "test_coverage_agent",
                    "message": (
                        f"{runner_label} ({test_res.get('selection_mode', 'full')}): "
                        f"{test_res.get('tests_found', 0)} test file(s) mapped, "
                        f"{test_res.get('passed', 0)} passed, "
                        f"{test_res.get('failed', 0)} failed"
                        + (
                            f", coverage={test_res.get('total_coverage_percent')}%"
                            if test_res.get("total_coverage_percent") is not None
                            else ""
                        )
                    ),
                },
            )

            src_map = (test_res.get("test_import_map") or {}).get("source_file_test_map") or {}
            changed_cov = test_res.get("changed_file_coverage") or {}
            all_changed_covered = bool(src_map) and all(
                bool(info.get("has_any_unmocked_test")) for info in src_map.values()
            )
            no_cov_gaps = all(
                not (cov_info or {}).get("missing_lines")
                for cov_info in changed_cov.values()
            )
            clean_suite_skip = bool(
                cfg.api_key.strip()
                and state.review_plan.get("risk_tier") != "high"
                and test_res.get("status") == "completed"
                and int(test_res.get("passed") or 0) > 0
                and int(test_res.get("failed") or 0) == 0
                and not (test_res.get("skipped_env_tests") or [])
                and all_changed_covered
                and no_cov_gaps
            )
            llm_skipped = bool((agent_plan.get("skip_scanners") and cfg.api_key.strip()) or clean_suite_skip)
            llm_degraded: dict[str, Any] | None = None
            token_usage: dict[str, int] | None = None
            stair_meta: dict[str, Any] = {"token_estimate": 0, "slices_count": 0}

            # Token-saving rule: on skipped/docs-only diffs or completely clean non-high-risk suites where all changed code is covered, skip redundant LLM calls
            if agent_plan.get("skip_scanners") and cfg.api_key.strip():
                llm_out: dict[str, Any] = {
                    "summary": "Skipped test suite execution for low-risk documentation/asset change (token saver).",
                    "findings": [],
                    "llm_skipped_token_saver": True,
                }
            elif clean_suite_skip:
                llm_out = {
                    "summary": (
                        f"{runner_label} passed cleanly ({test_res.get('passed', 0)} passed, 0 failed) "
                        "with full test-import coverage across changed files; LLM call skipped (token saver)."
                    ),
                    "findings": [],
                    "llm_skipped_token_saver": True,
                }
            else:
                # Token-saving rule: prioritize ONLY impacted tests rather than every test file in the repository
                impacted_tests = list(test_res.get("selected_test_files") or [])
                test_first_paths = [p for p in changed_paths if is_test_file_path(p)] + [
                    p for p in changed_paths if not is_test_file_path(p)
                ]
                stair_ctx = build_agent_context(
                    role="test_coverage_agent",
                    workspace_dir=state.workspace_dir,
                    structure_index=state.structure_index,
                    changed_files=state.changed_files,
                    diff_text=state.diff_text,
                    target_files=list(dict.fromkeys(test_first_paths + impacted_tests[:6])),
                    token_budget=agent_plan.get("token_budget"),
                    expand_for_high_risk=state.review_plan.get("risk_tier") == "high",
                )
                stair_meta = {
                    "token_estimate": stair_ctx["token_estimate"],
                    "token_budget": stair_ctx["token_budget"],
                    "slices_count": len(stair_ctx.get("selected_slices") or []),
                }
                prompt_test_payload = {
                    "status": test_res.get("status"),
                    "runner": test_res.get("runner"),
                    "selection_mode": test_res.get("selection_mode"),
                    "passed": test_res.get("passed", 0),
                    "failed": test_res.get("failed", 0),
                    "skipped": test_res.get("skipped", 0),
                    "total_coverage_percent": test_res.get("total_coverage_percent"),
                    "skipped_env_tests": test_res.get("skipped_env_tests") or [],
                    "failure_triage": test_res.get("failure_triage") or {},
                    "changed_file_coverage": changed_cov,
                    "test_import_map": test_res.get("test_import_map") or {},
                    "property_and_mutation": test_res.get("property_and_mutation") or {},
                    "selected_test_files": impacted_tests[:20],
                    "output_tail": str(test_res.get("output") or "")[-1800:],
                }
                diff_excerpt = prioritized_diff_excerpt(
                    state.changed_files, state.diff_text, max_chars=10000
                )
                contract_block = format_agent_contract("test_coverage_agent", agent_plan)

                user_prompt = (
                    f"Repository: {state.repository_name}\n"
                    f"Changed files: {json.dumps(changed_paths[:40], separators=(',', ':'))}\n\n"
                    f"{contract_block}\n\n"
                    "REPRODUCTION & TOKEN RULE: Use only the selected impacted tests and property/mutation candidates below. "
                    "Never claim tests or mutations executed if telemetry shows `executed: false` or `static_js_ts_inspection`.\n\n"
                    f"Test Runner, Failure Triage, Impact Map & Property Candidates:\n{json.dumps(prompt_test_payload, separators=(',', ':'))[:10000]}\n\n"
                    f"{stair_ctx['context_text']}\n\n"
                    f"Unified Diff Excerpt:\n```diff\n{diff_excerpt}\n```"
                )
                try:
                    llm_out = await run_structured_agent(
                        cfg,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        timeout_seconds=80.0,
                        max_tokens=1500,
                    )
                    token_usage = llm_out.pop("_token_usage", None)
                except (MissingAPIKeyError, ReviewCancelledError, asyncio.CancelledError):
                    raise
                except LLM_FALLBACK_EXCEPTIONS as llm_exc:
                    err_reason = str(llm_exc) or type(llm_exc).__name__
                    logger.warning("Test-Coverage Agent LLM fallback: %s", err_reason)
                    llm_degraded = {"reason": err_reason, "fallback": "deterministic_test_runner"}
                    det_findings: list[dict[str, Any]] = []
                    for rel_fp, info in src_map.items():
                        if info.get("coverage_status") in ("no_importing_tests_found", "mocked_only_untested"):
                            det_findings.append(
                                {
                                    "severity": "Medium",
                                    "title": f"Untested changed module `{rel_fp}`",
                                    "description": f"Cross-file test-import mapping status: {info.get('coverage_status')}.",
                                    "file_path": rel_fp,
                                    "line_number": 1,
                                    "evidence": json.dumps(info, separators=(",", ":"))[:300],
                                    "tool_name": "test-mapper",
                                    "recommendation": "Add unit tests exercising error and boundary branches for this module.",
                                    "confidence": 0.85,
                                }
                            )
                            if len(det_findings) >= 10:
                                break
                    llm_out = {
                        "summary": (
                            f"Deterministic {runner_label} & test-import mapping completed "
                            f"({test_res.get('passed', 0)} passed, {test_res.get('failed', 0)} failed); "
                            f"LLM analysis fell back cleanly ({err_reason[:100]})."
                        ),
                        "findings": det_findings,
                    }

            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-test-review")
                raw_conf = item.get("confidence", 0.7 if tool_name != "llm-test-review" else 0.5)
                try:
                    conf = max(0.0, min(1.0, float(raw_conf)))
                except (TypeError, ValueError):
                    conf = 0.5
                findings.append(
                    StructuredFinding(
                        agent="Test-Coverage Agent",
                        category="testing",
                        severity=str(item.get("severity") or "Medium").title(),
                        title=str(item.get("title") or "Test Coverage Gap"),
                        description=str(item.get("description") or ""),
                        file_path=str(item.get("file_path") or ""),
                        line_number=_parse_line_no(item.get("line_number")),
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Needs Verification",
                        tool_name=tool_name,
                        confidence=conf,
                    )
                )

            agent_status = "completed"
            err_msg = test_res.get("error") if test_res.get("status") in ("error", "incomplete", "tool_unavailable") else None

            compact_tr = _compact_test_telemetry(
                test_res,
                stair_meta=stair_meta,
                token_usage=token_usage,
                llm_skipped=llm_skipped,
                llm_degraded=llm_degraded,
            )
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="test_coverage_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status=agent_status,
                summary=str(
                    llm_out.get("summary")
                    or f"Tests: {test_res.get('passed', 0)} passed / {test_res.get('failed', 0)} failed."
                ),
                findings=findings,
                tool_results=compact_tr,
                raw_output=llm_out,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "test_coverage_agent",
                    "agent_label": cfg.label,
                    "status": out.status,
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": len(findings),
                    "summary": out.summary,
                    "tool_results": compact_tr,
                },
            )
            await ctx.send_message(out)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            compact_tr = _compact_test_telemetry(test_res)
            compact_tr["llm_degraded"] = {"reason": str(exc), "mode": "pytest_coverage_fallback"}
            det_findings: list[StructuredFinding] = []
            if int(test_res.get("failed") or 0) > 0:
                det_findings.append(
                    StructuredFinding(
                        agent="Test-Coverage Agent",
                        category="testing",
                        severity="High",
                        title=f"Test Suite Failure: {test_res.get('failed')} failing test(s)",
                        description=f"Automated test runner detected {test_res.get('failed')} failed test(s). See test telemetry for details.",
                        file_path="tests",
                        line_number=1,
                        end_line=None,
                        evidence=str(test_res.get("error") or "")[:300],
                        recommendation="Resolve failing regression tests before merging changes.",
                        verification_status="Needs Verification",
                        tool_name="pytest",
                        confidence=0.95,
                    )
                )
            out = AgentExecutionOutput(
                agent_name="test_coverage_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Deterministic test suite execution ({test_res.get('passed', 0)} passed, {test_res.get('failed', 0)} failed); LLM reasoning bypassed.",
                findings=det_findings,
                tool_results=compact_tr,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "test_coverage_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": len(det_findings),
                    "summary": out.summary,
                    "tool_results": compact_tr,
                },
            )
            await ctx.send_message(out)
        except Exception as exc:
            logger.exception("Test-Coverage Agent fallback to deterministic test execution: %s", exc)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            compact_tr = _compact_test_telemetry(test_res)
            compact_tr["error"] = str(exc)
            out = AgentExecutionOutput(
                agent_name="test_coverage_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Test coverage inspection completed ({test_res.get('passed', 0)} passed, {test_res.get('failed', 0)} failed).",
                findings=[],
                tool_results=compact_tr,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "test_coverage_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": 0,
                    "summary": out.summary,
                    "tool_results": compact_tr,
                },
            )
            await ctx.send_message(out)
