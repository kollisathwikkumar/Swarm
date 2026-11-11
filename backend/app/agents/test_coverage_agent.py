from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    ReviewState,
    StructuredFinding,
)
from app.scanners.code_engines import is_test_file_path, read_prioritized_workspace_files
from app.scanners.test_tools import run_test_and_coverage

SYSTEM_PROMPT = """You are the Test-Coverage Agent in ReviewBoard, an automated multi-agent code review system.
You receive real test runner results (Pytest / Coverage.py or Vitest), the full Cross-File Test-Import Coverage Map (`test_import_map`), extracted test case lists (`test_suites`), and line-numbered changed files.
CRITICAL ACCURACY RULES:
1. NEVER emit a finding claiming "Test-runner mismatch / 0 Python tests found" against a TypeScript/JavaScript project — that is review harness telemetry, not a defect in the user's code.
2. Check `test_import_map.source_file_test_map[file]` BEFORE claiming any module has no tests! Modules like `git-dirty-state.ts`, `audit-version.ts`, `exclusions.ts`, or `redaction.ts` may have `indirect_importing_tests` even without a `<name>.test.ts` file.
3. Only report a module as untested if `coverage_status` is `"no_importing_tests_found"` or `"mocked_only_untested"`.
4. Check `test_import_map.test_suites` AND full `[COMPLETE FILE]` test listings before claiming a test suite "only tests happy paths".
5. Focus on genuinely verified test failures, mocked-only modules, platform-skipped integration tests, or specific concrete untested error/security branches.
Return strict JSON:
{
  "summary": "Concise test execution & coverage report.",
  "findings": [
    {
      "severity": "High|Medium|Low",
      "title": "Concise test or coverage finding title",
      "description": "What test failed or what changed behavior lacks coverage",
      "file_path": "exact/path/to/code_or_test.py",
      "line_number": 18,
      "evidence": "Pytest/Vitest failure, Coverage.py missing_lines, or test_import_map evidence",
      "tool_name": "pytest|coverage.py|vitest|test-mapper|llm-test-review",
      "recommendation": "Specific test case(s) to add or fix",
      "verification_status": "Verified|Needs Verification"
    }
  ]
}
Only mark findings directly evidenced by failing pytest/vitest runs, Coverage.py missing_lines, or deterministic test-mapper output (`mocked_only_untested`, `no_importing_tests_found`, or `describe.skipIf`) as "Verified"."""


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
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            changed_paths = [f.get("path", "") for f in state.changed_files if f.get("path")]
            enable_exec = bool(state.policy.get("enable_test_execution", True))
            test_res = await run_test_and_coverage(
                state.workspace_dir, changed_paths, enable_execution=enable_exec
            )
            runner_label = str(test_res.get("runner") or "pytest").upper()
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "test_coverage_agent",
                    "message": (
                        f"{runner_label}: {test_res.get('tests_found', 0)} test file(s) mapped, "
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

            test_first_paths = [p for p in changed_paths if is_test_file_path(p)] + [
                p for p in changed_paths if not is_test_file_path(p)
            ]
            test_sources = read_prioritized_workspace_files(
                state.workspace_dir,
                list(dict.fromkeys(test_first_paths + list((test_res.get("test_import_map") or {}).get("test_suites", {}).keys()))),
                max_files=8,
                max_total_chars=18000,
                per_file_chars=10000,
            )

            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Changed files: {json.dumps(changed_paths[:40])}\n\n"
                f"Test Runner & Cross-File Test-Import Coverage Map:\n{json.dumps(test_res, indent=2)[:15000]}\n\n"
                f"Line-Numbered Test & Changed Files:\n{json.dumps(test_sources, indent=2)[:18000]}\n\n"
                f"Unified Diff Excerpt:\n```diff\n{(state.diff_text or '')[:6000]}\n```"
            )
            llm_out = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=70.0
            )

            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-test-review")
                is_det = tool_name in ("pytest", "coverage.py", "vitest", "test-mapper")
                findings.append(
                    StructuredFinding(
                        agent="Test-Coverage Agent",
                        category="testing",
                        severity=str(item.get("severity") or "Medium").title(),
                        title=str(item.get("title") or "Test Coverage Gap"),
                        description=str(item.get("description") or ""),
                        file_path=str(item.get("file_path") or ""),
                        line_number=item.get("line_number"),
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Verified" if is_det else "Needs Verification",
                        tool_name=tool_name,
                    )
                )

            agent_status = "completed"
            err_msg = None
            if test_res.get("status") in ("incomplete", "tool_unavailable"):
                agent_status = "incomplete"
                err_msg = test_res.get("error") or "Test execution incomplete"

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
                tool_results=test_res,
                raw_output=llm_out,
                error_message=err_msg,
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
                },
            )
            await ctx.send_message(out)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="test_coverage_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="incomplete",
                summary="Pytest/Coverage ran, but LLM API key is missing.",
                tool_results=test_res,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "test_coverage_agent", "status": "incomplete", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="test_coverage_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="failed",
                summary="Test-Coverage Agent failed.",
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "test_coverage_agent", "status": "failed", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
