from __future__ import annotations

import asyncio
import json
import logging
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
from app.scanners.code_engines import read_prioritized_workspace_files
from app.scanners.security_tools import run_security_scanners

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Security Agent in Swarm, an automated multi-agent code review system.
You receive deterministic scan findings from Semgrep, Bandit, Gitleaks, OSV-Scanner, and Deterministic Security Guards along with line-numbered changed source files and diff.
Your job:
1. Interpret deterministic scanner hits and verify whether they represent real security vulnerabilities (if Gitleaks marks a hit with `is_test_fixture: true` in a unit test file with fake fixture values, keep it Low informational or note it is a benign test fixture rather than calling it a leaked production key).
2. Inspect the COMPLETE source files provided for semantic security issues (SQL injection, auth bypass, incomplete redaction regexes, SSRF/unvalidated destinations, path traversal, insecure crypto, XSS, command injection).
3. Respect `[COMPLETE FILE]` / `[PARTIAL FILE]` headers: NEVER claim URL checks, citation checks, or sanitization is absent if a complete file implements it or if only a partial prefix was shown!
4. Assign accurate severity (Critical, High, Medium, Low) and distinguish verified deterministic tool evidence ("Verified") from LLM-only suspicions ("Needs Verification").
Return strict JSON:
{
  "summary": "Concise security posture summary.",
  "findings": [
    {
      "severity": "Critical|High|Medium|Low",
      "title": "Clear security finding title",
      "description": "Technical explanation of exploitability and risk",
      "file_path": "exact/path/from/repo.py",
      "line_number": 24,
      "evidence": "Exact vulnerable expression or scanner output",
      "tool_name": "semgrep|bandit|gitleaks|osv-scanner|security-guard|llm-security-review",
      "rule_id": "Rule or CWE identifier",
      "recommendation": "Exact remediation steps",
      "verification_status": "Verified|Needs Verification"
    }
  ]
}
Never invent file paths, lines, or fake vulnerabilities. If no vulnerabilities exist, return an empty findings array."""


class SecurityAgentExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="security_agent")
        self._emit = emit_event

    @handler
    async def handle(
        self, state: ReviewState, ctx: WorkflowContext[AgentExecutionOutput]
    ) -> None:
        t0 = time.perf_counter()
        cfg = state.agent_configs["security_agent"]
        await self._emit(
            state.review_id,
            "agent_started",
            {
                "agent_name": "security_agent",
                "agent_label": cfg.label,
                "model": cfg.model,
                "phase": "fan_out",
            },
        )
        sec_res: dict[str, Any] = {}
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            changed_paths = [f.get("path", "") for f in state.changed_files if f.get("path")]
            sec_res = await run_security_scanners(state.workspace_dir, changed_paths)
            total_raw = sum(len(sec_res[k].get("findings", [])) for k in sec_res)
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "security_agent",
                    "message": (
                        f"Scanners finished (Bandit: {len(sec_res['bandit']['findings'])}, "
                        f"Semgrep: {len(sec_res['semgrep']['findings'])}, "
                        f"Gitleaks: {len(sec_res['gitleaks']['findings'])}, "
                        f"OSV: {len(sec_res['osv_scanner']['findings'])}, "
                        f"Guards: {len(sec_res['deterministic_guards']['findings'])})"
                    ),
                },
            )

            # Prioritize production security/source files with complete line-numbered contents
            changed_contents = read_prioritized_workspace_files(
                state.workspace_dir,
                changed_paths,
                max_files=10,
                max_total_chars=24000,
                per_file_chars=12000,
            )

            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Deterministic Scanner Results (total raw hits={total_raw}):\n"
                f"{json.dumps(sec_res, indent=2)[:12000]}\n\n"
                f"Line-Numbered Changed Source Files:\n{json.dumps(changed_contents, indent=2)[:24000]}\n\n"
                f"Unified Diff Excerpt:\n```diff\n{(state.diff_text or '')[:8000]}\n```"
            )
            llm_out = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=75.0
            )

            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-security-review")
                is_det = tool_name in ("semgrep", "bandit", "gitleaks", "osv-scanner", "security-guard")
                findings.append(
                    StructuredFinding(
                        agent="Security Agent",
                        category="security",
                        severity=str(item.get("severity") or "Medium").title(),
                        title=str(item.get("title") or "Security Finding"),
                        description=str(item.get("description") or ""),
                        file_path=str(item.get("file_path") or ""),
                        line_number=item.get("line_number"),
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Verified" if is_det else "Needs Verification",
                        tool_name=tool_name,
                        rule_id=item.get("rule_id"),
                    )
                )

            # Check if any security tool itself failed/unavailable
            incomplete_tools = [
                k for k, v in sec_res.items() if v.get("status") in ("error", "incomplete", "tool_unavailable")
            ]
            status = "incomplete" if incomplete_tools else "completed"
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="security_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status=status,
                summary=str(
                    llm_out.get("summary")
                    or f"Security analysis identified {len(findings)} finding(s)."
                ),
                findings=findings,
                tool_results=sec_res,
                raw_output=llm_out,
                error_message=(
                    f"Incomplete scanners: {', '.join(incomplete_tools)}"
                    if incomplete_tools
                    else None
                ),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "security_agent",
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
                agent_name="security_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="incomplete",
                summary="Deterministic security scanners ran, but LLM API key is missing.",
                tool_results=sec_res,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "security_agent", "status": "incomplete", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
        except Exception as exc:
            logger.exception("Security Agent failed")
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="security_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="failed",
                summary="Security Agent failed.",
                tool_results=sec_res,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "security_agent", "status": "failed", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
