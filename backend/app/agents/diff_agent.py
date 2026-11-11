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
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    ReviewState,
    StructuredFinding,
)
from app.scanners.git_diff_tool import collect_diff_context
from app.skills.shared_contracts import format_agent_contract

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Diff Agent in Swarm, an automated multi-agent code review system.
Analyze the submitted Git diff, affected files, line-numbered complete source files, and Polyglot Symbol & Defensive Guard Facts.
Identify what changed, summarize the functional intent, and highlight concrete, verified behavioral or architectural bugs/risks.
CRITICAL ACCURACY RULES:
1. Check the `[COMPLETE FILE]` / `[PARTIAL FILE]` header and `polyglot_symbols.*.implemented_guards_in_full_file` BEFORE claiming any validation, URL check, citation check, or guard is missing!
2. NEVER claim a check or helper is missing if `implemented_guards_in_full_file` shows it exists later in the file (e.g., `validateEndpoint` or `evidenceIds` citation checking), or if only a `[PARTIAL FILE]` was shown.
3. Only report concrete issues directly evidenced by an exact line number `[NNN]` from the source/diff shown to you.
Return strict JSON with this exact schema:
{
  "diff_summary": "2-4 sentence technical summary of the code changes.",
  "risk_areas": [
    {
      "file_path": "path/to/file.py",
      "line_number": 24,
      "risk_level": "High|Medium|Low",
      "reason": "Concrete explanation of why this modification is risky."
    }
  ],
  "findings": [
    {
      "severity": "High|Medium|Low",
      "title": "Short finding title",
      "description": "Detailed explanation of the change risk",
      "file_path": "path/to/file.py",
      "line_number": 24,
      "evidence": "Exact code line or hunk excerpt from the file/diff",
      "recommendation": "Actionable engineering guidance"
    }
  ]
}
Only report findings grounded in the actual code provided. Do not invent file paths or line numbers."""


class DiffAgentExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="diff_agent")
        self._emit = emit_event

    @handler
    async def handle(
        self, state: ReviewState, ctx: WorkflowContext[AgentExecutionOutput]
    ) -> None:
        t0 = time.perf_counter()
        cfg = state.agent_configs["diff_agent"]
        await self._emit(
            state.review_id,
            "agent_started",
            {
                "agent_name": "diff_agent",
                "agent_label": cfg.label,
                "model": cfg.model,
                "phase": "fan_out",
            },
        )
        diff_ctx: dict[str, Any] = {}
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            diff_ctx = await collect_diff_context(
                state.workspace_dir,
                base_commit=state.base_commit,
                target_commit=state.target_commit,
                diff_text=state.diff_text,
                changed_files=state.changed_files,
            )
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "diff_agent",
                    "message": f"Parsed {diff_ctx['total_files']} changed file(s) (+{diff_ctx['total_additions']} / -{diff_ctx['total_deletions']})",
                },
            )

            compact_files = [
                {
                    "path": f.get("path"),
                    "status": f.get("status"),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changed_lines": (f.get("changed_lines") or [])[:40],
                }
                for f in diff_ctx.get("files", [])
            ]
            compact_ctx = {
                "total_files": diff_ctx.get("total_files"),
                "total_additions": diff_ctx.get("total_additions"),
                "total_deletions": diff_ctx.get("total_deletions"),
                "files": compact_files[:40],
                "polyglot_symbols": diff_ctx.get("polyglot_symbols", {}),
            }
            agent_plan = (state.review_plan.get("agent_plans") or {}).get("diff_agent") or {}
            stair_ctx = build_agent_context(
                role="diff_agent",
                workspace_dir=state.workspace_dir,
                structure_index=state.structure_index,
                changed_files=state.changed_files,
                diff_text=state.diff_text,
                target_files=agent_plan.get("focus_files"),
                token_budget=agent_plan.get("token_budget"),
                expand_for_high_risk=state.review_plan.get("risk_tier") == "high",
            )
            truncated_diff = (state.diff_text or "")[:10000]
            contract_block = format_agent_contract("diff_agent", agent_plan)
            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Base commit: {state.base_commit} | Target commit: {state.target_commit}\n"
                f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')}\n\n"
                f"{contract_block}\n\n"
                f"Changed files & Polyglot Symbols/Guards:\n{json.dumps(compact_ctx, indent=2)[:8000]}\n\n"
                f"{stair_ctx['context_text']}\n\n"
                f"Unified Diff Excerpt:\n```diff\n{truncated_diff}\n```"
            )
            llm_out = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=70.0
            )

            diff_summary = str(llm_out.get("diff_summary") or "").strip()
            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                raw_conf = item.get("confidence", 0.55)
                try:
                    conf = max(0.0, min(1.0, float(raw_conf)))
                except (TypeError, ValueError):
                    conf = 0.55
                findings.append(
                    StructuredFinding(
                        agent="Diff Agent",
                        category="change_risk",
                        severity=str(item.get("severity") or "Medium").title(),
                        title=str(item.get("title") or "Change Risk"),
                        description=str(item.get("description") or ""),
                        file_path=str(item.get("file_path") or ""),
                        line_number=item.get("line_number"),
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Needs Verification",
                        tool_name="git-diff",
                        confidence=conf,
                    )
                )

            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=diff_summary or f"Analyzed {diff_ctx['total_files']} changed file(s).",
                findings=findings,
                tool_results=diff_ctx,
                raw_output=llm_out,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "diff_agent",
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
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="incomplete",
                summary="Diff context collected, but LLM API key is missing.",
                tool_results=diff_ctx,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {
                    "agent_name": "diff_agent",
                    "status": "incomplete",
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )
            await ctx.send_message(out)
        except Exception as exc:
            logger.exception("Diff Agent failed")
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="failed",
                summary="Diff Agent execution failed.",
                tool_results=diff_ctx,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {
                    "agent_name": "diff_agent",
                    "status": "failed",
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )
            await ctx.send_message(out)
