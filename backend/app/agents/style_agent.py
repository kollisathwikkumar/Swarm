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
from app.scanners.code_engines import prioritize_repo_files, read_prioritized_workspace_files
from app.scanners.style_tools import run_style_scanners

SYSTEM_PROMPT = """You are the Style Agent in ReviewBoard, an automated multi-agent code review system.
Review the deterministic style/linter outputs (Ruff, AST complexity, duplicate detection) and the actual changed code.
Identify formatting inconsistencies, naming convention violations, code duplication, and readability/maintainability issues.
Return strict JSON with this schema:
{
  "summary": "Concise code quality assessment.",
  "findings": [
    {
      "severity": "High|Medium|Low",
      "title": "Concise style or maintainability issue title",
      "description": "Why this harms maintainability or violates standards",
      "file_path": "exact/path/from/repo.py",
      "line_number": 12,
      "evidence": "Exact code line or linter rule evidence",
      "tool_name": "ruff|ast-complexity|duplicate-detector|llm-style-review",
      "rule_id": "E501 or STYLE-NAMING etc",
      "recommendation": "Specific refactoring or formatting fix",
      "verification_status": "Verified|Needs Verification"
    }
  ]
}
Mark findings backed by Ruff/AST/duplicate-detector as "Verified", and purely LLM-spotted style advice as "Needs Verification".
Never invent file paths or line numbers."""


class StyleAgentExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="style_agent")
        self._emit = emit_event

    @handler
    async def handle(
        self, state: ReviewState, ctx: WorkflowContext[AgentExecutionOutput]
    ) -> None:
        t0 = time.perf_counter()
        cfg = state.agent_configs["style_agent"]
        await self._emit(
            state.review_id,
            "agent_started",
            {
                "agent_name": "style_agent",
                "agent_label": cfg.label,
                "model": cfg.model,
                "phase": "fan_out",
            },
        )
        style_res: dict[str, Any] = {}
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            changed_paths = [f.get("path", "") for f in state.changed_files if f.get("path")]
            style_res = await run_style_scanners(state.workspace_dir, changed_paths)
            ruff_count = len(style_res["ruff"]["findings"])
            ast_count = len(style_res["ast_checks"]["findings"])
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "style_agent",
                    "message": f"Ruff & AST scanners completed ({ruff_count} ruff, {ast_count} AST/duplicate hints)",
                },
            )

            full_sources = read_prioritized_workspace_files(
                state.workspace_dir,
                changed_paths,
                max_files=10,
                max_total_chars=20000,
                per_file_chars=8000,
            )
            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Changed files: {json.dumps(prioritize_repo_files(changed_paths)[:40])}\n\n"
                f"Deterministic Style, Syntax & AST Tool Results:\n{json.dumps(style_res, indent=2)[:8000]}\n\n"
                f"Line-Numbered Changed Source Files:\n{json.dumps(full_sources, indent=2)[:20000]}\n\n"
                f"Code Diff Excerpt:\n```diff\n{(state.diff_text or '')[:8000]}\n```"
            )
            llm_out = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=70.0
            )

            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-style-review")
                is_det = tool_name in (
                    "ruff",
                    "ast-complexity",
                    "ast-style-checker",
                    "js-style-checker",
                    "duplicate-detector",
                    "python-ast",
                    "ts-syntax-checker",
                )
                findings.append(
                    StructuredFinding(
                        agent="Style Agent",
                        category="code_quality",
                        severity=str(item.get("severity") or "Low").title(),
                        title=str(item.get("title") or "Code Quality Issue"),
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

            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="style_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=str(llm_out.get("summary") or f"Found {len(findings)} style/quality item(s)."),
                findings=findings,
                tool_results=style_res,
                raw_output=llm_out,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "style_agent",
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
                agent_name="style_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="incomplete",
                summary="Style scanners ran, but LLM API key is missing.",
                tool_results=style_res,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "style_agent", "status": "incomplete", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
        except Exception as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="style_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="failed",
                summary="Style Agent failed.",
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "style_agent", "status": "failed", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
