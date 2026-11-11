from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.cache.review_cache import ReviewCache, hash_config_dict
from app.intelligence.context_builder import build_agent_context
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    ReviewState,
    StructuredFinding,
)
from app.scanners.code_engines import prioritize_repo_files
from app.scanners.style_tools import run_style_scanners
from app.skills.shared_contracts import format_agent_contract

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Style Agent in Swarm, an automated multi-agent code review system.
Review the deterministic style/linter outputs (Ruff, AST complexity, duplicate detection) and the STAIR structural context slices.
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
      "tool_name": "ruff|ast-complexity|duplicate-detector|ts-syntax-checker|llm-style-review",
      "rule_id": "E501 or STYLE-NAMING etc",
      "recommendation": "Specific refactoring or formatting fix",
      "confidence": 0.9
    }
  ]
}
Never self-certify findings as Verified (EvidenceGuard verifies tool citations independently). Never invent file paths, lines, or deterministic linter hits."""


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
            agent_plan = (state.review_plan.get("agent_plans") or {}).get("style_agent") or {}
            cache = ReviewCache(state.cache_dir or (state.workspace_dir.parent / "_cache"))
            commit_ctx = f"{state.base_commit}..{state.target_commit}"
            style_res = await run_style_scanners(
                state.workspace_dir,
                changed_paths,
                cache=cache,
                commit_context=commit_ctx,
                config_hash=hash_config_dict({"policy": state.policy, "style_plan": agent_plan}),
                plan=agent_plan,
                structure_index=state.structure_index,
            )
            style_res["cache_stats"] = cache.stats.to_dict()
            ruff_list = (style_res.get("ruff") or {}).get("findings", [])
            eslint_list = (style_res.get("eslint") or {}).get("findings", [])
            pylint_list = (style_res.get("pylint") or {}).get("findings", [])
            dead_list = (style_res.get("dead_code") or {}).get("findings", [])
            ast_list = (style_res.get("ast_checks") or {}).get("findings", [])

            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "style_agent",
                    "message": (
                        f"Style engines finished ({len(ruff_list)} ruff, {len(eslint_list)} eslint, "
                        f"{len(pylint_list)} pylint, {len(dead_list)} dead-code, {len(ast_list)} AST hints"
                        + (", cache hit)" if style_res.get("cache_hit") else ")")
                    ),
                },
            )

            style_evidence = ruff_list + eslint_list + pylint_list + dead_list + ast_list
            # Token-saving rule: deterministic linters report exact violations; invoke LLM ONLY when ambiguous design/complexity/refactor issues exist (or missing API key on normal runs should still surface cleanly)
            design_ambiguity = any(
                item.get("rule_id") in ("STYLE-COMPLEXITY", "STYLE-LONG-FUNCTION", "STYLE-DEEP-NESTING", "STYLE-HIGH-COUPLING", "STYLE-DUPLICATION", "STYLE-EXISTING-PATTERN")
                for item in ast_list
            )
            skip_llm_token_saver = bool(
                (agent_plan.get("skip_scanners") and cfg.api_key.strip())
                or (cfg.api_key.strip() and not design_ambiguity and len(style_evidence) <= 15)
            )
            findings: list[StructuredFinding] = []
            if skip_llm_token_saver:
                for raw_item in style_evidence[:25]:
                    findings.append(
                        StructuredFinding(
                            agent="Style Agent",
                            category="code_quality",
                            severity=str(raw_item.get("severity") or "Low").title(),
                            title=f"{raw_item.get('rule_id') or 'Style'}: {str(raw_item.get('message') or '')[:80]}",
                            description=str(raw_item.get("message") or ""),
                            file_path=str(raw_item.get("file_path") or ""),
                            line_number=raw_item.get("line_number"),
                            end_line=raw_item.get("end_line"),
                            evidence=str(raw_item.get("message") or ""),
                            recommendation="Resolve deterministic lint, syntax, or dead-code violation locally.",
                            verification_status="Needs Verification",
                            tool_name=str(raw_item.get("tool") or "ruff"),
                            rule_id=raw_item.get("rule_id"),
                            confidence=0.92,
                        )
                    )
                llm_out: dict[str, Any] = {
                    "summary": (
                        f"Deterministic linters reported {len(findings)} exact violation(s); LLM call skipped cleanly (token-saving rule)."
                        if findings
                        else "Deterministic linters & AST checks passed cleanly; LLM call skipped (token-saving rule)."
                    ),
                    "llm_skipped_token_saver": True,
                }
            else:
                stair_ctx = build_agent_context(
                    role="style_agent",
                    workspace_dir=state.workspace_dir,
                    structure_index=state.structure_index,
                    changed_files=state.changed_files,
                    diff_text=state.diff_text,
                    evidence_items=style_evidence,
                    target_files=agent_plan.get("focus_files"),
                    token_budget=agent_plan.get("token_budget"),
                )
                contract_block = format_agent_contract("style_agent", agent_plan)
                user_prompt = (
                    f"Repository: {state.repository_name}\n"
                    f"Changed files: {json.dumps(prioritize_repo_files(changed_paths)[:40])}\n\n"
                    f"{contract_block}\n\n"
                    "TOKEN-SAVING INSTRUCTION: Deterministic linters already captured exact rule violations. "
                    "Focus only on explaining complex/ambiguous maintainability issues or small local refactors.\n\n"
                    f"Deterministic Style, Syntax, Dead-Code & AST Tool Results:\n{json.dumps(style_res, indent=2)[:8000]}\n\n"
                    f"{stair_ctx['context_text']}\n\n"
                    f"Code Diff Excerpt:\n```diff\n{(state.diff_text or '')[:8000]}\n```"
                )
                llm_out = await run_structured_agent(
                    cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=70.0
                )

                for item in llm_out.get("findings", []) or []:
                    tool_name = str(item.get("tool_name") or "llm-style-review")
                    raw_conf = item.get("confidence", 0.7 if tool_name != "llm-style-review" else 0.5)
                    try:
                        conf = max(0.0, min(1.0, float(raw_conf)))
                    except (TypeError, ValueError):
                        conf = 0.5
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
                            verification_status="Needs Verification",
                            tool_name=tool_name,
                            rule_id=item.get("rule_id"),
                            confidence=conf,
                        )
                    )

            incomplete_tools = [
                k
                for k, v in style_res.items()
                if isinstance(v, dict) and v.get("status") in ("error", "incomplete", "tool_unavailable")
            ]
            status = "incomplete" if incomplete_tools else "completed"
            err_msg = f"Incomplete style scanners: {', '.join(incomplete_tools)}" if incomplete_tools else None
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="style_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status=status,
                summary=str(llm_out.get("summary") or f"Found {len(findings)} style/quality item(s)."),
                findings=findings,
                tool_results=style_res,
                raw_output=llm_out,
                error_message=err_msg,
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
            logger.exception("Style Agent failed")
            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="style_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="failed",
                summary="Style Agent failed.",
                tool_results=style_res,
                error_message=str(exc),
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_failed",
                {"agent_name": "style_agent", "status": "failed", "error": str(exc), "duration_ms": duration_ms},
            )
            await ctx.send_message(out)
