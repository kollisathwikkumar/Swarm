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
from app.scanners.git_diff_tool import collect_diff_context, prioritized_diff_excerpt
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


def _compact_diff_telemetry(
    diff_ctx: dict[str, Any],
    *,
    stair_meta: dict[str, Any] | None = None,
    token_usage: dict[str, int] | None = None,
    llm_skipped: bool = False,
    llm_degraded: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep Diff Agent telemetry structured and lightweight without duplicating multi-MB raw diff patches."""
    if not diff_ctx:
        return {}
    compact_files = [
        {
            "path": f.get("path"),
            "status": f.get("status"),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "changed_lines": (f.get("changed_lines") or [])[:40],
        }
        for f in (diff_ctx.get("files") or [])[:50]
    ]
    out: dict[str, Any] = {
        "base_commit": diff_ctx.get("base_commit"),
        "target_commit": diff_ctx.get("target_commit"),
        "total_files": diff_ctx.get("total_files", 0),
        "total_additions": diff_ctx.get("total_additions", 0),
        "total_deletions": diff_ctx.get("total_deletions", 0),
        "git_stat": diff_ctx.get("git_stat", ""),
        "files": compact_files,
        "ast_diff": diff_ctx.get("ast_diff") or {},
        "polyglot_symbols": diff_ctx.get("polyglot_symbols") or {},
        "llm_skipped_token_saver": llm_skipped,
    }
    if stair_meta:
        out["stair_context"] = stair_meta
    if token_usage:
        out["token_usage"] = token_usage
    if llm_degraded:
        out["llm_degraded"] = llm_degraded
    return out

SYSTEM_PROMPT = """You are the Lead Diff & Architecture Agent in Swarm, an advanced multi-agent code review system.
Analyze the submitted Git diff, affected files, line-numbered complete source files, and Polyglot Symbol & Defensive Guard Facts.
Identify functional intent and highlight concrete, verified behavioral, contract, and architectural risks that cause production regressions.

CORE CHANGE-RISK AUDITING MANDATES:
1. API & CONTRACT BREAKING CHANGES:
   - Identify modifications to public function/method signatures, altered return schemas, removed/renamed fields, or changed HTTP route status codes that break downstream callers.
2. ASYNC & CONCURRENCY TRAPS:
   - Identify unawaited promises/coroutines, missing error handlers in background tasks, and race conditions on shared memory or database rows.
3. TRANSACTION & STATE SAFETY:
   - Identify mutating database operations missing transaction rollback handling on error, leading to partial or corrupted persistent state.
4. NULL POINTERS & BOUNDARY DEREFERENCES:
   - Identify property or dictionary key access on nullable/optional objects without defensive checks (causing AttributeError / TypeError / Cannot read property of undefined in production).

CRITICAL ACCURACY RULES:
1. Check the `[COMPLETE FILE]` / `[PARTIAL FILE]` header and `polyglot_symbols.*.implemented_guards_in_full_file` BEFORE claiming any validation, URL check, citation check, or guard is missing!
2. NEVER claim a check or helper is missing if `implemented_guards_in_full_file` shows it exists later in the file (e.g., `validateEndpoint` or `evidenceIds` citation checking), or if only a `[PARTIAL FILE]` was shown.
3. Only report concrete issues directly evidenced by an exact line number `[NNN]` from the source/diff shown to you.
Return strict JSON with this exact schema:
{
  "diff_summary": "2-4 sentence technical summary of the code changes and architectural impact.",
  "risk_areas": [
    {
      "file_path": "path/to/file.py",
      "line_number": 24,
      "risk_level": "High|Medium|Low",
      "reason": "Concrete explanation of why this modification poses behavioral or breaking risks."
    }
  ],
  "findings": [
    {
      "severity": "High|Medium|Low",
      "title": "Short, technically precise finding title",
      "description": "Detailed explanation of the behavioral regression, contract drift, or concurrency defect.",
      "file_path": "path/to/file.py",
      "line_number": 24,
      "evidence": "Exact code line or hunk excerpt from the file/diff",
      "recommendation": "Actionable, production-ready engineering guidance to eliminate the risk."
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
        ast_diff: dict[str, Any] = {}
        findings: list[StructuredFinding] = []
        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            diff_ctx = await collect_diff_context(
                state.workspace_dir,
                base_commit=state.base_commit,
                target_commit=state.target_commit,
                diff_text=state.diff_text,
                changed_files=state.changed_files,
                structure_index=state.structure_index,
            )
            ast_diff = diff_ctx.get("ast_diff") or {}
            semantic_counts = ast_diff.get("semantic_counts") or {}
            await self._emit(
                state.review_id,
                "agent_progress",
                {
                    "agent_name": "diff_agent",
                    "message": (
                        f"Parsed {diff_ctx['total_files']} changed file(s) "
                        f"(+{diff_ctx['total_additions']}/-{diff_ctx['total_deletions']}, "
                        f"{len(ast_diff.get('ast_symbol_changes') or [])} symbol diff(s), "
                        f"{len(ast_diff.get('api_contract_changes') or [])} API contract change(s))"
                    ),
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
                "ast_diff": {
                    "semantic_counts": semantic_counts,
                    "ast_symbol_changes": (ast_diff.get("ast_symbol_changes") or [])[:25],
                    "api_contract_changes": ast_diff.get("api_contract_changes") or [],
                    "config_and_dependency_impacts": ast_diff.get("config_and_dependency_impacts") or [],
                    "downstream_impact": ast_diff.get("downstream_impact") or {},
                },
                "polyglot_symbols": diff_ctx.get("polyglot_symbols", {}),
            }
            agent_plan = (state.review_plan.get("agent_plans") or {}).get("diff_agent") or {}
            plan_mode = str(agent_plan.get("mode") or "standard")
            pure_cosmetic = (
                bool(cfg.api_key.strip())
                and semantic_counts.get("cosmetic_or_variable_renames", 0) > 0
                and semantic_counts.get("added_symbols", 0) == 0
                and semantic_counts.get("removed_symbols", 0) == 0
                and semantic_counts.get("signature_or_contract_changes", 0) == 0
                and semantic_counts.get("permission_or_guard_edits", 0) == 0
                and semantic_counts.get("algorithm_or_logic_edits", 0) == 0
                and not ast_diff.get("config_and_dependency_impacts")
                and not ast_diff.get("findings")
            )

            stair_ctx: dict[str, Any] = {
                "token_estimate": 0,
                "token_budget": 0,
                "selected_slices": [],
                "fallback_used": False,
            }
            llm_skipped = False
            llm_degraded: dict[str, Any] | None = None
            token_usage: dict[str, int] | None = None

            if pure_cosmetic:
                llm_skipped = True
                llm_out: dict[str, Any] = {
                    "diff_summary": (
                        f"AST diff verified purely cosmetic/variable-rename changes across "
                        f"{diff_ctx['total_files']} file(s) (+{diff_ctx['total_additions']}/-"
                        f"{diff_ctx['total_deletions']}) with zero semantic or contract impact; "
                        "LLM skipped (token saver)."
                    ),
                    "findings": [],
                    "llm_skipped_token_saver": True,
                }
            elif plan_mode == "light":
                diff_excerpt = prioritized_diff_excerpt(
                    diff_ctx.get("files") or [], state.diff_text, max_chars=3000
                )
                user_prompt = (
                    f"Repository: {state.repository_name} | Mode: light (docs/assets)\n"
                    f"Files: {json.dumps(compact_files[:15], separators=(',', ':'))}\n"
                    f"Unified Diff:\n```diff\n{diff_excerpt}\n```\n"
                    "Summarize the documentation/asset changes concisely in JSON (`diff_summary`, `risk_areas`, `findings`)."
                )
                try:
                    llm_out = await run_structured_agent(
                        cfg,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        timeout_seconds=60.0,
                        max_tokens=600,
                    )
                    token_usage = llm_out.pop("_token_usage", None)
                except (MissingAPIKeyError, ReviewCancelledError, asyncio.CancelledError):
                    raise
                except LLM_FALLBACK_EXCEPTIONS as llm_exc:
                    err_reason = str(llm_exc) or type(llm_exc).__name__
                    logger.warning("Diff Agent light LLM fallback: %s", err_reason)
                    llm_degraded = {"reason": err_reason, "fallback": "deterministic_ast_diff"}
                    llm_out = {
                        "diff_summary": (
                            f"Deterministic diff inspection mapped {diff_ctx['total_files']} documentation/asset "
                            f"file(s) (+{diff_ctx['total_additions']}/-{diff_ctx['total_deletions']}). "
                            f"LLM narrative fell back cleanly ({err_reason[:100]})."
                        ),
                        "findings": [],
                    }
            else:
                # Token-saving rule: retrieve surrounding caller/callee context only when symbols have logic/contract edits or high risk
                needs_surrounding = bool(
                    semantic_counts.get("algorithm_or_logic_edits", 0)
                    or semantic_counts.get("signature_or_contract_changes", 0)
                    or semantic_counts.get("permission_or_guard_edits", 0)
                    or state.review_plan.get("risk_tier") == "high"
                )
                eff_budget = (
                    agent_plan.get("token_budget", 2400)
                    if needs_surrounding
                    else min(1200, agent_plan.get("token_budget", 1200))
                )
                stair_ctx = build_agent_context(
                    role="diff_agent",
                    workspace_dir=state.workspace_dir,
                    structure_index=state.structure_index,
                    changed_files=state.changed_files,
                    diff_text=state.diff_text,
                    evidence_items=ast_diff.get("findings") or [],
                    target_files=agent_plan.get("focus_files"),
                    token_budget=eff_budget,
                    expand_for_high_risk=state.review_plan.get("risk_tier") == "high",
                )
                diff_excerpt = prioritized_diff_excerpt(
                    diff_ctx.get("files") or [], state.diff_text, max_chars=12000
                )
                contract_block = format_agent_contract("diff_agent", agent_plan)
                user_prompt = (
                    f"Repository: {state.repository_name}\n"
                    f"Base commit: {state.base_commit} | Target commit: {state.target_commit}\n"
                    f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')}\n\n"
                    f"{contract_block}\n\n"
                    f"Changed files & Polyglot Symbols/Guards:\n{json.dumps(compact_ctx, separators=(',', ':'))[:6000]}\n\n"
                    f"{stair_ctx['context_text']}\n\n"
                    f"Prioritized Unified Diff Excerpt:\n```diff\n{diff_excerpt}\n```"
                )
                try:
                    llm_out = await run_structured_agent(
                        cfg,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        timeout_seconds=85.0,
                        max_tokens=1600,
                    )
                    token_usage = llm_out.pop("_token_usage", None)
                except (MissingAPIKeyError, ReviewCancelledError, asyncio.CancelledError):
                    raise
                except LLM_FALLBACK_EXCEPTIONS as llm_exc:
                    err_reason = str(llm_exc) or type(llm_exc).__name__
                    logger.warning("Diff Agent LLM fallback: %s", err_reason)
                    llm_degraded = {"reason": err_reason, "fallback": "deterministic_ast_diff"}
                    llm_out = {
                        "diff_summary": (
                            f"Deterministic AST & symbol analysis mapped {diff_ctx['total_files']} changed file(s) "
                            f"(+{diff_ctx['total_additions']}/-{diff_ctx['total_deletions']}, "
                            f"{len(ast_diff.get('findings') or [])} contract signal(s)). "
                            f"Deep LLM summary fell back cleanly ({err_reason[:100]})."
                        ),
                        "findings": [],
                    }

            diff_summary = str(llm_out.get("diff_summary") or "").strip()
            findings: list[StructuredFinding] = []
            seen_keys: set[tuple[str, int | None, str]] = set()
            for det in ast_diff.get("findings") or []:
                fp = str(det.get("file_path") or "").strip()
                ln = _parse_line_no(det.get("line_number"))
                rid = str(det.get("rule_id") or "DIFF-API-CONTRACT-CHANGE")
                seen_keys.add((fp, ln, rid))
                findings.append(
                    StructuredFinding(
                        agent="Diff Agent",
                        category="change_risk",
                        severity=str(det.get("severity") or "Medium").title(),
                        title=str(det.get("title") or "API Contract Change"),
                        description=str(det.get("evidence") or ""),
                        file_path=fp,
                        line_number=ln,
                        end_line=None,
                        evidence=str(det.get("evidence") or ""),
                        recommendation="Verify downstream callers match the updated signature or interface.",
                        verification_status="Needs Verification",
                        tool_name=str(det.get("tool") or "diff-ast-engine"),
                        rule_id=rid,
                        confidence=0.92,
                    )
                )

            for item in llm_out.get("findings", []) or []:
                fp = str(item.get("file_path") or "").strip()
                ln = _parse_line_no(item.get("line_number"))
                rid = str(item.get("rule_id") or "")
                if (fp, ln, rid) in seen_keys and rid:
                    continue
                tname = str(item.get("tool_name") or "git-diff")
                if tname not in ("git-diff", "diff-ast-engine", "llm-review"):
                    tname = "git-diff"
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
                        file_path=fp,
                        line_number=ln,
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Needs Verification",
                        tool_name=tname,
                        rule_id=rid or None,
                        confidence=conf,
                    )
                )

            stair_meta = {
                "token_estimate": stair_ctx["token_estimate"],
                "token_budget": stair_ctx["token_budget"],
                "slices_count": len(stair_ctx.get("selected_slices") or []),
                "fallback_used": stair_ctx["fallback_used"],
            }
            compact_tr = _compact_diff_telemetry(
                diff_ctx,
                stair_meta=stair_meta,
                token_usage=token_usage,
                llm_skipped=llm_skipped,
                llm_degraded=llm_degraded,
            )

            duration_ms = int((time.perf_counter() - t0) * 1000)
            out = AgentExecutionOutput(
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=diff_summary or f"Analyzed {diff_ctx['total_files']} changed file(s).",
                findings=findings,
                tool_results=compact_tr,
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
                    "tool_results": compact_tr,
                },
            )
            await ctx.send_message(out)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            compact_tr = _compact_diff_telemetry(diff_ctx)
            compact_tr["llm_degraded"] = {"reason": str(exc), "mode": "ast_structural_fallback"}
            det_findings = list(findings)
            for det in (ast_diff.get("findings") or []):
                fp = str(det.get("file_path") or "").strip()
                ln = _parse_line_no(det.get("line_number"))
                rid = str(det.get("rule_id") or "DIFF-API-CONTRACT-CHANGE")
                det_findings.append(
                    StructuredFinding(
                        agent="Diff Agent",
                        category="change_risk",
                        severity=str(det.get("severity") or "Medium").title(),
                        title=str(det.get("title") or "API Contract Change"),
                        description=str(det.get("evidence") or ""),
                        file_path=fp,
                        line_number=ln,
                        end_line=None,
                        evidence=str(det.get("evidence") or ""),
                        recommendation="Verify downstream callers match the updated signature or interface.",
                        verification_status="Needs Verification",
                        tool_name=str(det.get("tool") or "diff-ast-engine"),
                        rule_id=rid,
                        confidence=0.92,
                    )
                )
            out = AgentExecutionOutput(
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Deterministic AST diff and change analysis completed ({len(det_findings)} finding(s)); LLM reasoning bypassed.",
                findings=det_findings,
                tool_results=compact_tr,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "diff_agent",
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
            logger.exception("Diff Agent fallback to deterministic AST change analysis: %s", exc)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            compact_tr = _compact_diff_telemetry(diff_ctx)
            compact_tr["error"] = str(exc)
            out = AgentExecutionOutput(
                agent_name="diff_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Diff change analysis completed via deterministic fallback ({len(findings)} finding(s)).",
                findings=findings,
                tool_results=compact_tr,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "diff_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": len(findings),
                    "summary": out.summary,
                    "tool_results": compact_tr,
                },
            )
            await ctx.send_message(out)
