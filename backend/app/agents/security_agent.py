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
from app.scanners.security_tools import run_security_scanners
from app.skills.shared_contracts import format_agent_contract

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Security Agent in Swarm, an automated multi-agent code review system.
You receive deterministic scan findings from Semgrep, Bandit, Gitleaks, OSV-Scanner, and Deterministic Security Guards along with STAIR structural context slices and caller/guard relationships.
Your job:
1. Interpret deterministic scanner hits and verify whether they represent real security vulnerabilities (if Gitleaks marks a hit with `is_test_fixture: true` in a unit test file with fake fixture values, keep it Low informational or note it is a benign test fixture rather than calling it a leaked production key).
2. Inspect the retrieved symbols, callers, and guards for semantic security issues (SQL injection, auth bypass, incomplete redaction regexes, SSRF/unvalidated destinations, path traversal, insecure crypto, XSS, command injection).
3. Respect `implemented_guards` in the STAIR index: NEVER claim URL checks, citation checks, or sanitization is absent if the module or callee implements it!
4. Assign accurate severity (Critical, High, Medium, Low) and honest `confidence` (0.0–1.0). Never self-certify findings as Verified (EvidenceGuard verifies provenance independently).
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
      "confidence": 0.9
    }
  ]
}
Never invent file paths, lines, or fake tool attributions. If no vulnerabilities exist, return an empty findings array."""


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
            agent_plan = (state.review_plan.get("agent_plans") or {}).get("security_agent") or {}
            cache = ReviewCache(state.cache_dir or (state.workspace_dir.parent / "_cache"))
            commit_ctx = f"{state.base_commit}..{state.target_commit}"
            sec_res = await run_security_scanners(
                state.workspace_dir,
                changed_paths,
                cache=cache,
                commit_context=commit_ctx,
                config_hash=hash_config_dict({"policy": state.policy, "security_plan": agent_plan}),
                plan=agent_plan,
            )
            sec_res["cache_stats"] = cache.stats.to_dict()
            scanner_evidence: list[dict[str, Any]] = []
            total_raw = 0
            for v in sec_res.values():
                if isinstance(v, dict):
                    f_list = v.get("findings", [])
                    total_raw += len(f_list)
                    scanner_evidence.extend(f_list)

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
                        f"Guards: {len(sec_res['deterministic_guards']['findings'])}"
                        + (", cache hit)" if sec_res.get("cache_hit") else ")")
                    ),
                },
            )

            stair_ctx = build_agent_context(
                role="security_agent",
                workspace_dir=state.workspace_dir,
                structure_index=state.structure_index,
                changed_files=state.changed_files,
                diff_text=state.diff_text,
                evidence_items=scanner_evidence,
                target_files=agent_plan.get("focus_files"),
                token_budget=agent_plan.get("token_budget"),
                expand_for_high_risk=state.review_plan.get("risk_tier") == "high",
            )
            contract_block = format_agent_contract("security_agent", agent_plan)

            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')}\n\n"
                f"{contract_block}\n\n"
                f"Deterministic Scanner Results (total raw hits={total_raw}):\n"
                f"{json.dumps(sec_res, indent=2)[:12000]}\n\n"
                f"{stair_ctx['context_text']}\n\n"
                f"Unified Diff Excerpt:\n```diff\n{(state.diff_text or '')[:8000]}\n```"
            )
            llm_out = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=75.0
            )

            findings: list[StructuredFinding] = []
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-security-review")
                raw_conf = item.get("confidence", 0.75 if tool_name != "llm-security-review" else 0.5)
                try:
                    conf = max(0.0, min(1.0, float(raw_conf)))
                except (TypeError, ValueError):
                    conf = 0.5
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
                        verification_status="Needs Verification",
                        tool_name=tool_name,
                        rule_id=item.get("rule_id"),
                        confidence=conf,
                    )
                )

            # Check if any security tool itself failed/unavailable (never treat skipped_by_plan as incomplete)
            incomplete_tools = [
                k
                for k, v in sec_res.items()
                if isinstance(v, dict) and v.get("status") in ("error", "incomplete", "tool_unavailable")
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
