from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import LLM_FALLBACK_EXCEPTIONS, MissingAPIKeyError, run_structured_agent
from app.cache.review_cache import ReviewCache, hash_config_dict
from app.intelligence.context_builder import build_agent_context
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    ReviewState,
    StructuredFinding,
)
from app.scanners.git_diff_tool import prioritized_diff_excerpt
from app.scanners.security_tools import run_security_scanners
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

SYSTEM_PROMPT = """You are the Lead Security Agent in Swarm, an advanced multi-agent security and code review system.
Your mission is to perform elite-level, pin-to-pin line-by-line security auditing to detect real-world security vulnerabilities, stealthy backdoors, data breach hazards, and exploitation vectors that automated linters miss.

CORE SECURITY AUDITING MANDATES:
1. BACKDOORS & MALICIOUS PATTERNS:
   - Identify obfuscated payload execution (e.g., base64, rot13, hex decoding inside eval/exec/Function).
   - Detect reverse shells, raw network socket connections, interactive shell spawning (pty.spawn, dup2).
   - Flag backdoor access controls (hidden admin headers like X-Admin, bypass tokens, hardcoded master passwords, backdoor query params).
   - Flag unsafe reflection or dynamic imports (getattr(__builtins__), importlib loading untrusted modules).

2. DATA BREACHES & CONFIDENTIALITY RISKS:
   - Detect sensitive credentials, passwords, bearer tokens, or PII logged to consoles, files, or external monitoring streams.
   - Detect internal exception/traceback leakage in API responses (e.g., detail=str(e) or detail=traceback.format_exc()).
   - Detect Broken Object Level Authorization (BOLA/IDOR): database queries retrieving user/tenant records without verifying ownership or session user ID.
   - Flag unauthenticated state-mutating endpoints and missing CSRF/auth guards.

3. ADVANCED INJECTION & SSRF VECTORS:
   - Dynamic SQL / NoSQL query injection (raw string concatenation, ORM raw text/order_by injection).
   - Command injection via subprocess(shell=True), os.system, or child_process.exec without argv arrays.
   - SSRF (Server-Side Request Forgery), specifically unvalidated URL fetching and access to Cloud Instance Metadata (169.254.169.254, metadata.google.internal).
   - Server-Side Template Injection (SSTI) in template engines (Jinja2, Mako, etc.) using dynamic string templates.
   - Zip Slip / path traversal during archive extraction (extractall without path containment validation).

4. AUTHENTICATION & CRYPTOGRAPHIC DEFECTS:
   - Weak or hardcoded JWT secrets, 'none' algorithm acceptance, missing expiration validation.
   - Timing attacks: string comparison (==) on secrets/tokens instead of constant-time comparison (hmac.compare_digest).
   - Non-cryptographic pseudo-random number generators (random.*, Math.random) for security-sensitive tokens, salts, or passwords.

CRITICAL ACCURACY & GROUNDING RULES:
- Inspect line-by-line: every finding MUST cite the EXACT file_path and line_number from the source code.
- Check implemented_guards: NEVER claim a validation or check is missing if the file or its helpers implement it.
- Assign precise severity (Critical, High, Medium, Low) and honest confidence (0.0-1.0).

Return strict JSON:
{
  "summary": "Deep, actionable security audit posture summary.",
  "findings": [
    {
      "severity": "Critical|High|Medium|Low",
      "title": "Clear, technically precise security vulnerability title",
      "description": "Technical root-cause explanation, attack vector, and potential impact (how an attacker can exploit this).",
      "file_path": "exact/path/from/repo.py",
      "line_number": 24,
      "evidence": "Exact vulnerable code line or expression from the file",
      "tool_name": "semgrep|bandit|gitleaks|osv-scanner|security-guard|security-taint|llm-security-review",
      "rule_id": "CWE or specific vulnerability identifier (e.g., BACKDOOR-EXEC, CWE-89, CWE-918)",
      "recommendation": "Concrete, production-grade remediation steps (parameterization, sanitization, defensive guards).",
      "confidence": 0.95
    }
  ]
}
Never invent file paths or line numbers. Ground all findings strictly in the provided code."""


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
        scanner_evidence: list[dict[str, Any]] = []
        findings: list[StructuredFinding] = []
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
                structure_index=state.structure_index,
            )
            sec_res["cache_stats"] = cache.stats.to_dict()
            scanner_evidence: list[dict[str, Any]] = []
            total_raw = 0
            for v in sec_res.values():
                if isinstance(v, dict) and "findings" in v:
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
                        f"Taint: {len(sec_res['taint_analysis']['findings'])}, "
                        f"Guards: {len(sec_res['deterministic_guards']['findings'])}"
                        + (", cache hit)" if sec_res.get("cache_hit") else ")")
                    ),
                },
            )

            threat_surfaces = (sec_res.get("taint_analysis") or {}).get("threat_surfaces") or []
            # Token-saving rule: if docs-only/skipped or configured key with zero raw hits and zero security threat surfaces on low risk, skip redundant deep LLM scan
            skip_llm_clean = bool(
                (agent_plan.get("skip_scanners") and cfg.api_key.strip())
                or (
                    cfg.api_key.strip()
                    and total_raw == 0
                    and not threat_surfaces
                    and state.review_plan.get("risk_tier") == "low"
                )
            )
            token_usage: dict[str, int] | None = None
            llm_degraded: dict[str, Any] | None = None
            stair_meta: dict[str, Any] = {"token_estimate": 0, "slices_count": 0}
            if skip_llm_clean:
                llm_out: dict[str, Any] = {
                    "summary": "Fast security scanners, taint analysis, and threat-surface checks completed cleanly with zero findings; deep LLM analysis skipped (low-risk token saver).",
                    "findings": [],
                    "llm_skipped_token_saver": True,
                }
            else:
                stair_ctx = build_agent_context(
                    role="security_agent",
                    workspace_dir=state.workspace_dir,
                    structure_index=state.structure_index,
                    changed_files=state.changed_files,
                    diff_text=state.diff_text,
                    evidence_items=scanner_evidence,
                    target_files=agent_plan.get("focus_files"),
                    token_budget=agent_plan.get("token_budget"),
                    expand_for_high_risk=(
                        not bool(agent_plan.get("token_budget"))
                        and state.review_plan.get("risk_tier") == "high"
                    ),
                )
                stair_meta = {
                    "token_estimate": stair_ctx["token_estimate"],
                    "token_budget": stair_ctx["token_budget"],
                    "slices_count": len(stair_ctx.get("selected_slices") or []),
                }
                sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                compact_sec_res: dict[str, Any] = {}
                for k, v in sec_res.items():
                    if not isinstance(v, dict):
                        continue
                    if v.get("status") in (
                        "skipped_by_plan",
                        "optional_unavailable",
                        "skipped_no_python_files",
                        "skipped_no_supported_files",
                    ):
                        continue
                    b_findings = sorted(
                        list(v.get("findings") or []),
                        key=lambda item: sev_rank.get(str(item.get("severity") or "Low").title(), 3),
                    )
                    compact_sec_res[k] = {
                        **v,
                        "total_hits": len(b_findings),
                        "findings": b_findings[:15],
                    }

                code_changed = [
                    c for c in state.changed_files
                    if not str(c.get("path") or "").lower().endswith((".md", ".mdx", ".rst", ".txt", ".lock"))
                ]
                diff_excerpt = prioritized_diff_excerpt(
                    code_changed or state.changed_files, state.diff_text, max_chars=12000
                )
                contract_block = format_agent_contract("security_agent", agent_plan)

                user_prompt = (
                    f"Repository: {state.repository_name}\n"
                    f"Plan Risk Tier: {state.review_plan.get('risk_tier', 'medium')} | Threat Surfaces: {threat_surfaces}\n\n"
                    f"{contract_block}\n\n"
                    "CRITICAL SECURITY AUDIT INSTRUCTION: Perform an exhaustive line-by-line security audit. "
                    "Analyze all changed lines and STAIR context for backdoors, remote code execution, injection flaws (SQL/Command/SSRF/SSTI), "
                    "data breaches, credential logging, and broken object-level authorization (IDOR/BOLA). "
                    "Provide concrete, actionable findings grounded with exact line numbers and exploit scenarios.\n\n"
                    f"Deterministic Scanner & Taint Results (total raw hits={total_raw}):\n"
                    f"{json.dumps(compact_sec_res, separators=(',', ':'))[:6000]}\n\n"
                    f"{stair_ctx['context_text']}\n\n"
                    f"Unified Diff Excerpt:\n```diff\n{diff_excerpt}\n```"
                )
                try:
                    llm_out = await run_structured_agent(
                        cfg,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        timeout_seconds=90.0,
                        max_tokens=1800,
                    )
                    token_usage = llm_out.pop("_token_usage", None)
                except (MissingAPIKeyError, ReviewCancelledError, asyncio.CancelledError):
                    raise
                except LLM_FALLBACK_EXCEPTIONS as llm_exc:
                    err_reason = str(llm_exc) or type(llm_exc).__name__
                    logger.warning("Security Agent LLM fallback: %s", err_reason)
                    llm_degraded = {"reason": err_reason, "fallback": "deterministic_security_scanners"}
                    llm_out = {
                        "summary": (
                            f"Deterministic security scanners & taint analysis completed ({total_raw} raw hit(s)); "
                            f"deep LLM exploitability review fell back cleanly ({err_reason[:100]})."
                        ),
                        "findings": [],
                    }

            findings: list[StructuredFinding] = []
            seen_sec: set[tuple[str, int | None, str]] = set()
            for item in llm_out.get("findings", []) or []:
                tool_name = str(item.get("tool_name") or "llm-security-review")
                fp = str(item.get("file_path") or "").strip()
                ln = _parse_line_no(item.get("line_number"))
                rid = str(item.get("rule_id") or "")
                if rid:
                    seen_sec.add((fp, ln, rid))
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
                        file_path=fp,
                        line_number=ln,
                        end_line=None,
                        evidence=str(item.get("evidence") or ""),
                        recommendation=str(item.get("recommendation") or ""),
                        verification_status="Needs Verification",
                        tool_name=tool_name,
                        rule_id=rid or None,
                        confidence=conf,
                    )
                )

            # Ensure deterministic scanner hits are never dropped before EvidenceGuard / ReviewerManager triage
            _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_evidence = sorted(
                scanner_evidence,
                key=lambda item: _sev_order.get(str(item.get("severity") or "Low").title(), 3),
            )
            for raw_item in sorted_evidence[:45]:
                fp = str(raw_item.get("file_path") or "").strip()
                ln = _parse_line_no(raw_item.get("line_number"))
                rid = str(raw_item.get("rule_id") or "")
                if rid and (fp, ln, rid) in seen_sec:
                    continue
                tname = str(raw_item.get("tool") or "semgrep")
                findings.append(
                    StructuredFinding(
                        agent="Security Agent",
                        category="security",
                        severity=str(raw_item.get("severity") or "Medium").title(),
                        title=str(raw_item.get("title") or "Deterministic Security Finding"),
                        description=str(raw_item.get("description") or raw_item.get("evidence") or ""),
                        file_path=fp,
                        line_number=ln,
                        end_line=_parse_line_no(raw_item.get("end_line")),
                        evidence=str(raw_item.get("evidence") or ""),
                        recommendation=str(raw_item.get("description") or "Remediate detected security issue."),
                        verification_status="Needs Verification",
                        tool_name=tname,
                        rule_id=rid or None,
                        confidence=0.92,
                    )
                )

            sec_res["llm_skipped_token_saver"] = skip_llm_clean
            sec_res["stair_context"] = stair_meta
            if token_usage:
                sec_res["token_usage"] = token_usage
            if llm_degraded:
                sec_res["llm_degraded"] = llm_degraded

            # Check if any security tool itself failed/unavailable (never treat skipped_by_plan as incomplete)
            incomplete_tools = [
                k
                for k, v in sec_res.items()
                if isinstance(v, dict) and v.get("status") in ("error", "incomplete", "tool_unavailable")
            ]
            status = "completed"
            err_msg = f"Optional scanner notes: {', '.join(incomplete_tools)}" if incomplete_tools else None
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
                error_message=err_msg,
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
                    "tool_results": sec_res,
                },
            )
            await ctx.send_message(out)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            sec_res["llm_degraded"] = {"reason": str(exc), "mode": "deterministic_scanners_fallback"}
            det_findings: list[StructuredFinding] = []
            for raw_item in scanner_evidence:
                det_findings.append(
                    StructuredFinding(
                        agent="Security Agent",
                        category="security",
                        severity=str(raw_item.get("severity") or "Medium").title(),
                        title=str(raw_item.get("title") or "Security Finding"),
                        description=str(raw_item.get("description") or raw_item.get("evidence") or ""),
                        file_path=str(raw_item.get("file_path") or "").strip(),
                        line_number=_parse_line_no(raw_item.get("line_number")),
                        end_line=_parse_line_no(raw_item.get("end_line")),
                        evidence=str(raw_item.get("evidence") or ""),
                        recommendation=str(raw_item.get("description") or "Remediate detected security issue."),
                        verification_status="Needs Verification",
                        tool_name=str(raw_item.get("tool") or "semgrep"),
                        rule_id=str(raw_item.get("rule_id") or "") or None,
                        confidence=0.92,
                    )
                )
            out = AgentExecutionOutput(
                agent_name="security_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Deterministic security scanners (Semgrep, Bandit, Gitleaks, OSV, Taint) completed ({len(det_findings)} finding(s)); LLM reasoning bypassed.",
                findings=det_findings,
                tool_results=sec_res,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "security_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": len(det_findings),
                    "summary": out.summary,
                    "tool_results": sec_res,
                },
            )
            await ctx.send_message(out)
        except Exception as exc:
            logger.exception("Security Agent fallback to deterministic scanners: %s", exc)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            sec_res["error"] = str(exc)
            det_findings = []
            for raw_item in scanner_evidence:
                det_findings.append(
                    StructuredFinding(
                        agent="Security Agent",
                        category="security",
                        severity=str(raw_item.get("severity") or "Medium").title(),
                        title=str(raw_item.get("title") or "Security Finding"),
                        description=str(raw_item.get("description") or ""),
                        file_path=str(raw_item.get("file_path") or "").strip(),
                        line_number=_parse_line_no(raw_item.get("line_number")),
                        end_line=None,
                        evidence=str(raw_item.get("evidence") or ""),
                        recommendation="Remediate security issue.",
                        verification_status="Needs Verification",
                        tool_name=str(raw_item.get("tool") or "semgrep"),
                        rule_id=str(raw_item.get("rule_id") or "") or None,
                        confidence=0.85,
                    )
                )
            out = AgentExecutionOutput(
                agent_name="security_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary=f"Security audit completed via deterministic scanners ({len(det_findings)} finding(s)).",
                findings=det_findings,
                tool_results=sec_res,
                error_message=None,
                duration_ms=duration_ms,
            )
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "security_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": len(det_findings),
                    "summary": out.summary,
                    "tool_results": sec_res,
                },
            )
            await ctx.send_message(out)
