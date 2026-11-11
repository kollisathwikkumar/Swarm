from __future__ import annotations

import asyncio
import difflib
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    PatchProposal,
    ReviewState,
)
from app.scanners.code_engines import is_test_file_path, verify_code_syntax
from app.services.git_workspace import resolve_within_dir, verify_patch_applicability

SYSTEM_PROMPT = """You are the Fix-Suggestion Agent in ReviewBoard.
You receive a high-priority actionable code review finding, the exact target source code, and any Existing Test Contracts covering that file.
Rules:
1. Fix ONLY the identified defect cleanly with minimal collateral changes, preserving indentation, exports, and existing public behavior.
2. MUST preserve every existing test expectation in `Existing Test Contracts` (e.g. exact thrown error regex substrings like /HTTPS/, test endpoints, return shapes). If adding SSRF/private-IP blocking to a configurable endpoint validator, block loopback/private/link-local IPs cleanly WITHOUT hardcoding a closed hostname allowlist that rejects arbitrary test or user-configured HTTPS endpoints unless explicitly requested.
3. Verify every regex literal, escape sequence, quote, and bracket carefully so the file compiles cleanly with zero syntax errors.
Return strict JSON:
{
  "title": "Short patch title describing the fix",
  "corrected_code": "THE EXACT complete corrected code matching the provided snippet/file scope (with NO placeholders or '...').",
  "explanation": "Clear explanation of why this change resolves the issue without breaking existing tests."
}"""


def _compute_unified_diff(file_path: str, original: str, proposed: str) -> str:
    orig_lines = original.splitlines(keepends=True)
    prop_lines = proposed.splitlines(keepends=True)
    if orig_lines and not orig_lines[-1].endswith("\n"):
        orig_lines[-1] += "\n"
    if prop_lines and not prop_lines[-1].endswith("\n"):
        prop_lines[-1] += "\n"
    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            prop_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="\n",
        )
    )
    return "".join(diff_lines)


def _assemble_corrected_file(
    lines: list[str], window_start: int, window_end: int, total_lines: int, snippet: str
) -> str:
    if window_start == 1 and window_end == total_lines:
        return snippet
    if not snippet.endswith("\n"):
        snippet += "\n"
    return "".join(lines[: window_start - 1]) + snippet + "".join(lines[window_end:])


def _select_target_findings(
    workspace_dir: Path, findings: list[dict[str, Any]], max_patches: int = 2
) -> list[tuple[int, dict[str, Any]]]:
    """Select top Verified/actionable source-file defects (skipping Unverified guesses and test-fixture alerts)."""
    sev_weight = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranked: list[tuple[tuple[int, int, int, int], int, dict[str, Any]]] = []

    for idx, f in enumerate(findings):
        fp = str(f.get("file_path") or "").strip()
        if not fp:
            continue
        full = resolve_within_dir(workspace_dir, fp)
        if full is None or not full.exists() or not full.is_file() or full.stat().st_size > 250_000:
            continue
        ver = str(f.get("verification_status") or "Needs Verification")
        if ver == "Unverified":
            continue
        sev = str(f.get("severity") or "Medium")
        if sev not in ("Critical", "High", "Medium"):
            continue
        if str(f.get("tool_name") or "") == "test-mapper":
            continue
        if is_test_file_path(fp) and str(f.get("tool_name") or "") == "gitleaks":
            continue

        score = (
            1 if is_test_file_path(fp) else 0,
            0 if ver == "Verified" else 1,
            sev_weight.get(sev, 2),
            idx,
        )
        ranked.append((score, idx, f))

    ranked.sort(key=lambda item: item[0])
    candidates: list[tuple[int, dict[str, Any]]] = []
    seen_files: set[str] = set()
    for _, idx, f in ranked:
        fp = str(f.get("file_path") or "").strip()
        if fp in seen_files:
            continue
        candidates.append((idx, f))
        seen_files.add(fp)
        if len(candidates) >= max_patches:
            break
    return candidates


def _extract_test_contract_context(state: ReviewState, rel_path: str) -> str:
    test_res = (state.agent_results.get("test_coverage_agent") or {}).get("tool_results") or {}
    tmap = (test_res.get("test_import_map") or {}).get("source_file_test_map") or {}
    info = tmap.get(rel_path) or {}
    related_tests = list(info.get("direct_tests") or []) + list(info.get("indirect_importing_tests") or [])
    if not related_tests:
        return ""

    excerpts: list[str] = []
    used = 0
    for test_rel in related_tests[:2]:
        tp = (state.workspace_dir / test_rel).resolve()
        if not tp.exists() or not tp.is_file() or tp.stat().st_size > 120_000:
            continue
        lines = tp.read_text(encoding="utf-8", errors="replace").splitlines()
        relevant = [
            f"{i:03d}: {ln}"
            for i, ln in enumerate(lines, start=1)
            if any(k in ln for k in ("expect(", "toThrow", "rejects", "assert", "it(", "test(", "endpoint", "http://", "https://"))
        ]
        if relevant:
            chunk = f"--- Related Test Contract ({test_rel}) ---\n" + "\n".join(relevant[:65])
            if used + len(chunk) > 5000:
                break
            excerpts.append(chunk)
            used += len(chunk)
    return "\n\n".join(excerpts)


async def _validate_patch_bundle(
    workspace_dir: Path, rel_path: str, proposed_code: str, unified_diff: str
) -> tuple[bool, bool, bool, str]:
    apply_ok, apply_msg = await verify_patch_applicability(workspace_dir, rel_path, unified_diff)
    syntax_ok, syntax_msg = await verify_code_syntax(rel_path, proposed_code, workspace_dir)
    combined_ok = apply_ok and syntax_ok
    validation_output = f"git apply --check: {apply_msg} | Syntax check: {syntax_msg}"
    return combined_ok, apply_ok, syntax_ok, validation_output


class FixSuggestionAgentExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="fix_suggestion_agent")
        self._emit = emit_event

    @handler
    async def handle(
        self, state: ReviewState, ctx: WorkflowContext[ReviewState, ReviewState]
    ) -> None:
        t0 = time.perf_counter()
        cfg = state.agent_configs["fix_suggestion_agent"]
        await self._emit(
            state.review_id,
            "agent_started",
            {
                "agent_name": "fix_suggestion_agent",
                "agent_label": cfg.label,
                "model": cfg.model,
                "phase": "fix_suggestion",
            },
        )

        targets = _select_target_findings(state.workspace_dir, state.findings, max_patches=2)
        if not targets:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            state.agent_results["fix_suggestion_agent"] = AgentExecutionOutput(
                agent_name="fix_suggestion_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary="No actionable source-file findings required a generated patch.",
                duration_ms=duration_ms,
            ).to_dict()
            state.review_status = "completed"
            await self._emit(
                state.review_id,
                "agent_completed",
                {
                    "agent_name": "fix_suggestion_agent",
                    "agent_label": cfg.label,
                    "status": "completed",
                    "model": cfg.model,
                    "duration_ms": duration_ms,
                    "findings_count": 0,
                    "summary": "No patch required.",
                },
            )
            await ctx.yield_output(state)
            return

        proposals: list[dict[str, Any]] = []
        status = "completed"
        err_msg: str | None = None

        try:
            for finding_idx, finding in targets:
                if is_review_cancelled(state.review_id):
                    raise ReviewCancelledError("Review stopped by user.")
                rel_path = finding["file_path"]
                target_file = resolve_within_dir(state.workspace_dir, rel_path)
                if target_file is None or not target_file.exists():
                    continue
                original_code = target_file.read_text(
                    encoding="utf-8", errors="replace"
                )
                lines = original_code.splitlines(keepends=True)
                total_lines = len(lines)

                if total_lines <= 500 and len(original_code) <= 25000:
                    window_start = 1
                    window_end = total_lines
                    target_snippet = original_code
                    scope_label = f"Full File ({total_lines} lines)"
                else:
                    center = int(finding.get("line_number") or 1)
                    window_start = max(1, center - 70)
                    window_end = min(total_lines, center + 70)
                    target_snippet = "".join(lines[window_start - 1 : window_end])
                    scope_label = f"Lines {window_start}-{window_end} of {total_lines}"

                contract_notes = _extract_test_contract_context(state, rel_path)
                contract_section = (
                    f"\nExisting Test Contracts (DO NOT break these assertions):\n{contract_notes}\n"
                    if contract_notes
                    else ""
                )

                user_prompt = (
                    f"Target Finding:\n{json.dumps(finding, indent=2)}\n\n"
                    f"File Path: {rel_path}\n"
                    f"Scope: {scope_label}\n"
                    f"{contract_section}\n"
                    f"Source Code to Fix (return the exact corrected replacement for this {scope_label}):\n"
                    f"```\n{target_snippet}\n```"
                )
                llm_out = await run_structured_agent(
                    cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=85.0
                )
                corrected_snippet = str(
                    llm_out.get("corrected_code")
                    or llm_out.get("corrected_file_content")
                    or ""
                )
                explanation = str(llm_out.get("explanation") or "")
                title = str(llm_out.get("title") or f"Fix: {finding.get('title')}")

                if not corrected_snippet.strip():
                    continue

                proposed_code = _assemble_corrected_file(
                    lines, window_start, window_end, total_lines, corrected_snippet
                )
                if proposed_code == original_code:
                    continue

                unified_diff = _compute_unified_diff(rel_path, original_code, proposed_code)
                applicable, _, _, validation_output = await _validate_patch_bundle(
                    state.workspace_dir, rel_path, proposed_code, unified_diff
                )

                # Automatic 1-shot Self-Repair if git apply or language syntax parser failed
                if not applicable:
                    repair_prompt = (
                        f"Your previous fix for `{rel_path}` FAILED deterministic verification:\n"
                        f"ERROR: {validation_output}\n\n"
                        f"Previous corrected_code:\n```\n{corrected_snippet}\n```\n\n"
                        f"Original {scope_label}:\n```\n{target_snippet}\n```\n"
                        "Return the repaired `corrected_code` with ZERO syntax errors, preserving regexes and surrounding code."
                    )
                    repaired = await run_structured_agent(
                        cfg, system_prompt=SYSTEM_PROMPT, user_prompt=repair_prompt, timeout_seconds=70.0
                    )
                    repaired_snippet = str(
                        repaired.get("corrected_code") or repaired.get("corrected_file_content") or ""
                    )
                    if repaired_snippet.strip():
                        cand_code = _assemble_corrected_file(
                            lines, window_start, window_end, total_lines, repaired_snippet
                        )
                        if cand_code != original_code:
                            cand_diff = _compute_unified_diff(rel_path, original_code, cand_code)
                            cand_ok, _, _, cand_val = await _validate_patch_bundle(
                                state.workspace_dir, rel_path, cand_code, cand_diff
                            )
                            proposed_code = cand_code
                            unified_diff = cand_diff
                            applicable = cand_ok
                            validation_output = cand_val
                            if repaired.get("explanation"):
                                explanation = str(repaired["explanation"])

                proposals.append(
                    PatchProposal(
                        finding_index=finding_idx,
                        file_path=rel_path,
                        title=title,
                        original_code=original_code,
                        proposed_code=proposed_code,
                        unified_diff=unified_diff,
                        explanation=explanation,
                        applicability_verified=applicable,
                        validation_output=validation_output,
                    ).to_dict()
                )
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            status = "incomplete"
            err_msg = str(exc)
        except Exception as exc:
            status = "failed"
            err_msg = str(exc)

        state.patch_proposals = proposals
        duration_ms = int((time.perf_counter() - t0) * 1000)
        verified_count = len([p for p in proposals if p.get("applicability_verified")])
        summary = (
            f"Generated {len(proposals)} fix proposal(s) ({verified_count} syntax + git-apply verified) awaiting developer approval."
            if proposals
            else (err_msg or "Unable to generate an applicable patch.")
        )
        state.agent_results["fix_suggestion_agent"] = AgentExecutionOutput(
            agent_name="fix_suggestion_agent",
            agent_label=cfg.label,
            model_used=cfg.model,
            status=status,
            summary=summary,
            tool_results={"patch_count": len(proposals), "verified_patches": verified_count},
            error_message=err_msg,
            duration_ms=duration_ms,
        ).to_dict()
        state.review_status = "completed"

        await self._emit(
            state.review_id,
            "fix_suggestion_completed",
            {
                "agent_name": "fix_suggestion_agent",
                "agent_label": cfg.label,
                "status": status,
                "model": cfg.model,
                "duration_ms": duration_ms,
                "patches_count": len(proposals),
                "summary": summary,
            },
        )
        await ctx.yield_output(state)
