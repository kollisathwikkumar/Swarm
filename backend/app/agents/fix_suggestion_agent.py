from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.agents.reviewer_manager import _evaluate_review_policy
from app.intelligence.context_builder import build_agent_context
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import (
    AgentExecutionOutput,
    PatchProposal,
    ReviewState,
)
from app.scanners.code_engines import (
    is_test_file_path,
    run_deterministic_code_guards,
    verify_code_syntax,
)
from app.scanners.security_taint import run_taint_and_threat_analysis
from app.scanners.tool_runner import (
    resolve_binary,
    resolve_workspace_binary,
    run_command_capture,
    sanitized_subprocess_env,
)
from app.services.git_workspace import resolve_within_dir, verify_patch_applicability
from app.skills.shared_contracts import format_agent_contract
from app.verification.evidence_guard import is_patch_eligible

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Fix-Suggestion Agent in Swarm.
You receive an EvidenceGuard-Verified defect, its root-cause & target source code, STAIR caller/import context, and Existing Test Contracts.
Rules:
1. Perform root-cause analysis and fix ONLY the identified defect with minimal AST-safe edits, reusing existing repository helpers/patterns and preserving indentation, exports, and existing public behavior.
2. MUST preserve every existing test expectation in `Existing Test Contracts` (e.g. exact thrown error regex substrings like /HTTPS/, test endpoints, return shapes).
3. Verify every regex literal, escape sequence, quote, type annotation, and bracket carefully so syntax & type checks pass cleanly.
4. Optionally provide a minimal regression test function/snippet (`regression_test_code`) that reproduces and verifies the fix when safe.
Return strict JSON:
{
  "title": "Short patch title describing the fix",
  "corrected_code": "THE EXACT complete corrected code matching the provided snippet/file scope (with NO placeholders or '...').",
  "explanation": "Root-cause explanation + why this minimal patch resolves the issue without breaking existing tests.",
  "regression_test_code": "Optional minimal unit test verifying this fix (empty string if unnecessary)."
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
    workspace_dir: Path,
    findings: list[dict[str, Any]],
    max_patches: int = 5,
    *,
    allow_unverified: bool = False,
) -> list[tuple[int, dict[str, Any]]]:
    """Select top Verified, evidence-backed source-file defects strictly gated by EvidenceGuard."""
    sev_weight = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranked: list[tuple[tuple[int, int, int, int], int, dict[str, Any]]] = []

    for idx, f in enumerate(findings):
        fp = str(f.get("file_path") or "").strip()
        if not fp:
            continue
        full = resolve_within_dir(workspace_dir, fp)
        if full is None or not full.exists() or not full.is_file() or full.stat().st_size > 250_000:
            continue
        if not is_patch_eligible(f, allow_unverified=allow_unverified):
            continue
        ver = str(f.get("verification_status") or "Needs Verification")
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
        tp = resolve_within_dir(state.workspace_dir, test_rel)
        if tp is None or not tp.exists() or not tp.is_file() or tp.stat().st_size > 120_000:
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


def _related_tests_for_file(state: ReviewState, rel_path: str) -> list[str]:
    test_res = (state.agent_results.get("test_coverage_agent") or {}).get("tool_results") or {}
    tmap = (test_res.get("test_import_map") or {}).get("source_file_test_map") or {}
    info = tmap.get(rel_path) or {}
    direct_ind = list(info.get("direct_tests") or []) + list(info.get("indirect_importing_tests") or [])
    stair_links = ((state.structure_index.get("graphs") or {}).get("test_links") or {}).get(rel_path) or []
    return list(dict.fromkeys(direct_ind + list(stair_links)))


def _check_patch_conflict(
    workspace_dir: Path,
    finding: dict[str, Any],
    evidence_store: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Detect stale source files modified since deterministic EvidenceStore capture."""
    rel_path = str(finding.get("file_path") or "").strip()
    target = resolve_within_dir(workspace_dir, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return False, f"Target file `{rel_path}` missing from workspace."
    cur_hash = hashlib.sha256(target.read_bytes()).hexdigest()[:16]
    ev_ids = set(finding.get("evidence_ids") or [])
    for rec in evidence_store:
        if rec.get("evidence_id") in ev_ids and rec.get("source_hash") and rec["source_hash"] != cur_hash:
            return False, (
                f"Patch conflict detected: `{rel_path}` hash changed ({cur_hash}) since "
                f"{rec['evidence_id']} capture ({rec['source_hash']})."
            )
    return True, "No source conflict"


def _copy_workspace_for_validation(src_ws: Path, dst_ws: Path) -> None:
    skip_names = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "_cache", ".next", "dist"}
    for root_str, dirs, files in os.walk(src_ws):
        rel_root = Path(root_str).relative_to(src_ws)
        if "node_modules" in dirs:
            dirs.remove("node_modules")
            nm_dst = dst_ws / rel_root / "node_modules"
            nm_dst.parent.mkdir(parents=True, exist_ok=True)
            if not nm_dst.exists():
                nm_dst.symlink_to(Path(root_str) / "node_modules", target_is_directory=True)
        dirs[:] = [d for d in dirs if d not in skip_names]
        (dst_ws / rel_root).mkdir(parents=True, exist_ok=True)
        for fname in files:
            src_f = Path(root_str) / fname
            if src_f.is_file() and src_f.stat().st_size <= 2_000_000:
                shutil.copy2(src_f, dst_ws / rel_root / fname)


async def _validate_patch_bundle(
    workspace_dir: Path,
    rel_path: str,
    proposed_code: str,
    unified_diff: str,
    *,
    related_tests: list[str] | None = None,
    regression_test_code: str = "",
) -> tuple[bool, bool, bool, str]:
    apply_ok, apply_msg = await verify_patch_applicability(workspace_dir, rel_path, unified_diff)
    syntax_ok, syntax_msg = await verify_code_syntax(rel_path, proposed_code, workspace_dir)

    # Security + Taint Revalidation: ensure patch does not introduce any new Critical/High security or taint alerts
    guard_ok = True
    guard_msg = "Security & taint rescan passed"
    before_guards = await run_deterministic_code_guards(workspace_dir, [rel_path])
    before_taint = run_taint_and_threat_analysis(workspace_dir, [rel_path])
    before_rules = {
        (f.get("rule_id"), f.get("severity"))
        for f in (before_guards.get("findings") or []) + (before_taint.get("findings") or [])
        if f.get("severity") in ("Critical", "High")
    }

    type_ok = True
    type_msg = "Type check: optional skipped"
    test_ok = True
    test_msg = "Tests: none impacted"

    with tempfile.TemporaryDirectory(prefix="swarm_patch_val_") as tmp_dir:
        tmp_ws = Path(tmp_dir)
        _copy_workspace_for_validation(workspace_dir, tmp_ws)
        tmp_file = resolve_within_dir(tmp_ws, rel_path)
        if tmp_file is not None:
            tmp_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file.write_text(proposed_code, encoding="utf-8")

            after_guards = await run_deterministic_code_guards(tmp_ws, [rel_path])
            after_taint = run_taint_and_threat_analysis(tmp_ws, [rel_path])
            new_high_risk = [
                f
                for f in (after_guards.get("findings") or []) + (after_taint.get("findings") or [])
                if f.get("severity") in ("Critical", "High")
                and (f.get("rule_id"), f.get("severity")) not in before_rules
            ]
            if new_high_risk:
                guard_ok = False
                guard_msg = f"Introduced {len(new_high_risk)} new security/taint issue(s): {new_high_risk[0].get('rule_id')}"

            # Optional type checker (mypy for Python or tsc --noEmit for TS repos with tsconfig.json)
            if rel_path.endswith(".py"):
                mypy_bin = resolve_workspace_binary(workspace_dir, "mypy")
                if mypy_bin:
                    tc = await run_command_capture([mypy_bin, "--ignore-missing-imports", rel_path], cwd=tmp_ws, timeout=30)
                    if tc["returncode"] != 0:
                        type_ok = False
                        type_msg = f"Type check failed (mypy): {(tc['stdout'] or tc['stderr'])[:160]}"
                    else:
                        type_msg = "Type check passed (mypy)"
            elif rel_path.endswith((".ts", ".tsx")) and (tmp_ws / "tsconfig.json").exists():
                tsc_bin = resolve_workspace_binary(workspace_dir, "tsc")
                if tsc_bin:
                    tc = await run_command_capture([tsc_bin, "--noEmit"], cwd=tmp_ws, timeout=45)
                    if tc["returncode"] != 0:
                        type_ok = False
                        type_msg = f"Type check failed (tsc): {(tc['stdout'] or tc['stderr'])[:160]}"
                    else:
                        type_msg = "Type check passed (tsc)"

            # Targeted test execution on the isolated patched copy (never modifies workspace_dir!)
            py_related = [t for t in (related_tests or []) if t.endswith(".py") and (tmp_ws / t).exists()]
            repro_rel: str | None = None
            if regression_test_code.strip() and rel_path.endswith(".py"):
                ok_reg, _ = await verify_code_syntax("test_swarm_repro.py", regression_test_code, tmp_ws)
                if ok_reg:
                    repro_path = tmp_ws / "test_swarm_repro.py"
                    repro_path.write_text(regression_test_code, encoding="utf-8")
                    repro_rel = "test_swarm_repro.py"

            pytest_targets = list(py_related)
            if repro_rel:
                pytest_targets.append(repro_rel)
            if pytest_targets:
                pytest_bin = resolve_binary("pytest")
                if pytest_bin:
                    env = sanitized_subprocess_env()
                    env["PYTHONPATH"] = str(tmp_ws)
                    pt = await run_command_capture(
                        [pytest_bin, "-q", "--tb=short", *pytest_targets],
                        cwd=tmp_ws,
                        timeout=45,
                        env=env,
                    )
                    if pt["returncode"] != 0:
                        test_ok = False
                        test_msg = f"Targeted tests failed: {(pt['stdout'] or pt['stderr'])[-180:]}"
                    else:
                        test_msg = f"Targeted tests passed ({len(pytest_targets)} file(s))"

    combined_ok = apply_ok and syntax_ok and guard_ok and type_ok and test_ok
    validation_output = (
        f"git apply --check: {apply_msg} | Syntax check: {syntax_msg} | "
        f"{guard_msg} | {type_msg} | {test_msg}"
    )
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

        allow_unverified = bool((state.policy or {}).get("allow_unverified_patches", False))
        targets = _select_target_findings(
            state.workspace_dir,
            state.findings,
            max_patches=5,
            allow_unverified=allow_unverified,
        )
        if not targets:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            state.agent_results["fix_suggestion_agent"] = AgentExecutionOutput(
                agent_name="fix_suggestion_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary="No EvidenceGuard-Verified actionable source-file findings required a generated patch.",
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
                conflict_ok, conflict_msg = _check_patch_conflict(
                    state.workspace_dir, finding, state.evidence_store
                )
                if not conflict_ok:
                    logger.info("Skipping stale patch target: %s", conflict_msg)
                    continue
                target_file = resolve_within_dir(state.workspace_dir, rel_path)
                if target_file is None or not target_file.exists():
                    continue
                related_tests = _related_tests_for_file(state, rel_path)
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
                fix_plan = (state.review_plan.get("agent_plans") or {}).get("fix_suggestion_agent") or {}
                stair_ctx = build_agent_context(
                    role="fix_suggestion_agent",
                    workspace_dir=state.workspace_dir,
                    structure_index=state.structure_index,
                    changed_files=state.changed_files,
                    diff_text=state.diff_text,
                    findings=[finding],
                    target_files=[rel_path],
                    token_budget=fix_plan.get("token_budget"),
                )
                contract_block = format_agent_contract("fix_suggestion_agent", fix_plan)

                user_prompt = (
                    f"{contract_block}\n\n"
                    f"Target Verified Finding:\n{json.dumps(finding, indent=2)}\n\n"
                    f"File Path: {rel_path}\n"
                    f"Scope: {scope_label}\n"
                    f"{contract_section}\n"
                    f"STAIR Dependency & Caller Context:\n{stair_ctx['context_text'][:6000]}\n\n"
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
                regression_test_code = str(llm_out.get("regression_test_code") or "").strip()
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
                    state.workspace_dir,
                    rel_path,
                    proposed_code,
                    unified_diff,
                    related_tests=related_tests,
                    regression_test_code=regression_test_code,
                )

                # Automatic 1-shot Self-Repair if git apply, syntax, type, security, or targeted tests failed
                if not applicable:
                    repair_prompt = (
                        f"Your previous fix for `{rel_path}` FAILED deterministic verification:\n"
                        f"ERROR: {validation_output}\n\n"
                        f"Previous corrected_code:\n```\n{corrected_snippet}\n```\n\n"
                        f"Original {scope_label}:\n```\n{target_snippet}\n```\n"
                        "Return the repaired `corrected_code` passing syntax, security, type, and test checks cleanly."
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
                                state.workspace_dir,
                                rel_path,
                                cand_code,
                                cand_diff,
                                related_tests=related_tests,
                                regression_test_code=str(repaired.get("regression_test_code") or regression_test_code),
                            )
                            proposed_code = cand_code
                            unified_diff = cand_diff
                            applicable = cand_ok
                            validation_output = cand_val
                            if repaired.get("explanation"):
                                explanation = str(repaired["explanation"])
                if regression_test_code:
                    explanation = f"{explanation}\n\nSuggested regression test:\n```\n{regression_test_code[:1200]}\n```"

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
            logger.exception("Fix-Suggestion Agent failed")
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
        rec, reason, evaluated_findings = _evaluate_review_policy(
            state, state.findings, list(state.agent_results.values())
        )
        state.findings = evaluated_findings
        state.recommendation = rec
        state.recommendation_reason = reason
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
                "recommendation": rec,
                "summary": summary,
            },
        )
        await ctx.yield_output(state)
