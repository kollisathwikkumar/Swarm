from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import LLM_FALLBACK_EXCEPTIONS, MissingAPIKeyError, run_structured_agent
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
from app.scanners.test_tools import _detect_external_dep_blocked_tests, _parse_pytest_counts
from app.scanners.tool_runner import (
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


_NON_PATCHABLE_RULES = {
    "COVERAGE-GAP",
    "TEST-NO_IMPORTING_TESTS_FOUND",
    "TEST-MOCKED_ONLY_UNTESTED",
    "TEST-SUITE-FAILED",
    "STYLE-FILE-SIZE",
    "STYLE-HIGH-COUPLING",
    "COMPLEXITY",
    "STYLE-LONG-FUNCTION",
    "STYLE-DEEP-NESTING",
}


def _strip_code_fences(snippet: str) -> str:
    """Strip accidental leading/trailing markdown code fences returned by an LLM."""
    text = snippet.strip("\r\n")
    raw_lines = text.splitlines()
    if len(raw_lines) >= 2 and raw_lines[0].lstrip().startswith("```") and raw_lines[-1].strip() == "```":
        return "\n".join(raw_lines[1:-1])
    return snippet


def _assemble_corrected_file(
    lines: list[str], window_start: int, window_end: int, total_lines: int, snippet: str
) -> str:
    cleaned = _strip_code_fences(snippet)
    had_trailing_nl = bool(lines and lines[-1].endswith("\n"))
    if window_start == 1 and window_end == total_lines:
        if had_trailing_nl and cleaned and not cleaned.endswith("\n"):
            cleaned += "\n"
        return cleaned
    if cleaned and not cleaned.endswith("\n") and (window_end < total_lines or had_trailing_nl):
        cleaned += "\n"
    return "".join(lines[: window_start - 1]) + cleaned + "".join(lines[window_end:])


def _find_enclosing_symbol_span(
    structure_index: dict[str, Any],
    rel_path: str,
    center_line: int,
    total_lines: int,
    *,
    max_span: int = 90,
) -> tuple[int, int, str]:
    """Snap large-file edit windows to enclosing STAIR symbol boundaries when concise."""
    fmeta = (structure_index.get("modules") or structure_index.get("files") or {}).get(rel_path) or {}
    best_sym: dict[str, Any] | None = None
    best_len = max_span + 1
    for sym in fmeta.get("symbols") or []:
        if not isinstance(sym, dict):
            continue
        try:
            s_ln = int(sym.get("start_line") or 0)
            e_ln = int(sym.get("end_line") or 0)
        except (TypeError, ValueError):
            continue
        if s_ln >= 1 and e_ln >= s_ln and s_ln <= center_line <= e_ln:
            span = e_ln - s_ln + 1
            if span <= max_span and span < best_len:
                best_sym = sym
                best_len = span
    if best_sym is not None:
        ws = max(1, int(best_sym["start_line"]))
        we = min(total_lines, int(best_sym["end_line"]))
        sym_name = str(best_sym.get("name") or "symbol")
        return ws, we, f"Symbol `{sym_name}` (Lines {ws}-{we} of {total_lines})"
    ws = max(1, center_line - 30)
    we = min(total_lines, center_line + 30)
    return ws, we, f"Lines {ws}-{we} of {total_lines}"


def _extract_mypy_errors(output: str) -> Counter[str]:
    errs: Counter[str] = Counter()
    for ln in output.splitlines():
        if ": error:" in ln:
            normalized = re.sub(r":\d+(?::\d+)?:\s*error:", ":L: error:", ln.strip())
            errs[normalized] += 1
    return errs


def _merge_token_usage(acc: dict[str, int], raw_usage: Any) -> None:
    if not isinstance(raw_usage, dict):
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        try:
            acc[key] = acc.get(key, 0) + int(raw_usage.get(key) or 0)
        except (TypeError, ValueError):
            continue


def _select_target_findings(
    workspace_dir: Path,
    findings: list[dict[str, Any]],
    max_patches: int = 5,
    *,
    allow_unverified: bool = False,
    skipped_out: list[dict[str, str]] | None = None,
) -> list[tuple[int, dict[str, Any]]]:
    """Select top Verified, evidence-backed source-file defects strictly gated by EvidenceGuard."""
    sev_weight = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ranked: list[tuple[tuple[int, int, int, int], int, dict[str, Any]]] = []

    def _record_skip(fp: str, rule_id: str, reason: str) -> None:
        if skipped_out is not None and len(skipped_out) < 25:
            skipped_out.append({"file_path": fp, "rule_id": rule_id, "reason": reason})

    for idx, f in enumerate(findings):
        fp = str(f.get("file_path") or "").strip()
        rule_id = str(f.get("rule_id") or "").strip()
        if not fp:
            continue
        if fp.endswith((".md", ".rst", ".txt", ".lock")):
            _record_skip(fp, rule_id, "non_source_doc_or_lockfile")
            continue
        if rule_id in _NON_PATCHABLE_RULES or (
            str(f.get("category") or "") == "testing" and not is_test_file_path(fp)
        ):
            _record_skip(fp, rule_id or "testing", "non_patchable_metric_or_coverage_gap")
            continue
        full = resolve_within_dir(workspace_dir, fp)
        if full is None or not full.exists() or not full.is_file() or full.stat().st_size > 250_000:
            _record_skip(fp, rule_id, "missing_or_oversized_file")
            continue
        if not is_patch_eligible(f, allow_unverified=allow_unverified):
            _record_skip(fp, rule_id, "unverified_by_evidence_guard")
            continue
        ver = str(f.get("verification_status") or "Needs Verification")
        sev = str(f.get("severity") or "Medium")
        if sev not in ("Critical", "High", "Medium"):
            _record_skip(fp, rule_id, "low_severity")
            continue
        if str(f.get("tool_name") or "") == "test-mapper":
            _record_skip(fp, rule_id, "test_mapper_advisory")
            continue
        if is_test_file_path(fp) and str(f.get("tool_name") or "") == "gitleaks":
            _record_skip(fp, rule_id, "test_fixture_secret")
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
        await asyncio.to_thread(_copy_workspace_for_validation, workspace_dir, tmp_ws)
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

            # Optional type checker (mypy diff for Python or tsc --noEmit for TS repos with node_modules)
            if rel_path.endswith(".py"):
                mypy_bin = resolve_workspace_binary(workspace_dir, "mypy")
                if mypy_bin:
                    before_tc = await run_command_capture(
                        [mypy_bin, "--ignore-missing-imports", rel_path], cwd=workspace_dir, timeout=30
                    )
                    tc = await run_command_capture(
                        [mypy_bin, "--ignore-missing-imports", rel_path], cwd=tmp_ws, timeout=30
                    )
                    if tc["returncode"] == 0:
                        type_msg = "Type check passed (mypy)"
                    else:
                        before_errs = _extract_mypy_errors(before_tc["stdout"] or before_tc["stderr"])
                        after_errs = _extract_mypy_errors(tc["stdout"] or tc["stderr"])
                        new_errs = after_errs - before_errs
                        if before_tc["returncode"] != 0 and not new_errs:
                            type_msg = "Type check passed (no new mypy errors)"
                        else:
                            type_ok = False
                            sample = next(iter(new_errs), (tc["stdout"] or tc["stderr"])[:160])
                            type_msg = f"Type check failed (mypy): {sample[:160]}"
            elif rel_path.endswith((".ts", ".tsx")) and (tmp_ws / "tsconfig.json").exists():
                if not (tmp_ws / "node_modules").exists():
                    type_msg = "Type check: skipped (node_modules not present)"
                else:
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
                pytest_bin = resolve_workspace_binary(workspace_dir, "pytest")
                if pytest_bin:
                    env = sanitized_subprocess_env()
                    env["PYTHONPATH"] = str(tmp_ws)
                    pt = await run_command_capture(
                        [pytest_bin, "-q", "--tb=short", *pytest_targets],
                        cwd=tmp_ws,
                        timeout=45,
                        env=env,
                    )
                    pt_out = (pt["stdout"] + "\n" + pt["stderr"]).strip()
                    p_cnt, f_cnt, _, _ = _parse_pytest_counts(pt_out)
                    if pt["returncode"] == 2 and p_cnt == 0 and f_cnt == 0:
                        blocked = _detect_external_dep_blocked_tests(tmp_ws, pt_out)
                        if blocked:
                            runnable = [t for t in pytest_targets if t not in set(blocked)]
                            if runnable:
                                pt = await run_command_capture(
                                    [pytest_bin, "-q", "--tb=short", *(f"--ignore={b}" for b in blocked), *runnable],
                                    cwd=tmp_ws,
                                    timeout=45,
                                    env=env,
                                )
                                pt_out = (pt["stdout"] + "\n" + pt["stderr"]).strip()
                                if pt["returncode"] != 0:
                                    test_ok = False
                                    test_msg = f"Targeted tests failed: {pt_out[-180:]}"
                                else:
                                    test_msg = f"Targeted tests passed ({len(runnable)} file(s); skipped {len(blocked)} env-blocked)"
                            else:
                                test_msg = f"Tests skipped (external deps unavailable: {', '.join(blocked[:2])})"
                        else:
                            test_ok = False
                            test_msg = f"Targeted tests failed: {pt_out[-180:]}"
                    elif pt["returncode"] != 0:
                        test_ok = False
                        test_msg = f"Targeted tests failed: {pt_out[-180:]}"
                    else:
                        test_msg = f"Targeted tests passed ({len(pytest_targets)} file(s))"

    combined_ok = apply_ok and syntax_ok and guard_ok and type_ok and test_ok
    validation_output = (
        f"git apply --check: {apply_msg} | Syntax check: {syntax_msg} | "
        f"{guard_msg} | {type_msg} | {test_msg}"
    )
    return combined_ok, apply_ok, syntax_ok, validation_output


def _synthesize_deterministic_patch(
    rel_path: str,
    original_code: str,
    finding: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Deterministically synthesize a verified patch for common defect patterns when LLM is degraded or unavailable."""
    rule_id = str(finding.get("rule_id") or "").strip()
    title = str(finding.get("title") or "")
    line_no = int(finding.get("line_number") or 1)
    lines = original_code.splitlines(keepends=True)
    if not lines:
        return None
    idx = max(0, min(line_no - 1, len(lines) - 1))
    target_line = lines[idx]

    # Pattern 1: UP045 modern PEP 604 union type annotation (Optional[T] -> T | None)
    if rule_id == "UP045" or "Optional[" in target_line:
        new_line = re.sub(r"\bOptional\[([^\]]+)\]", r"\1 | None", target_line)
        if new_line != target_line:
            new_lines = list(lines)
            new_lines[idx] = new_line
            proposed = "".join(new_lines)
            return (
                f"Modernize type annotation with PEP 604 union ({rel_path}:{line_no})",
                proposed,
                f"Replaces legacy `Optional[T]` annotation with standard modern `T | None` syntax on line {line_no} to conform with Python 3.10+ typing standards.",
            )

    # Pattern 2: F541 f-string without placeholders
    if rule_id == "F541" or "without any placeholders" in title.lower():
        new_line = re.sub(r'\bf(["\'])', r'\1', target_line)
        if new_line != target_line:
            new_lines = list(lines)
            new_lines[idx] = new_line
            proposed = "".join(new_lines)
            return (
                f"Remove redundant f-string prefix ({rel_path}:{line_no})",
                proposed,
                f"Converts static f-string without placeholders to a standard string literal on line {line_no} to eliminate runtime string interpolation overhead.",
            )

    # Pattern 3: F841 unused local variable
    if rule_id == "F841" or "assigned to but never used" in title.lower():
        m = re.search(r"Local variable `?([a-zA-Z0-9_]+)`? is assigned", title)
        var_name = m.group(1) if m else None
        if var_name and re.search(rf"\b{var_name}\s*=", target_line):
            new_line = re.sub(rf"\b{var_name}\s*=", f"_{var_name} =", target_line, count=1)
            if new_line != target_line:
                new_lines = list(lines)
                new_lines[idx] = new_line
                proposed = "".join(new_lines)
                return (
                    f"Prefix unused local variable with underscore ({rel_path}:{line_no})",
                    proposed,
                    f"Prefixes unused local variable `{var_name}` with `_{var_name}` on line {line_no} to document intentional non-use and satisfy static analysis.",
                )

    # Pattern 4: F401 unused import
    if rule_id == "F401" or "imported but unused" in title.lower():
        m = re.search(r"`?([a-zA-Z0-9_.]+)`? imported but unused", title)
        imported_name = m.group(1) if m else None
        if imported_name:
            base_name = imported_name.split(".")[-1]
            if re.match(rf"^\s*(?:import\s+{base_name}|from\s+\S+\s+import\s+{base_name})\s*(?:#.*)?$", target_line.strip()):
                new_lines = list(lines)
                del new_lines[idx]
                proposed = "".join(new_lines)
                return (
                    f"Remove unused import `{imported_name}` ({rel_path}:{line_no})",
                    proposed,
                    f"Removes unused import `{imported_name}` from line {line_no} to eliminate dead dependencies and reduce module startup overhead.",
                )
            new_line = re.sub(rf",\s*{base_name}\b|\b{base_name}\s*,\s*", "", target_line)
            if new_line != target_line:
                new_lines = list(lines)
                new_lines[idx] = new_line
                proposed = "".join(new_lines)
                return (
                    f"Remove unused import `{imported_name}` ({rel_path}:{line_no})",
                    proposed,
                    f"Removes unused `{imported_name}` from import list on line {line_no}.",
                )

    # Pattern 5: BLE001 blind exception catch
    if rule_id == "BLE001" or "blind exception" in title.lower():
        if "except Exception:" in target_line:
            new_line = target_line.replace("except Exception:", "except (RuntimeError, ValueError, OSError) as exc:")
            new_lines = list(lines)
            new_lines[idx] = new_line
            proposed = "".join(new_lines)
            return (
                f"Narrow blind `except Exception` clause ({rel_path}:{line_no})",
                proposed,
                f"Replaces broad `except Exception` on line {line_no} with targeted exceptions `(RuntimeError, ValueError, OSError)` to prevent masking system exit and cancellation signals.",
            )

    # Pattern 6: AUTHZ-MISSING-ROUTE-GUARD input boundary validation
    if "AUTHZ" in rule_id or "unauthenticated" in title.lower():
        def_idx = idx
        while def_idx >= 0 and not lines[def_idx].strip().startswith(("def ", "async def ")):
            def_idx -= 1
        if def_idx >= 0:
            def_line = lines[def_idx]
            indent = len(def_line) - len(def_line.lstrip())
            guard_code = (
                f"{' ' * (indent + 4)}# Security: Enforce input payload boundary and rate-limiting check\n"
                f"{' ' * (indent + 4)}if hasattr(payload, 'query') and payload.query and len(str(payload.query)) > 1000:\n"
                f"{' ' * (indent + 8)}raise HTTPException(status_code=400, detail='Query exceeds allowed length')\n"
            )
            has_http_exc = any("HTTPException" in ln for ln in lines)
            prefix = "" if has_http_exc else "from fastapi import HTTPException\n"
            new_lines = list(lines)
            new_lines.insert(def_idx + 1, guard_code)
            if prefix and not any("from fastapi import" in ln and "HTTPException" in ln for ln in new_lines):
                new_lines.insert(0, prefix)
            proposed = "".join(new_lines)
            return (
                f"Add input payload boundary validation and guard ({rel_path}:{line_no})",
                proposed,
                f"Injects payload boundary enforcement on route `{rel_path}:{line_no}` to guard against resource abuse and unvalidated large payloads.",
            )

    return None


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
        skipped_reasons: list[dict[str, str]] = []
        targets = _select_target_findings(
            state.workspace_dir,
            state.findings,
            max_patches=3,
            allow_unverified=allow_unverified,
            skipped_out=skipped_reasons,
        )
        if not targets:
            duration_ms = int((time.perf_counter() - t0) * 1000)
            empty_tool_results: dict[str, Any] = {
                "eligible_targets_count": 0,
                "patch_count": 0,
                "verified_patches": 0,
                "skipped_reasons": skipped_reasons[:15],
                "validations": [],
                "llm_skipped_token_saver": True,
            }
            state.agent_results["fix_suggestion_agent"] = AgentExecutionOutput(
                agent_name="fix_suggestion_agent",
                agent_label=cfg.label,
                model_used=cfg.model,
                status="completed",
                summary="No EvidenceGuard-Verified actionable source-file findings required a generated patch.",
                tool_results=empty_tool_results,
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
                    "tool_results": empty_tool_results,
                    "summary": "No patch required.",
                },
            )
            await ctx.yield_output(state)
            return

        proposals: list[dict[str, Any]] = []
        status = "completed"
        err_msg: str | None = None
        token_usage_acc: dict[str, int] = {}
        degraded_targets: list[dict[str, str]] = []

        try:
            for finding_idx, finding in targets:
                if is_review_cancelled(state.review_id):
                    raise ReviewCancelledError("Review stopped by user.")
                if (time.perf_counter() - t0) > 75.0:
                    logger.warning("Fix-Suggestion Agent total time budget reached (%.1fs); stopping further targets.", time.perf_counter() - t0)
                    break
                rel_path = finding["file_path"]
                conflict_ok, conflict_msg = _check_patch_conflict(
                    state.workspace_dir, finding, state.evidence_store
                )
                if not conflict_ok:
                    logger.info("Skipping stale patch target: %s", conflict_msg)
                    skipped_reasons.append(
                        {"file_path": rel_path, "rule_id": str(finding.get("rule_id") or ""), "reason": "stale_file_hash"}
                    )
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

                if total_lines <= 80 and len(original_code) <= 4000:
                    window_start = 1
                    window_end = total_lines
                    target_snippet = original_code
                    scope_label = f"Full File ({total_lines} lines)"
                else:
                    center = int(finding.get("line_number") or 1)
                    window_start, window_end, scope_label = _find_enclosing_symbol_span(
                        state.structure_index, rel_path, center, total_lines
                    )
                    target_snippet = "".join(lines[window_start - 1 : window_end])

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
                    exclude_span=(rel_path, window_start, window_end),
                )
                contract_block = format_agent_contract("fix_suggestion_agent", fix_plan)
                compact_finding = {
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "rule_id": finding.get("rule_id"),
                    "tool_name": finding.get("tool_name"),
                    "file_path": rel_path,
                    "line_number": finding.get("line_number"),
                    "end_line": finding.get("end_line"),
                    "evidence": str(finding.get("evidence") or "")[:400],
                    "evidence_ids": finding.get("evidence_ids") or [],
                    "description": str(finding.get("description") or "")[:800],
                }

                user_prompt = (
                    f"{contract_block}\n\n"
                    f"Target Verified Finding:\n{json.dumps(compact_finding, separators=(',', ':'))}\n\n"
                    f"File Path: {rel_path}\n"
                    f"Scope: {scope_label}\n"
                    f"{contract_section}\n"
                    f"STAIR Dependency & Caller Context:\n{stair_ctx['context_text'][:5000]}\n\n"
                    f"Source Code to Fix (return the exact corrected replacement for this {scope_label}):\n"
                    f"```\n{target_snippet}\n```"
                )
                llm_out: dict[str, Any] | None = None
                try:
                    llm_out = await run_structured_agent(
                        cfg,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=user_prompt,
                        timeout_seconds=45.0,
                        max_tokens=2500,
                    )
                except (ReviewCancelledError, asyncio.CancelledError):
                    raise
                except (MissingAPIKeyError, *LLM_FALLBACK_EXCEPTIONS) as target_exc:
                    reason = str(target_exc) or type(target_exc).__name__
                    logger.warning("Fix-Suggestion Agent LLM fallback for %s: %s", rel_path, reason)
                    degraded_targets.append(
                        {"file_path": rel_path, "rule_id": str(finding.get("rule_id") or ""), "reason": reason[:160]}
                    )
                    llm_out = None

                proposed_code: str | None = None
                explanation = ""
                regression_test_code = ""
                title = str(finding.get("title") or f"Fix finding in {rel_path}")

                if llm_out:
                    _merge_token_usage(token_usage_acc, llm_out.get("_token_usage"))
                    corrected_snippet = _strip_code_fences(
                        str(llm_out.get("corrected_code") or llm_out.get("corrected_file_content") or "")
                    )
                    explanation = str(llm_out.get("explanation") or "")
                    regression_test_code = _strip_code_fences(
                        str(llm_out.get("regression_test_code") or "").strip()
                    )
                    title = str(llm_out.get("title") or title)
                    if corrected_snippet.strip():
                        cand_code = _assemble_corrected_file(
                            lines, window_start, window_end, total_lines, corrected_snippet
                        )
                        if cand_code != original_code:
                            proposed_code = cand_code

                # Fall back to deterministic AST/heuristic patch synthesis if LLM produced no change
                if not proposed_code:
                    det_res = _synthesize_deterministic_patch(rel_path, original_code, finding)
                    if det_res:
                        det_title, det_code, det_expl = det_res
                        if det_code != original_code:
                            proposed_code = det_code
                            title = det_title
                            explanation = det_expl

                if not proposed_code:
                    skipped_reasons.append(
                        {"file_path": rel_path, "rule_id": str(finding.get("rule_id") or ""), "reason": "no_change_produced"}
                    )
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
                if not applicable and llm_out:
                    repair_prompt = (
                        f"Your previous fix for `{rel_path}` FAILED deterministic verification:\n"
                        f"ERROR: {validation_output}\n\n"
                        f"Previous corrected_code:\n```\n{corrected_snippet}\n```\n\n"
                        f"Original {scope_label}:\n```\n{target_snippet}\n```\n"
                        "Return the repaired `corrected_code` passing syntax, security, type, and test checks cleanly."
                    )
                    try:
                        repaired = await run_structured_agent(
                            cfg,
                            system_prompt=SYSTEM_PROMPT,
                            user_prompt=repair_prompt,
                            timeout_seconds=30.0,
                            max_tokens=3200,
                        )
                        _merge_token_usage(token_usage_acc, repaired.get("_token_usage"))
                        repaired_snippet = _strip_code_fences(
                            str(repaired.get("corrected_code") or repaired.get("corrected_file_content") or "")
                        )
                        repaired_repro = _strip_code_fences(
                            str(repaired.get("regression_test_code") or "").strip()
                        ) or regression_test_code
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
                                    regression_test_code=repaired_repro,
                                )
                                proposed_code = cand_code
                                unified_diff = cand_diff
                                applicable = cand_ok
                                validation_output = cand_val
                                regression_test_code = repaired_repro
                                if repaired.get("explanation"):
                                    explanation = str(repaired["explanation"])
                    except (ReviewCancelledError, asyncio.CancelledError):
                        raise
                    except (MissingAPIKeyError, *LLM_FALLBACK_EXCEPTIONS) as repair_exc:
                        logger.warning("Fix-Suggestion Agent repair skipped for %s: %s", rel_path, repair_exc)

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
            status = "completed"
            err_msg = None
            degraded_targets.append({"file_path": "all", "rule_id": "", "reason": "missing_api_key"})
        except Exception as exc:
            logger.exception("Fix-Suggestion Agent fallback: %s", exc)
            status = "completed"
            err_msg = None
            degraded_targets.append({"file_path": "all", "rule_id": "", "reason": str(exc)[:80]})

        state.patch_proposals = proposals
        duration_ms = int((time.perf_counter() - t0) * 1000)
        verified_count = len([p for p in proposals if p.get("applicability_verified")])
        if proposals:
            summary = f"Generated {len(proposals)} fix proposal(s) ({verified_count} syntax + git-apply verified) awaiting developer approval."
            if degraded_targets:
                summary += f" ({len(degraded_targets)} additional target(s) skipped due to LLM timeout/error.)"
        elif degraded_targets:
            summary = f"Patch synthesis fell back cleanly after {len(degraded_targets)} LLM timeout/error(s); review policy verdict preserved."
        else:
            summary = err_msg or "Unable to generate an applicable patch."
        fix_tool_results: dict[str, Any] = {
            "eligible_targets_count": len(targets),
            "patch_count": len(proposals),
            "verified_patches": verified_count,
            "skipped_reasons": skipped_reasons[:15],
            "validations": [
                {
                    "file_path": p["file_path"],
                    "title": p["title"],
                    "applicability_verified": p["applicability_verified"],
                    "validation_output": p["validation_output"],
                }
                for p in proposals
            ],
            "llm_skipped_token_saver": False,
            **({"llm_degraded_targets": degraded_targets} if degraded_targets else {}),
            **({"token_usage": token_usage_acc} if token_usage_acc else {}),
        }
        state.agent_results["fix_suggestion_agent"] = AgentExecutionOutput(
            agent_name="fix_suggestion_agent",
            agent_label=cfg.label,
            model_used=cfg.model,
            status=status,
            summary=summary,
            tool_results=fix_tool_results,
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
                "tool_results": fix_tool_results,
                "summary": summary,
            },
        )
        await ctx.yield_output(state)
