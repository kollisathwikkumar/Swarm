from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from agent_framework import Executor, WorkflowContext, handler

from app.agents.llm_factory import MissingAPIKeyError, run_structured_agent
from app.orchestration.cancellation import ReviewCancelledError, is_review_cancelled
from app.orchestration.shared_state import AgentExecutionOutput, ReviewState
from app.scanners.code_engines import is_test_fixture_hit, read_prioritized_workspace_files

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

DETERMINISTIC_TOOL_NAMES = {
    "bandit",
    "semgrep",
    "gitleaks",
    "osv-scanner",
    "security-guard",
    "ruff",
    "ast-complexity",
    "ast-style-checker",
    "js-style-checker",
    "duplicate-detector",
    "python-ast",
    "ts-syntax-checker",
    "pytest",
    "vitest",
    "coverage.py",
    "test-mapper",
}

LLM_ONLY_TOOLS = {
    "git-diff",
    "llm-review",
    "llm-style-review",
    "llm-security-review",
    "llm-test-review",
}

SYSTEM_PROMPT = """You are the Reviewer Manager (Fan-In Adversarial Verification & Decision Engine) in Swarm.
You receive:
1. Candidate findings from the four parallel agents (Diff, Style, Security, Test-Coverage).
2. Deterministic Scanner Hits Index (`deterministic_tool_index`), Cross-File Test-Import Coverage Map (`test_import_map`), Polyglot Symbols/Guards (`polyglot_symbols`), and COMPLETE line-numbered ground-truth source files (`ground_truth_files`).

Your strict verification & consolidation duties:
1. **Cross-Examine Every Candidate Against Ground-Truth Code & Maps**:
   - Check `[COMPLETE FILE]` headers, `implemented_guards_in_full_file`, and `test_import_map` BEFORE keeping any claim.
   - **REJECT** any finding that contradicts the actual code on disk or `test_import_map` — for example:
     * Claims a validation, URL check, or citation check is missing when it is implemented in `ground_truth_files` or `implemented_guards_in_full_file`.
     * Claims a test suite "only tests happy paths" when error/edge tests exist in `test_import_map.test_suites` or the test file.
     * Claims a module has no test coverage when `test_import_map.source_file_test_map[file].has_any_unmocked_test` is true.
     * Complains about Swarm's own test runner (`pytest` finding 0 Python tests on a TS repo).
   - Record every discarded finding cleanly in `"rejected_false_positives"` with exact contradictory evidence.
2. **Deduplicate Overlapping Findings**:
   - Merge findings covering the same underlying defect + file + line/module into one canonical finding, listing all contributing sources in `deduplicated_sources`.
3. **Honest Evidence Provenance (`verification_status`)**:
   - Mark `"Verified"` ONLY when backed directly by an entry in `deterministic_tool_index` (Bandit, Semgrep, Gitleaks, OSV-Scanner, Security-Guard, Ruff, AST/Syntax checkers, Pytest/Vitest failures, Coverage.py missing_lines, or deterministic Test-Mapper status).
   - Mark pure LLM reasoning (`git-diff`, `llm-*`) strictly as `"Needs Verification"`, NEVER `"Verified"`.
   - Downgrade Gitleaks/secret hits flagged `is_test_fixture: true` in unit-test files to `"Low"` informational (do not demand credential rotation for clearly synthetic fixtures).
4. **Priority & Executive Summary**:
   - Order verified Critical/High security & correctness bugs at top (`priority_rank` starting at 1).

Return strict JSON:
{
  "executive_summary": "Concise consolidated engineering review summary.",
  "rejected_false_positives": [
    {
      "title": "Rejected claim title",
      "file_path": "path/to/file",
      "reason": "Exact contradiction observed in ground_truth_files or test_import_map"
    }
  ],
  "consolidated_findings": [
    {
      "agent": "Security Agent",
      "category": "security|code_quality|testing|change_risk",
      "severity": "Critical|High|Medium|Low",
      "title": "Canonical finding title",
      "description": "Clear description",
      "file_path": "exact/path.py",
      "line_number": 24,
      "evidence": "Verified evidence snippet from the actual file or deterministic tool",
      "tool_name": "bandit|semgrep|gitleaks|osv-scanner|security-guard|ruff|ast-complexity|js-style-checker|ts-syntax-checker|duplicate-detector|pytest|vitest|coverage.py|test-mapper|git-diff|llm-review",
      "rule_id": "optional rule id",
      "recommendation": "Actionable fix guidance",
      "verification_status": "Verified|Needs Verification|Unverified",
      "deduplicated_sources": ["Security Agent", "Diff Agent"],
      "priority_rank": 1
    }
  ]
}"""


def _verify_file_and_line(workspace_dir: Path, file_path: str, line_number: int | None) -> tuple[bool, str]:
    if not file_path:
        return False, ""
    candidate = (workspace_dir / file_path).resolve()
    if not candidate.exists() or not candidate.is_file():
        return False, ""
    if workspace_dir.resolve() not in candidate.parents and candidate != workspace_dir.resolve():
        return False, ""
    if line_number is None or line_number < 1:
        return True, ""
    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_number <= len(lines):
        return True, lines[line_number - 1].strip()
    return True, ""


def _deterministic_deduplicate(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, int, str], dict[str, Any]] = {}
    for f in raw_findings:
        fp = str(f.get("file_path") or "").strip()
        ln = int(f.get("line_number") or 0)
        cat = str(f.get("category") or "general")
        sev = str(f.get("severity") or "Low").title()
        key = (fp, ln, cat)
        src = str(f.get("agent") or "Agent")
        if f.get("tool_name"):
            src = f"{src} ({f['tool_name']})"
        if key not in merged:
            copy = dict(f)
            copy["severity"] = sev
            copy["deduplicated_sources"] = [src]
            merged[key] = copy
        else:
            existing = merged[key]
            if src not in existing["deduplicated_sources"]:
                existing["deduplicated_sources"].append(src)
            if SEVERITY_ORDER.get(sev, 3) < SEVERITY_ORDER.get(
                str(existing.get("severity") or "Low").title(), 3
            ):
                existing["severity"] = sev
            if f.get("verification_status") == "Verified":
                existing["verification_status"] = "Verified"
    result = list(merged.values())
    result.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(str(x.get("severity") or "Low").title(), 3),
            x.get("file_path", ""),
            x.get("line_number") or 0,
        )
    )
    for idx, item in enumerate(result, start=1):
        item["priority_rank"] = idx
    return result


def _agent_field(agent: AgentExecutionOutput | dict[str, Any], key: str, default: Any = None) -> Any:
    if isinstance(agent, dict):
        return agent.get(key, default)
    return getattr(agent, key, default)


def _evaluate_review_policy(
    state: ReviewState,
    findings: list[dict[str, Any]],
    agent_outputs: list[AgentExecutionOutput] | list[dict[str, Any]],
) -> tuple[str, str, list[dict[str, Any]]]:
    policy = state.policy or {}
    block_critical = bool(policy.get("block_on_critical", True))
    block_high = bool(policy.get("block_on_high", True))
    require_tests_pass = bool(policy.get("require_tests_pass", True))
    require_all_scans = bool(policy.get("require_all_mandatory_scans", True))

    stopped_agents = [
        str(_agent_field(a, "agent_label") or _agent_field(a, "agent_name") or "Agent")
        for a in agent_outputs
        if _agent_field(a, "status") == "stopped"
    ]
    incomplete_agents = [
        str(_agent_field(a, "agent_label") or _agent_field(a, "agent_name") or "Agent")
        for a in agent_outputs
        if _agent_field(a, "status") in ("incomplete", "failed")
    ]
    test_agent = next(
        (a for a in agent_outputs if _agent_field(a, "agent_name") == "test_coverage_agent"),
        None,
    )
    test_tr = (_agent_field(test_agent, "tool_results") or {}) if test_agent else {}
    tests_failed = int(test_tr.get("failed", 0))

    blocking_reasons: list[str] = []
    for f in findings:
        sev = str(f.get("severity") or "Low").title()
        f["severity"] = sev
        verified = f.get("verification_status") == "Verified"
        is_block = verified and ((sev == "Critical" and block_critical) or (sev == "High" and block_high))
        f["is_blocking"] = is_block
        if is_block:
            blocking_reasons.append(f"{sev}: {f.get('title')} ({f.get('file_path')}:{f.get('line_number') or 1})")

    # Priority 1: Stop Operation or mandatory agent/scanner timeout, failure, or missing API key
    if is_review_cancelled(state.review_id) or stopped_agents:
        return (
            "Incomplete",
            "Stopped by user before completion.",
            findings,
        )
    if require_all_scans and incomplete_agents:
        return (
            "Incomplete",
            f"Mandatory analysis incomplete for: {', '.join(incomplete_agents)}.",
            findings,
        )
    # Priority 2: Mandatory test suite failure
    if require_tests_pass and tests_failed > 0:
        return (
            "Request Changes",
            f"Mandatory test suite failed ({tests_failed} failing test(s)) and {len(blocking_reasons)} blocking finding(s).",
            findings,
        )
    # Priority 3: Verified Critical / High blocking finding
    if blocking_reasons:
        return (
            "Request Changes",
            f"{len(blocking_reasons)} verified blocking finding(s) found (top: {blocking_reasons[0]}).",
            findings,
        )
    # Priority 4: Clean pass
    return (
        "Approve",
        "No verified Critical/High blocking findings and all mandatory checks passed.",
        findings,
    )


def _collect_deterministic_index(results: list[AgentExecutionOutput]) -> tuple[set[tuple[str, str]], dict[str, Any]]:
    """
    Build an authoritative index of `(tool_name, file_path)` emitted by deterministic scanners/analyzers
    during this review so LLMs cannot forge `'Verified'` status or hallucinate tool provenance.
    """
    det_pairs: set[tuple[str, str]] = set()
    extras: dict[str, Any] = {
        "polyglot_symbols": {},
        "test_import_map": {},
        "test_runner": "",
        "tests_failed": 0,
        "deterministic_hits": [],
    }

    for res in results:
        tr = res.tool_results or {}
        if res.agent_name == "diff_agent":
            extras["polyglot_symbols"] = tr.get("polyglot_symbols") or tr.get("python_ast_symbols") or {}
        elif res.agent_name == "security_agent":
            for key in ("bandit", "semgrep", "gitleaks", "osv_scanner", "deterministic_guards"):
                for item in (tr.get(key) or {}).get("findings", []) or []:
                    tname = str(item.get("tool") or ("security-guard" if key == "deterministic_guards" else key.replace("_", "-")))
                    fp = str(item.get("file_path") or "").strip()
                    det_pairs.add((tname, fp))
                    extras["deterministic_hits"].append(
                        {
                            "tool": tname,
                            "rule_id": item.get("rule_id"),
                            "file_path": fp,
                            "line_number": item.get("line_number"),
                            "severity": item.get("severity"),
                            "title": item.get("title"),
                            "is_test_fixture": bool(item.get("is_test_fixture")),
                        }
                    )
        elif res.agent_name == "style_agent":
            for section in ("ruff", "ast_checks"):
                for item in (tr.get(section) or {}).get("findings", []) or []:
                    tname = str(item.get("tool") or "ruff")
                    fp = str(item.get("file_path") or "").strip()
                    det_pairs.add((tname, fp))
                    extras["deterministic_hits"].append(
                        {
                            "tool": tname,
                            "rule_id": item.get("rule_id"),
                            "file_path": fp,
                            "line_number": item.get("line_number"),
                            "severity": item.get("severity"),
                            "message": item.get("message"),
                        }
                    )
        elif res.agent_name == "test_coverage_agent":
            extras["test_import_map"] = tr.get("test_import_map") or {}
            extras["test_runner"] = str(tr.get("runner") or "")
            extras["tests_failed"] = int(tr.get("failed") or 0)
            src_map = (extras["test_import_map"] or {}).get("source_file_test_map") or {}
            for fp, info in src_map.items():
                if info.get("coverage_status") in ("mocked_only_untested", "no_importing_tests_found"):
                    det_pairs.add(("test-mapper", fp))
            for fp in (tr.get("changed_file_coverage") or {}):
                det_pairs.add(("coverage.py", fp))
            if extras["tests_failed"] > 0:
                runner = extras["test_runner"] or "pytest"
                det_pairs.add((runner, "*"))
                for tf in tr.get("test_files") or []:
                    det_pairs.add((runner, tf))

    return det_pairs, extras


def _is_harness_noise(finding: dict[str, Any], extras: dict[str, Any]) -> str | None:
    title = str(finding.get("title") or "").lower()
    evidence = str(finding.get("evidence") or "").lower()
    desc = str(finding.get("description") or "").lower()
    combined = f"{title} {evidence} {desc}"

    if extras.get("test_runner") in ("static_js_ts_inspection", "vitest") and (
        "test-runner mismatch" in combined
        or "no python test files discovered" in combined
        or ("pytest" in combined and "tests_found" in combined and "0" in combined)
    ):
        return "Rejected harness-level pytest/TS runner telemetry mistakenly filed as a repository code defect."
    return None


class ReviewerManagerExecutor(Executor):
    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="reviewer_manager")
        self._emit = emit_event

    @handler
    async def handle(
        self,
        results: list[AgentExecutionOutput],
        ctx: WorkflowContext[ReviewState],
    ) -> None:
        t0 = time.perf_counter()
        state: ReviewState = ctx.get_state("review_state")
        cfg = state.agent_configs["reviewer_manager"]

        await self._emit(
            state.review_id,
            "fan_in_started",
            {
                "agent_name": "reviewer_manager",
                "agent_label": cfg.label,
                "model": cfg.model,
                "completed_parallel_agents": [r.agent_name for r in results],
            },
        )

        all_raw_findings: list[dict[str, Any]] = []
        for res in results:
            state.agent_results[res.agent_name] = res.to_dict()
            if res.agent_name == "diff_agent":
                if res.summary and not res.error_message:
                    state.diff_summary = res.summary
                state.diff_context = res.tool_results
            for f in res.findings:
                all_raw_findings.append(f.to_dict())

        # Surface deterministic scanner findings directly if an analysis agent failed/missed API key
        # or if security_agent didn't forward deterministic_guards hits
        existing_sig = {
            (str(f.get("file_path") or ""), int(f.get("line_number") or 0), str(f.get("rule_id") or ""))
            for f in all_raw_findings
        }
        for res in results:
            tr = res.tool_results or {}
            if res.agent_name == "security_agent":
                guard_items = (tr.get("deterministic_guards") or {}).get("findings", []) or []
                for item in guard_items:
                    sig = (str(item.get("file_path") or ""), int(item.get("line_number") or 0), str(item.get("rule_id") or ""))
                    if sig not in existing_sig:
                        all_raw_findings.append(
                            {
                                "agent": "Security Agent",
                                "category": "security",
                                "severity": item.get("severity", "Medium"),
                                "title": item.get("title", "Deterministic Security Guard Finding"),
                                "description": item.get("description", ""),
                                "file_path": item.get("file_path", ""),
                                "line_number": item.get("line_number"),
                                "end_line": None,
                                "evidence": item.get("evidence", ""),
                                "recommendation": item.get("description", "Remediate detected guard gap."),
                                "verification_status": "Verified",
                                "tool_name": "security-guard",
                                "rule_id": item.get("rule_id"),
                            }
                        )
            if res.status in ("incomplete", "failed") and tr:
                if res.agent_name == "security_agent":
                    for tool_key in ("bandit", "semgrep", "gitleaks", "osv_scanner"):
                        for item in (tr.get(tool_key) or {}).get("findings", []):
                            all_raw_findings.append(
                                {
                                    "agent": "Security Agent",
                                    "category": "security",
                                    "severity": item.get("severity", "High"),
                                    "title": item.get("title", "Deterministic Security Finding"),
                                    "description": item.get("description", ""),
                                    "file_path": item.get("file_path", ""),
                                    "line_number": item.get("line_number"),
                                    "end_line": item.get("end_line"),
                                    "evidence": item.get("evidence", ""),
                                    "recommendation": "Remediate detected security issue.",
                                    "verification_status": "Verified",
                                    "tool_name": item.get("tool", tool_key),
                                    "rule_id": item.get("rule_id"),
                                }
                            )
                elif res.agent_name == "style_agent":
                    for section in ("ruff", "ast_checks"):
                        for item in (tr.get(section) or {}).get("findings", []):
                            all_raw_findings.append(
                                {
                                    "agent": "Style Agent",
                                    "category": "code_quality",
                                    "severity": item.get("severity", "Low"),
                                    "title": item.get("rule_id", "Style Violation"),
                                    "description": item.get("message", ""),
                                    "file_path": item.get("file_path", ""),
                                    "line_number": item.get("line_number"),
                                    "end_line": item.get("end_line"),
                                    "evidence": item.get("message", ""),
                                    "recommendation": "Fix code style/complexity issue.",
                                    "verification_status": "Verified",
                                    "tool_name": item.get("tool", "ruff"),
                                    "rule_id": item.get("rule_id"),
                                }
                            )
            if res.agent_name == "test_coverage_agent" and int(tr.get("failed") or 0) > 0:
                failed_cnt = int(tr.get("failed") or 0)
                runner_name = str(tr.get("runner") or "pytest")
                test_file_hint = str((tr.get("test_files") or [""])[0] or "")
                has_test_failure = any(
                    str(f.get("tool_name") or "") in ("pytest", "vitest")
                    and "fail" in f"{f.get('title', '')} {f.get('description', '')}".lower()
                    for f in all_raw_findings
                )
                if not has_test_failure:
                    all_raw_findings.append(
                        {
                            "agent": "Test-Coverage Agent",
                            "category": "testing",
                            "severity": "High",
                            "title": f"{runner_name} suite reported {failed_cnt} failing test(s)",
                            "description": f"Deterministic {runner_name} execution failed with {failed_cnt} failing test(s).",
                            "file_path": test_file_hint,
                            "line_number": 1 if test_file_hint else None,
                            "end_line": None,
                            "evidence": str(tr.get("output") or "")[-400:],
                            "recommendation": "Fix the failing unit/integration tests before merging.",
                            "verification_status": "Verified",
                            "tool_name": runner_name,
                            "rule_id": "TEST-SUITE-FAILED",
                        }
                    )

        det_index, extras = _collect_deterministic_index(results)
        rejected_auto: list[dict[str, Any]] = []

        # Pre-LLM deterministic grounding & noise rejection
        verified_raw: list[dict[str, Any]] = []
        referenced_files: list[str] = []
        for f in all_raw_findings:
            noise_reason = _is_harness_noise(f, extras)
            if noise_reason:
                rejected_auto.append(
                    {
                        "title": f.get("title", ""),
                        "file_path": f.get("file_path", ""),
                        "reason": noise_reason,
                    }
                )
                continue

            fp = str(f.get("file_path") or "").strip()
            ln = f.get("line_number")
            if fp:
                referenced_files.append(fp)
            exists, actual_line = _verify_file_and_line(state.workspace_dir, fp, ln)
            tool_name = str(f.get("tool_name") or "llm-review")
            is_tool_backed = (tool_name, fp) in det_pairs_or_star(det_index, fp)

            if not exists and fp:
                f["verification_status"] = "Unverified"
            else:
                if actual_line and not f.get("evidence"):
                    f["evidence"] = actual_line
                if tool_name in LLM_ONLY_TOOLS or not is_tool_backed:
                    f["verification_status"] = "Needs Verification"
                    if tool_name in DETERMINISTIC_TOOL_NAMES and not is_tool_backed:
                        f["tool_name"] = "llm-review"
                else:
                    f["verification_status"] = "Verified"

                # Normalize Gitleaks fixture classification cleanly
                if tool_name == "gitleaks" and is_test_fixture_hit(
                    state.workspace_dir, fp, ln, str(f.get("evidence") or "")
                ):
                    f["severity"] = "Low"
                    f["is_test_fixture"] = True

            verified_raw.append(f)

        # Include test suites referenced for verification
        test_suites = ((extras.get("test_import_map") or {}).get("test_suites") or {}).keys()
        ground_truth_files = read_prioritized_workspace_files(
            state.workspace_dir,
            list(dict.fromkeys(referenced_files + list(test_suites))),
            max_files=14,
            max_total_chars=26000,
            per_file_chars=12000,
        )

        consolidated: list[dict[str, Any]] = []
        rejected_llm: list[dict[str, Any]] = []
        manager_summary = ""
        manager_status = "completed"
        manager_error: str | None = None
        manager_raw: dict[str, Any] = {}

        try:
            if is_review_cancelled(state.review_id):
                raise ReviewCancelledError("Review stopped by user.")
            user_prompt = (
                f"Repository: {state.repository_name}\n"
                f"Diff Summary: {state.diff_summary[:2000]}\n"
                f"Agent Execution Statuses: {json.dumps({r.agent_name: r.status for r in results})}\n\n"
                f"Deterministic Tool Index (only these files/tools produced verified tool hits):\n"
                f"{json.dumps(extras['deterministic_hits'], indent=2)[:7000]}\n\n"
                f"Polyglot Symbols & Guards (across complete files):\n"
                f"{json.dumps(extras['polyglot_symbols'], indent=2)[:7000]}\n\n"
                f"Cross-File Test-Import Coverage Map:\n"
                f"{json.dumps(extras['test_import_map'], indent=2)[:7000]}\n\n"
                f"Complete Ground-Truth Referenced Files:\n"
                f"{json.dumps(ground_truth_files, indent=2)[:24000]}\n\n"
                f"Candidate Findings ({len(verified_raw)}):\n"
                f"{json.dumps(verified_raw, indent=2)[:14000]}"
            )
            manager_raw = await run_structured_agent(
                cfg, system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, timeout_seconds=95.0
            )
            manager_summary = str(manager_raw.get("executive_summary") or "").strip()
            rejected_llm = list(manager_raw.get("rejected_false_positives") or [])

            for idx, item in enumerate(manager_raw.get("consolidated_findings", []) or [], start=1):
                noise_reason = _is_harness_noise(item, extras)
                if noise_reason:
                    rejected_auto.append(
                        {"title": item.get("title", ""), "file_path": item.get("file_path", ""), "reason": noise_reason}
                    )
                    continue

                fp = str(item.get("file_path") or "").strip()
                ln = item.get("line_number")
                exists, actual_line = _verify_file_and_line(state.workspace_dir, fp, ln)
                tool_name = str(item.get("tool_name") or "llm-review")
                ver_status = str(item.get("verification_status") or "Needs Verification")
                is_tool_backed = (tool_name, fp) in det_pairs_or_star(det_index, fp)

                if not exists and fp:
                    ver_status = "Unverified"
                elif tool_name in LLM_ONLY_TOOLS or not is_tool_backed:
                    ver_status = "Needs Verification"
                    if tool_name in DETERMINISTIC_TOOL_NAMES and not is_tool_backed:
                        tool_name = "llm-review"
                else:
                    ver_status = "Verified"

                sev = str(item.get("severity") or "Medium").title()
                if tool_name == "gitleaks" and is_test_fixture_hit(
                    state.workspace_dir, fp, ln, str(item.get("evidence") or "")
                ):
                    sev = "Low"

                consolidated.append(
                    {
                        "agent": str(item.get("agent") or "Reviewer Manager"),
                        "category": str(item.get("category") or "general"),
                        "severity": sev,
                        "title": str(item.get("title") or "Finding"),
                        "description": str(item.get("description") or ""),
                        "file_path": fp,
                        "line_number": ln,
                        "end_line": item.get("end_line"),
                        "evidence": str(item.get("evidence") or actual_line or ""),
                        "tool_name": tool_name,
                        "rule_id": item.get("rule_id"),
                        "recommendation": str(item.get("recommendation") or ""),
                        "verification_status": ver_status,
                        "deduplicated_sources": list(
                            item.get("deduplicated_sources") or [item.get("agent") or "Reviewer Manager"]
                        ),
                        "priority_rank": int(item.get("priority_rank") or idx),
                    }
                )
            if not consolidated and verified_raw and not rejected_llm:
                consolidated = _deterministic_deduplicate(verified_raw)
        except (ReviewCancelledError, asyncio.CancelledError):
            raise
        except MissingAPIKeyError as exc:
            manager_status = "incomplete"
            manager_error = str(exc)
            consolidated = _deterministic_deduplicate(verified_raw)
            manager_summary = "Reviewer Manager LLM API key is missing; deterministic consolidation applied."
        except Exception as exc:
            logger.exception("Reviewer Manager LLM failed")
            manager_status = "failed"
            manager_error = str(exc)
            consolidated = _deterministic_deduplicate(verified_raw)
            manager_summary = f"Reviewer Manager LLM error: {exc}"

        all_rejected = rejected_auto + rejected_llm
        all_outputs_for_policy = results + [
            AgentExecutionOutput(
                agent_name="reviewer_manager",
                agent_label=cfg.label,
                model_used=cfg.model,
                status=manager_status,
                summary=manager_summary,
                error_message=manager_error,
            )
        ]
        recommendation, reason, evaluated_findings = _evaluate_review_policy(
            state, consolidated, all_outputs_for_policy
        )
        state.findings = evaluated_findings
        state.recommendation = recommendation
        state.recommendation_reason = reason

        duration_ms = int((time.perf_counter() - t0) * 1000)
        state.agent_results["reviewer_manager"] = AgentExecutionOutput(
            agent_name="reviewer_manager",
            agent_label=cfg.label,
            model_used=cfg.model,
            status=manager_status,
            summary=manager_summary or reason,
            tool_results={
                "consolidated_count": len(evaluated_findings),
                "rejected_false_positives_count": len(all_rejected),
                "rejected_false_positives": all_rejected[:20],
                "recommendation": recommendation,
            },
            raw_output=manager_raw,
            error_message=manager_error,
            duration_ms=duration_ms,
        ).to_dict()

        await self._emit(
            state.review_id,
            "reviewer_manager_completed",
            {
                "agent_name": "reviewer_manager",
                "agent_label": cfg.label,
                "status": manager_status,
                "model": cfg.model,
                "duration_ms": duration_ms,
                "recommendation": recommendation,
                "findings_count": len(evaluated_findings),
                "rejected_false_positives": len(all_rejected),
                "summary": manager_summary or reason,
            },
        )
        await ctx.send_message(state)


def det_pairs_or_star(det_index: set[tuple[str, str]], fp: str) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for tool_name, item_fp in det_index:
        if item_fp == fp or item_fp == "*":
            out.add((tool_name, fp))
    return out
