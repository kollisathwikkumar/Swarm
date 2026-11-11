from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.services.git_workspace import resolve_within_dir
from app.skills.permissions import enforce_agent_permissions

DETERMINISTIC_TOOL_NAMES = {
    "bandit",
    "semgrep",
    "gitleaks",
    "osv-scanner",
    "security-guard",
    "security-taint",
    "codeql",
    "trivy",
    "ruff",
    "eslint",
    "pylint",
    "ast-complexity",
    "ast-style-checker",
    "js-style-checker",
    "duplicate-detector",
    "dead-code-analyzer",
    "python-ast",
    "ts-syntax-checker",
    "mypy",
    "tsc",
    "diff-ast-engine",
    "pytest",
    "vitest",
    "coverage.py",
    "test-mapper",
    "hypothesis",
    "mutmut",
}

LLM_ONLY_TOOLS = {
    "git-diff",
    "llm-review",
    "llm-style-review",
    "llm-security-review",
    "llm-test-review",
}


@dataclass
class EvidenceRecord:
    evidence_id: str
    tool_name: str
    rule_id: str | None
    file_path: str
    line_number: int | None
    end_line: int | None
    commit_sha: str
    source_hash: str
    snippet: str
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "tool_name": self.tool_name,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "end_line": self.end_line,
            "commit_sha": self.commit_sha,
            "source_hash": self.source_hash,
            "snippet": self.snippet,
            "severity": self.severity,
        }


def _file_sha256_prefix(workspace_dir: Path, rel_path: str) -> str:
    if not rel_path:
        return ""
    target = resolve_within_dir(workspace_dir, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return ""
    try:
        return hashlib.sha256(target.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def verify_file_and_line(workspace_dir: Path, file_path: str, line_number: int | None) -> tuple[bool, str]:
    """Verify `file_path` exists safely inside workspace_dir and extract the actual source line."""
    if not file_path:
        return False, ""
    candidate = resolve_within_dir(workspace_dir, file_path)
    if candidate is None or not candidate.exists() or not candidate.is_file():
        return False, ""
    if line_number is None or line_number < 1:
        return True, ""
    lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_number <= len(lines):
        return True, lines[line_number - 1].strip()
    return True, ""


def _read_agent_value(res: Any, key: str, default: Any = None) -> Any:
    if isinstance(res, dict):
        return res.get(key, default)
    return getattr(res, key, default)


def build_evidence_store(
    results: list[Any],
    workspace_dir: Path,
    commit_sha: str,
) -> tuple[list[EvidenceRecord], dict[str, Any]]:
    """
    Build an immutable provenance EvidenceStore (`EV-001`, `EV-002`, ...) from real
    deterministic scanner/analyzer outputs so LLMs cannot forge `Verified` tags.
    """
    records: list[EvidenceRecord] = []
    file_hashes: dict[str, str] = {}
    extras: dict[str, Any] = {
        "polyglot_symbols": {},
        "test_import_map": {},
        "test_runner": "",
        "tests_failed": 0,
        "deterministic_hits": [],
        "evidence_store": [],
    }

    def _hash_for(fp: str) -> str:
        if fp not in file_hashes:
            file_hashes[fp] = _file_sha256_prefix(workspace_dir, fp)
        return file_hashes[fp]

    def _add_record(
        *,
        tool_name: str,
        rule_id: str | None,
        file_path: str,
        line_number: int | None,
        end_line: int | None,
        snippet: str,
        severity: str,
        extra_meta: dict[str, Any] | None = None,
    ) -> None:
        ev_id = f"EV-{len(records) + 1:03d}"
        rec = EvidenceRecord(
            evidence_id=ev_id,
            tool_name=tool_name,
            rule_id=rule_id,
            file_path=file_path,
            line_number=int(line_number) if isinstance(line_number, int) and line_number > 0 else None,
            end_line=int(end_line) if isinstance(end_line, int) and end_line > 0 else None,
            commit_sha=commit_sha,
            source_hash=_hash_for(file_path),
            snippet=snippet[:240],
            severity=str(severity or "Medium").title(),
        )
        records.append(rec)
        hit_summary = {
            "evidence_id": ev_id,
            "tool": rec.tool_name,
            "rule_id": rec.rule_id,
            "file_path": rec.file_path,
            "line_number": rec.line_number,
            "severity": rec.severity,
            **(extra_meta or {}),
        }
        extras["deterministic_hits"].append(hit_summary)

    for res in results:
        agent_name = _read_agent_value(res, "agent_name", "")
        tr = _read_agent_value(res, "tool_results") or {}
        if agent_name == "diff_agent":
            extras["polyglot_symbols"] = tr.get("polyglot_symbols") or tr.get("python_ast_symbols") or {}
            extras["ast_diff"] = tr.get("ast_diff") or {}
            for item in (tr.get("ast_diff") or {}).get("findings", []) or []:
                _add_record(
                    tool_name=str(item.get("tool") or "diff-ast-engine"),
                    rule_id=str(item.get("rule_id") or "DIFF-API-CONTRACT"),
                    file_path=str(item.get("file_path") or "").strip(),
                    line_number=item.get("line_number"),
                    end_line=None,
                    snippet=str(item.get("evidence") or item.get("title") or ""),
                    severity=str(item.get("severity") or "Medium"),
                )
        elif agent_name == "security_agent":
            for key in (
                "bandit",
                "semgrep",
                "gitleaks",
                "osv_scanner",
                "deterministic_guards",
                "taint_analysis",
                "codeql",
                "trivy",
            ):
                for item in (tr.get(key) or {}).get("findings", []) or []:
                    tname = str(
                        item.get("tool")
                        or (
                            "security-guard"
                            if key == "deterministic_guards"
                            else ("security-taint" if key == "taint_analysis" else key.replace("_", "-"))
                        )
                    )
                    fp = str(item.get("file_path") or "").strip()
                    _add_record(
                        tool_name=tname,
                        rule_id=str(item.get("rule_id")) if item.get("rule_id") else None,
                        file_path=fp,
                        line_number=item.get("line_number"),
                        end_line=item.get("end_line"),
                        snippet=str(item.get("evidence") or item.get("title") or ""),
                        severity=str(item.get("severity") or "Medium"),
                        extra_meta={
                            "title": item.get("title"),
                            "is_test_fixture": bool(item.get("is_test_fixture")),
                        },
                    )
        elif agent_name == "style_agent":
            for section in ("ruff", "eslint", "pylint", "dead_code", "ast_checks"):
                for item in (tr.get(section) or {}).get("findings", []) or []:
                    tname = str(item.get("tool") or section.replace("_", "-"))
                    fp = str(item.get("file_path") or "").strip()
                    _add_record(
                        tool_name=tname,
                        rule_id=str(item.get("rule_id")) if item.get("rule_id") else None,
                        file_path=fp,
                        line_number=item.get("line_number"),
                        end_line=item.get("end_line"),
                        snippet=str(item.get("message") or ""),
                        severity=str(item.get("severity") or "Low"),
                    )
        elif agent_name == "test_coverage_agent":
            extras["test_import_map"] = tr.get("test_import_map") or {}
            extras["test_runner"] = str(tr.get("runner") or "")
            extras["test_runner_status"] = str(tr.get("status") or "")
            extras["tests_failed"] = int(tr.get("failed") or 0)
            extras["test_telemetry"] = {
                "runner": extras["test_runner"],
                "status": extras["test_runner_status"],
                "failed": extras["tests_failed"],
            }
            src_map = (extras["test_import_map"] or {}).get("source_file_test_map") or {}
            for fp, info in src_map.items():
                cov_st = info.get("coverage_status")
                if cov_st in ("mocked_only_untested", "no_importing_tests_found"):
                    _add_record(
                        tool_name="test-mapper",
                        rule_id=f"TEST-{cov_st.upper()}",
                        file_path=fp,
                        line_number=1,
                        end_line=None,
                        snippet=f"Cross-file test import map status: {cov_st}",
                        severity="Low",
                    )
            for fp in tr.get("changed_file_coverage") or {}:
                cov_info = (tr.get("changed_file_coverage") or {}).get(fp) or {}
                missing = cov_info.get("missing_lines") or []
                first_missing = missing[0] if missing else 1
                _add_record(
                    tool_name="coverage.py",
                    rule_id="COVERAGE-GAP",
                    file_path=fp,
                    line_number=first_missing,
                    end_line=missing[-1] if missing else None,
                    snippet=f"Coverage: {cov_info.get('percent_covered', 0)}% (missing lines: {missing[:6]})",
                    severity="Medium",
                )
            if extras["tests_failed"] > 0:
                runner = extras["test_runner"] or "pytest"
                test_files = list(tr.get("test_files") or []) or [""]
                for tf in test_files[:8]:
                    _add_record(
                        tool_name=runner,
                        rule_id="TEST-SUITE-FAILED",
                        file_path=tf,
                        line_number=1 if tf else None,
                        end_line=None,
                        snippet=f"{runner} reported {extras['tests_failed']} failing test(s)",
                        severity="High",
                    )

    extras["evidence_store"] = [r.to_dict() for r in records]
    return records, extras


def _line_matches(
    claim_line: int | None,
    rec_start: int | None,
    rec_end: int | None,
    tolerance: int = 3,
) -> bool:
    if rec_start is None or claim_line is None:
        return True
    upper = rec_end if rec_end is not None and rec_end >= rec_start else rec_start
    return (rec_start - tolerance) <= claim_line <= (upper + tolerance)


def _rule_matches(claim_rule: str | None, rec_rule: str | None) -> bool:
    if not claim_rule or not rec_rule:
        return True
    c = claim_rule.strip().lower()
    r = rec_rule.strip().lower()
    return c == r or c in r or r in c


def _clamp_confidence(raw_conf: Any, default: float) -> float:
    try:
        val = float(raw_conf)
    except (TypeError, ValueError):
        return default
    return round(min(1.0, max(0.0, val)), 2)


_AGENT_KEY_BY_LABEL = {
    "Diff Agent": "diff_agent",
    "Style Agent": "style_agent",
    "Security Agent": "security_agent",
    "Test-Coverage Agent": "test_coverage_agent",
    "Reviewer Manager": "reviewer_manager",
    "Fix-Suggestion Agent": "fix_suggestion_agent",
}


def verify_finding_provenance(
    finding: dict[str, Any],
    evidence_store: list[EvidenceRecord],
    workspace_dir: Path,
    *,
    line_tolerance: int = 3,
    execution_telemetry: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bool]:
    """
    Independently verify a candidate finding against disk files + immutable EvidenceStore + permission boundaries.
    Returns `(normalized_finding, fabricated_or_unauthorized_claim)`.
    An LLM can never self-certify `Verified`: only exact `(file_path, tool/rule, line_range)` matches succeed.
    """
    out = dict(finding)
    raw_agent = str(out.get("agent") or "Reviewer Manager")
    agent_key = _AGENT_KEY_BY_LABEL.get(raw_agent, raw_agent.lower().replace(" ", "_"))
    out, perm_violations = enforce_agent_permissions(agent_key, out, execution_telemetry)

    fp = str(out.get("file_path") or "").strip()
    ln = out.get("line_number")
    line_int = int(ln) if isinstance(ln, int) and ln > 0 else None
    claimed_tool = str(out.get("tool_name") or "llm-review").strip()
    claimed_rule = str(out.get("rule_id") or "").strip() or None
    claimed_ev_ids = {str(x).strip() for x in (out.get("evidence_ids") or []) if str(x).strip()}

    exists, actual_line = verify_file_and_line(workspace_dir, fp, line_int)
    if not exists and fp:
        out["verification_status"] = "Unverified"
        out["evidence_ids"] = []
        out["confidence"] = _clamp_confidence(out.get("confidence"), 0.25)
        return out, bool(perm_violations or claimed_tool in DETERMINISTIC_TOOL_NAMES)

    if actual_line and not out.get("evidence"):
        out["evidence"] = actual_line

    if perm_violations:
        out["permission_violations"] = perm_violations
        out["confidence"] = _clamp_confidence(out.get("confidence"), 0.4)
        return out, True

    matched_records: list[EvidenceRecord] = []
    for rec in evidence_store:
        file_ok = rec.file_path == fp or (not fp and not rec.file_path)
        if not file_ok:
            continue
        if not _line_matches(line_int, rec.line_number, rec.end_line, tolerance=line_tolerance):
            continue
        id_match = bool(claimed_ev_ids and rec.evidence_id in claimed_ev_ids)
        tool_match = claimed_tool == rec.tool_name and _rule_matches(claimed_rule, rec.rule_id)
        if id_match or tool_match:
            matched_records.append(rec)

    if matched_records:
        primary = matched_records[0]
        out["verification_status"] = "Verified"
        out["evidence_ids"] = [r.evidence_id for r in matched_records[:5]]
        out["tool_name"] = primary.tool_name
        if not out.get("rule_id") and primary.rule_id:
            out["rule_id"] = primary.rule_id
        out["confidence"] = _clamp_confidence(out.get("confidence"), 0.95)
        return out, False

    fabricated = claimed_tool in DETERMINISTIC_TOOL_NAMES
    out["verification_status"] = "Needs Verification"
    out["evidence_ids"] = []
    if fabricated:
        out["tool_name"] = "llm-review"
    default_conf = 0.65 if claimed_tool in LLM_ONLY_TOOLS and exists else 0.45
    out["confidence"] = _clamp_confidence(out.get("confidence"), default_conf)
    return out, fabricated


def normalize_severity_with_criteria(finding: dict[str, Any]) -> str:
    """Consistent deterministic severity normalization across agents."""
    sev = str(finding.get("severity") or "Medium").strip().title()
    rule = str(finding.get("rule_id") or "").upper()
    tool = str(finding.get("tool_name") or "").lower()
    if finding.get("is_test_fixture"):
        return "Low"
    if rule in ("TAINT-SQL-INJECTION", "TAINT-CMD-INJECTION"):
        return "Critical"
    if rule in ("SYNTAX-ERROR", "SYNTAX-INVALID-SOURCE", "TAINT-PATH-TRAVERSAL", "CRYPTO-INSECURE-RANDOM"):
        return "High" if sev in ("Low", "Medium") else sev
    if tool == "dead-code-analyzer" and rule == "DEAD-UNUSED-PRIVATE-SYMBOL":
        return "Low"
    return sev if sev in ("Critical", "High", "Medium", "Low") else "Medium"


def detect_cross_agent_contradictions(
    findings: list[dict[str, Any]], extras: dict[str, Any]
) -> list[dict[str, Any]]:
    """Detect conflicting claims across specialists on the same file or test status."""
    contradictions: list[dict[str, Any]] = []
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        fp = str(f.get("file_path") or "").strip()
        if fp:
            by_file.setdefault(fp, []).append(f)

    for fp, items in by_file.items():
        if len(items) < 2:
            continue
        agents = {str(it.get("agent") or "") for it in items}
        texts = [f"{it.get('title', '')} {it.get('description', '')}".lower() for it in items]
        has_missing_cov = any("untested" in t or "no tests" in t for t in texts)
        tmap = ((extras.get("test_import_map") or {}).get("source_file_test_map") or {}).get(fp) or {}
        if has_missing_cov and tmap.get("has_any_unmocked_test"):
            contradictions.append(
                {
                    "file_path": fp,
                    "agents": sorted(agents),
                    "reason": f"Agent claimed `{fp}` has no tests, contradicting Test-Import Map ({tmap.get('coverage_status')}).",
                }
            )
    return contradictions


def check_finding_contradiction(finding: dict[str, Any], extras: dict[str, Any]) -> str | None:
    """Reject harness noise or claims directly contradicted by full-file facts / test-import maps."""
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

    fp = str(finding.get("file_path") or "").strip()
    if fp:
        tmap = ((extras.get("test_import_map") or {}).get("source_file_test_map") or {}).get(fp) or {}
        if (
            tmap.get("has_any_unmocked_test")
            and str(finding.get("tool_name") or "") in LLM_ONLY_TOOLS
            and ("no unit tests" in combined or "no tests found" in combined or "untested module" in combined)
        ):
            direct = ", ".join((tmap.get("direct_tests") or []) + (tmap.get("indirect_importing_tests") or []))
            return f"Contradicted by Cross-File Test-Import Map: `{fp}` is covered by {direct}."

        guards = ((extras.get("polyglot_symbols") or {}).get(fp) or {}).get("implemented_guards_in_full_file") or {}
        if (
            "url_parsing" in guards
            and "https_enforcement" in guards
            and ("missing https validation" in combined or "does not validate url protocol" in combined)
            and str(finding.get("tool_name") or "") in LLM_ONLY_TOOLS
        ):
            return f"Contradicted by full-file polyglot guard index: URL/HTTPS validation is implemented at line(s) {guards['https_enforcement']}."

    return None


def is_patch_eligible(finding: dict[str, Any], *, allow_unverified: bool = False) -> bool:
    """Strict default gate: only Verified, evidence-backed findings trigger patch synthesis."""
    ver = str(finding.get("verification_status") or "Needs Verification")
    if allow_unverified:
        return ver != "Unverified"
    return ver == "Verified" and bool(finding.get("evidence_ids"))
