from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from app.cache.review_cache import (
    SCANNER_CACHE_SCHEMA_VERSION,
    ReviewCache,
    hash_files_content,
    hash_text,
)
from app.scanners.code_engines import (
    is_test_fixture_hit,
    prioritize_repo_files,
    run_deterministic_code_guards,
)
from app.scanners.security_taint import run_taint_and_threat_analysis
from app.scanners.tool_runner import get_tool_version, resolve_binary, run_command_capture

LOCAL_SEMGREP_RULES = Path(__file__).resolve().parent / "semgrep_rules.yml"


def _normalize_severity(raw: str | None) -> str:
    val = (raw or "Medium").strip().upper()
    if val in ("CRITICAL", "ERROR"):
        return "Critical" if val == "CRITICAL" else "High"
    if val in ("HIGH", "WARNING"):
        return "High" if val == "HIGH" else "Medium"
    if val in ("MEDIUM", "MODERATE"):
        return "Medium"
    return "Low"


def _rel_path(workspace_dir: Path, raw_path: str) -> str:
    try:
        return str(Path(raw_path).resolve().relative_to(workspace_dir.resolve()))
    except ValueError:
        return raw_path.lstrip("./")


def _read_source_snippet(workspace_dir: Path, rel_path: str, line_no: int | None) -> str:
    if not line_no or line_no < 1:
        return ""
    target = workspace_dir / rel_path
    if not target.exists() or not target.is_file():
        return ""
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        if line_no <= len(lines):
            return lines[line_no - 1].strip()
    except OSError:
        return ""
    return ""


async def run_bandit(workspace_dir: Path, targets: list[str]) -> dict[str, Any]:
    bandit_bin = resolve_binary("bandit")
    if not bandit_bin:
        return {"status": "tool_unavailable", "findings": [], "error": "bandit binary not found"}

    py_files = [
        t for t in targets if t.endswith(".py") and (workspace_dir / t).exists()
    ]
    cmd = [bandit_bin, "-f", "json", "-q"]
    if py_files:
        cmd.extend(py_files)
    else:
        cmd.extend(["-r", "."])

    res = await run_command_capture(cmd, cwd=workspace_dir, timeout=90)
    if res["timed_out"]:
        return {"status": "incomplete", "findings": [], "error": "bandit scan timed out"}
    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            errors = data.get("errors") or []
            if res["returncode"] not in (0, 1) and not data.get("results"):
                err_msg = "; ".join(str(e.get("message") or e) for e in errors) or res["stderr"]
                return {"status": "error", "findings": [], "error": err_msg[:500]}
            for item in data.get("results", []):
                rel = _rel_path(workspace_dir, item.get("filename", ""))
                line_no = item.get("line_number", 1)
                code_snippet = (item.get("code") or "").strip() or _read_source_snippet(workspace_dir, rel, line_no)
                findings.append(
                    {
                        "tool": "bandit",
                        "rule_id": item.get("test_id", "BANDIT"),
                        "title": item.get("test_name", "Bandit security finding").replace("_", " ").title(),
                        "file_path": rel,
                        "line_number": line_no,
                        "severity": _normalize_severity(item.get("issue_severity")),
                        "confidence": item.get("issue_confidence", "MEDIUM"),
                        "evidence": code_snippet or item.get("issue_text", ""),
                        "description": item.get("issue_text", ""),
                        "cwe": (item.get("issue_cwe") or {}).get("id"),
                    }
                )
            return {"status": "completed", "findings": findings, "error": ""}
        except json.JSONDecodeError as exc:
            return {"status": "error", "findings": [], "error": f"Failed parsing bandit JSON: {exc}"}
    if res["returncode"] in (0, 1):
        return {"status": "completed", "findings": [], "error": ""}
    return {"status": "error", "findings": [], "error": res["stderr"][:500]}


async def run_semgrep(workspace_dir: Path, targets: list[str]) -> dict[str, Any]:
    semgrep_bin = resolve_binary("semgrep")
    if not semgrep_bin:
        return {"status": "tool_unavailable", "findings": [], "error": "semgrep binary not found"}

    existing = prioritize_repo_files(
        [t for t in targets if (workspace_dir / t).exists() and (workspace_dir / t).is_file()]
    )[:80]
    scan_targets = existing or ["."]

    cmd = [
        semgrep_bin,
        "scan",
        "--config",
        str(LOCAL_SEMGREP_RULES),
        "--json",
        "--quiet",
        "--no-git-ignore",
        *scan_targets,
    ]
    res = await run_command_capture(cmd, cwd=workspace_dir, timeout=120)
    if res["timed_out"]:
        return {"status": "incomplete", "findings": [], "error": "semgrep scan timed out"}

    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            errors = data.get("errors") or []
            if res["returncode"] not in (0, 1) and not data.get("results"):
                err_msg = "; ".join(str(e.get("message") or e) for e in errors) or res["stderr"]
                return {"status": "error", "findings": [], "error": err_msg[:500]}
            for item in data.get("results", []):
                extra = item.get("extra") or {}
                meta = extra.get("metadata") or {}
                sev_raw = extra.get("severity") or meta.get("impact") or "MEDIUM"
                rule_id_full = item.get("check_id", "semgrep-rule")
                short_rule = rule_id_full.split(".")[-1]
                if str(sev_raw).upper() == "ERROR" and (
                    "sql" in short_rule.lower()
                    or "command" in short_rule.lower()
                    or "secret" in short_rule.lower()
                    or "credential" in short_rule.lower()
                    or "deserialization" in short_rule.lower()
                ):
                    sev = "Critical" if "credential" in short_rule.lower() or "sql" in short_rule.lower() else "High"
                else:
                    sev = _normalize_severity(sev_raw)
                rel = _rel_path(workspace_dir, item.get("path", ""))
                start_line = (item.get("start") or {}).get("line", 1)
                raw_lines = extra.get("lines") or ""
                if not raw_lines or raw_lines.strip() == "requires login":
                    raw_lines = _read_source_snippet(workspace_dir, rel, start_line)
                findings.append(
                    {
                        "tool": "semgrep",
                        "rule_id": short_rule,
                        "title": short_rule.replace("-", " ").replace("_", " ").title()
                        or "Semgrep Security Pattern",
                        "file_path": rel,
                        "line_number": start_line,
                        "end_line": (item.get("end") or {}).get("line"),
                        "severity": sev,
                        "evidence": (raw_lines or extra.get("message") or "").strip(),
                        "description": extra.get("message", ""),
                    }
                )
            return {"status": "completed", "findings": findings, "error": ""}
        except json.JSONDecodeError as exc:
            return {"status": "error", "findings": [], "error": f"Failed parsing semgrep JSON: {exc}"}
    if res["returncode"] in (0, 1):
        return {"status": "completed", "findings": [], "error": ""}
    return {"status": "incomplete", "findings": [], "error": (res["stderr"] or "semgrep failed")[:500]}


async def run_gitleaks(workspace_dir: Path) -> dict[str, Any]:
    gitleaks_bin = resolve_binary("gitleaks")
    if not gitleaks_bin:
        return {"status": "tool_unavailable", "findings": [], "error": "gitleaks binary not found"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report_path = Path(tf.name)
    try:
        cmd = [
            gitleaks_bin,
            "detect",
            "--source",
            str(workspace_dir),
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            "--redact",
        ]
        res = await run_command_capture(cmd, cwd=workspace_dir, timeout=60)
        if res["timed_out"]:
            return {"status": "incomplete", "findings": [], "error": "gitleaks scan timed out"}
        findings: list[dict[str, Any]] = []
        if report_path.exists() and report_path.stat().st_size > 0:
            raw = report_path.read_text(encoding="utf-8", errors="replace").strip()
            if raw and raw != "null":
                items = json.loads(raw)
                for item in items:
                    rel_fp = _rel_path(workspace_dir, item.get("File", ""))
                    line_no = item.get("StartLine", 1)
                    ev = f"Rule {item.get('RuleID')} matched redacted secret: {item.get('Match', '[REDACTED]')}"
                    fixture_hit = is_test_fixture_hit(workspace_dir, rel_fp, line_no, ev)
                    desc = item.get("Description", "Hardcoded credential or token detected in source file.")
                    if fixture_hit:
                        desc = f"{desc} Appears to be a synthetic test fixture inside a test file."
                    findings.append(
                        {
                            "tool": "gitleaks",
                            "rule_id": item.get("RuleID", "gitleaks-secret"),
                            "title": (
                                f"Synthetic Test Secret in Test Fixture ({item.get('Description') or item.get('RuleID')})"
                                if fixture_hit
                                else f"Hardcoded Secret Detected ({item.get('Description') or item.get('RuleID')})"
                            ),
                            "file_path": rel_fp,
                            "line_number": line_no,
                            "end_line": item.get("EndLine"),
                            "severity": "Low" if fixture_hit else "Critical",
                            "is_test_fixture": fixture_hit,
                            "evidence": ev,
                            "description": desc,
                        }
                    )
        if res["returncode"] in (0, 1):
            return {"status": "completed", "findings": findings, "error": ""}
        return {"status": "error", "findings": findings, "error": res["stderr"][:500]}
    finally:
        report_path.unlink(missing_ok=True)


async def run_osv_scanner(workspace_dir: Path) -> dict[str, Any]:
    osv_bin = resolve_binary("osv-scanner")
    if not osv_bin:
        return {"status": "tool_unavailable", "findings": [], "error": "osv-scanner binary not found"}

    manifests = [
        p
        for p in workspace_dir.rglob("*")
        if p.is_file()
        and p.name
        in {
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "Pipfile.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.mod",
            "Cargo.lock",
        }
        and ".git" not in p.parts
    ]
    if not manifests:
        return {"status": "completed", "findings": [], "error": "", "note": "No dependency lockfiles or manifests found"}

    cmd = [osv_bin, "scan", "--format", "json", "-r", str(workspace_dir)]
    res = await run_command_capture(cmd, cwd=workspace_dir, timeout=90)
    if res["timed_out"]:
        return {"status": "incomplete", "findings": [], "error": "osv-scanner scan timed out"}
    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            for result in data.get("results", []):
                source_path = _rel_path(workspace_dir, (result.get("source") or {}).get("path", "requirements.txt"))
                for pkg in result.get("packages", []):
                    pkg_info = pkg.get("package") or {}
                    pkg_name = pkg_info.get("name", "unknown")
                    pkg_ver = pkg_info.get("version", "")
                    for vuln in pkg.get("vulnerabilities", []):
                        vuln_id = vuln.get("id", "OSV")
                        summary = vuln.get("summary") or vuln.get("details", "")[:240]
                        findings.append(
                            {
                                "tool": "osv-scanner",
                                "rule_id": vuln_id,
                                "title": f"Vulnerable Dependency: {pkg_name}=={pkg_ver} ({vuln_id})",
                                "file_path": source_path,
                                "line_number": 1,
                                "severity": "High",
                                "evidence": f"Package {pkg_name} ({pkg_ver}) affected by {vuln_id}: {summary}",
                                "description": summary,
                            }
                        )
            return {"status": "completed", "findings": findings, "error": ""}
        except json.JSONDecodeError:
            pass
    if res["returncode"] in (0, 1, 128):
        return {"status": "completed", "findings": findings, "error": ""}
    return {"status": "incomplete", "findings": findings, "error": res["stderr"][:500]}


async def run_trivy(workspace_dir: Path) -> dict[str, Any]:
    """Optional Trivy filesystem vulnerability & misconfiguration scanner."""
    trivy_bin = resolve_binary("trivy")
    if not trivy_bin:
        return {"status": "optional_unavailable", "findings": [], "error": ""}
    res = await run_command_capture(
        [trivy_bin, "fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig", str(workspace_dir)],
        cwd=workspace_dir,
        timeout=90,
    )
    if res["timed_out"]:
        return {"status": "incomplete", "findings": [], "error": "trivy scan timed out"}
    findings: list[dict[str, Any]] = []
    if res["stdout"].strip():
        try:
            data = json.loads(res["stdout"])
            for result in data.get("Results", []) or []:
                target_file = _rel_path(workspace_dir, str(result.get("Target") or "requirements.txt"))
                for vuln in result.get("Vulnerabilities", []) or []:
                    findings.append(
                        {
                            "tool": "trivy",
                            "rule_id": vuln.get("VulnerabilityID", "TRIVY-VULN"),
                            "title": f"Trivy CVE: {vuln.get('PkgName')} ({vuln.get('VulnerabilityID')})",
                            "file_path": target_file,
                            "line_number": 1,
                            "severity": _normalize_severity(vuln.get("Severity")),
                            "evidence": str(vuln.get("Title") or vuln.get("Description") or "")[:240],
                            "description": str(vuln.get("Description") or "")[:300],
                        }
                    )
                for mis in result.get("Misconfigurations", []) or []:
                    findings.append(
                        {
                            "tool": "trivy",
                            "rule_id": mis.get("ID", "TRIVY-MISCONFIG"),
                            "title": str(mis.get("Title") or "Trivy Misconfiguration"),
                            "file_path": target_file,
                            "line_number": (mis.get("CauseMetadata") or {}).get("StartLine") or 1,
                            "severity": _normalize_severity(mis.get("Severity")),
                            "evidence": str(mis.get("Message") or "")[:240],
                            "description": str(mis.get("Description") or "")[:300],
                        }
                    )
            return {"status": "completed", "findings": findings[:40], "error": ""}
        except json.JSONDecodeError:
            pass
    if res["returncode"] in (0, 1):
        return {"status": "completed", "findings": findings, "error": ""}
    return {"status": "optional_unavailable", "findings": [], "error": res["stderr"][:300]}


async def run_codeql(workspace_dir: Path, targets: list[str]) -> dict[str, Any]:
    """Optional CodeQL SARIF analyzer when `codeql` CLI and language packs are installed."""
    codeql_bin = resolve_binary("codeql")
    if not codeql_bin:
        return {"status": "optional_unavailable", "findings": [], "error": ""}
    py_present = any(t.endswith(".py") for t in targets)
    js_present = any(t.endswith((".ts", ".tsx", ".js", ".jsx")) for t in targets)
    lang = "python" if py_present else ("javascript" if js_present else "")
    if not lang:
        return {"status": "skipped_no_supported_files", "findings": [], "error": ""}

    with tempfile.TemporaryDirectory(prefix="swarm_codeql_") as tmp_dir:
        db_dir = Path(tmp_dir) / "db"
        sarif_path = Path(tmp_dir) / "out.sarif"
        create_res = await run_command_capture(
            [codeql_bin, "database", "create", str(db_dir), f"--language={lang}", f"--source-root={workspace_dir}"],
            cwd=workspace_dir,
            timeout=120,
        )
        if create_res["returncode"] != 0:
            return {"status": "optional_unavailable", "findings": [], "error": create_res["stderr"][:300]}
        analyze_res = await run_command_capture(
            [codeql_bin, "database", "analyze", str(db_dir), "--format=sarif-latest", f"--output={sarif_path}"],
            cwd=workspace_dir,
            timeout=120,
        )
        if analyze_res["returncode"] != 0 or not sarif_path.exists():
            return {"status": "optional_unavailable", "findings": [], "error": analyze_res["stderr"][:300]}
        findings: list[dict[str, Any]] = []
        try:
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            for run in sarif.get("runs", []) or []:
                for r in run.get("results", []) or []:
                    locs = r.get("locations") or []
                    phys = (locs[0].get("physicalLocation") or {}) if locs else {}
                    uri = ((phys.get("artifactLocation") or {}).get("uri") or "").lstrip("./")
                    start_line = (phys.get("region") or {}).get("startLine") or 1
                    findings.append(
                        {
                            "tool": "codeql",
                            "rule_id": r.get("ruleId", "CODEQL"),
                            "title": f"CodeQL: {r.get('ruleId', 'Finding')}",
                            "file_path": _rel_path(workspace_dir, uri),
                            "line_number": start_line,
                            "severity": "High" if r.get("level") == "error" else "Medium",
                            "evidence": ((r.get("message") or {}).get("text") or "")[:240],
                            "description": ((r.get("message") or {}).get("text") or "")[:300],
                        }
                    )
        except (OSError, json.JSONDecodeError):
            return {"status": "optional_unavailable", "findings": [], "error": "Failed to parse CodeQL SARIF"}
        return {"status": "completed", "findings": findings[:40], "error": ""}


async def _skipped_by_plan_result(note: str) -> dict[str, Any]:
    return {"status": "skipped_by_plan", "findings": [], "error": "", "note": note}


async def run_security_scanners(
    workspace_dir: Path,
    changed_file_paths: list[str],
    *,
    cache: ReviewCache | None = None,
    commit_context: str = "HEAD",
    config_hash: str = "default",
    plan: dict[str, Any] | None = None,
    structure_index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    import asyncio

    if plan and plan.get("skip_scanners"):
        note = "Skipped by ReviewPlanner (low-risk/docs-only change)"
        skipped = await _skipped_by_plan_result(note)
        return {
            "bandit": dict(skipped),
            "semgrep": dict(skipped),
            "gitleaks": dict(skipped),
            "osv_scanner": dict(skipped),
            "deterministic_guards": dict(skipped),
            "taint_analysis": dict(skipped),
            "codeql": dict(skipped),
            "trivy": dict(skipped),
            "cache_hit": False,
        }

    manifest_names = {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "Cargo.lock",
    }
    cache_targets = list(changed_file_paths)
    for mname in manifest_names:
        if (workspace_dir / mname).is_file() and mname not in cache_targets:
            cache_targets.append(mname)

    content_hash = ""
    tool_version = ""
    if cache is not None and cache_targets:
        content_hash = hash_files_content(workspace_dir, cache_targets)
        vb, vs, vg, vo, vt, vc = await asyncio.gather(
            get_tool_version("bandit"),
            get_tool_version("semgrep"),
            get_tool_version("gitleaks", ("version",)),
            get_tool_version("osv-scanner"),
            get_tool_version("trivy"),
            get_tool_version("codeql"),
        )
        rules_digest = (
            hash_text(LOCAL_SEMGREP_RULES.read_text(encoding="utf-8", errors="replace"))[:12]
            if LOCAL_SEMGREP_RULES.exists()
            else "norules"
        )
        plan_flags = hash_text(json.dumps(plan or {}, sort_keys=True, default=str))[:12]
        tool_version = (
            f"{SCANNER_CACHE_SCHEMA_VERSION}|b={vb}|s={vs}|g={vg}|o={vo}|t={vt}|c={vc}|r={rules_digest}|p={plan_flags}"
        )
        cached = cache.get(
            "security_scanners",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=config_hash or "default",
            commit_context=commit_context,
        )
        if isinstance(cached, dict):
            return {**cached, "cache_hit": True}

    run_bandit_flag = plan.get("run_bandit", True) if plan else True
    run_semgrep_flag = plan.get("run_semgrep", True) if plan else True
    run_gitleaks_flag = plan.get("run_gitleaks", True) if plan else True
    run_osv_flag = plan.get("run_osv", True) if plan else True
    run_taint_flag = plan.get("run_taint", True) if plan else True
    run_codeql_flag = plan.get("run_codeql", False) if plan else False
    run_trivy_flag = plan.get("run_trivy", False) if plan else False

    bandit_res, semgrep_res, gitleaks_res, osv_res, guards_res, codeql_res, trivy_res = await asyncio.gather(
        run_bandit(workspace_dir, changed_file_paths)
        if run_bandit_flag
        else _skipped_by_plan_result("No Python changes in diff"),
        run_semgrep(workspace_dir, changed_file_paths)
        if run_semgrep_flag
        else _skipped_by_plan_result("Skipped by ReviewPlanner"),
        run_gitleaks(workspace_dir)
        if run_gitleaks_flag
        else _skipped_by_plan_result("Skipped by ReviewPlanner"),
        run_osv_scanner(workspace_dir)
        if run_osv_flag
        else _skipped_by_plan_result("Skipped by ReviewPlanner"),
        run_deterministic_code_guards(workspace_dir, changed_file_paths),
        run_codeql(workspace_dir, changed_file_paths)
        if run_codeql_flag
        else _skipped_by_plan_result("Skipped for medium/low risk plan"),
        run_trivy(workspace_dir)
        if run_trivy_flag
        else _skipped_by_plan_result("Skipped when no dependency/high-risk trigger"),
    )
    taint_res = (
        run_taint_and_threat_analysis(workspace_dir, changed_file_paths, structure_index=structure_index)
        if run_taint_flag
        else {"status": "skipped_by_plan", "findings": [], "threat_surfaces": [], "error": ""}
    )
    payload = {
        "bandit": bandit_res,
        "semgrep": semgrep_res,
        "gitleaks": gitleaks_res,
        "osv_scanner": osv_res,
        "deterministic_guards": guards_res,
        "taint_analysis": taint_res,
        "codeql": codeql_res,
        "trivy": trivy_res,
    }
    cacheable_statuses = {
        "completed",
        "skipped_by_plan",
        "tool_unavailable",
        "optional_unavailable",
        "skipped_no_supported_files",
    }
    all_clean = all(
        str(v.get("status", "")) in cacheable_statuses
        for v in payload.values()
        if isinstance(v, dict)
    )
    if cache is not None and cache_targets and all_clean:
        cache.set(
            "security_scanners",
            content_hash=content_hash,
            tool_version=tool_version,
            configuration_hash=config_hash or "default",
            commit_context=commit_context,
            value=payload,
        )
    return {**payload, "cache_hit": False}
