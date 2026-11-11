from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from app.scanners.code_engines import (
    is_test_fixture_hit,
    prioritize_repo_files,
    run_deterministic_code_guards,
)
from app.scanners.tool_runner import resolve_binary, run_command_capture

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
    except Exception:
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
    except Exception:
        pass
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
    scan_targets = existing if existing else ["."]

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


async def run_security_scanners(
    workspace_dir: Path, changed_file_paths: list[str]
) -> dict[str, Any]:
    import asyncio

    bandit_res, semgrep_res, gitleaks_res, osv_res, guards_res = await asyncio.gather(
        run_bandit(workspace_dir, changed_file_paths),
        run_semgrep(workspace_dir, changed_file_paths),
        run_gitleaks(workspace_dir),
        run_osv_scanner(workspace_dir),
        run_deterministic_code_guards(workspace_dir, changed_file_paths),
    )
    return {
        "bandit": bandit_res,
        "semgrep": semgrep_res,
        "gitleaks": gitleaks_res,
        "osv_scanner": osv_res,
        "deterministic_guards": guards_res,
    }
