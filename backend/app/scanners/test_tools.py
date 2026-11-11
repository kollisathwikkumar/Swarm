from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from app.scanners.code_engines import is_test_file_path, prioritize_repo_files
from app.scanners.tool_runner import (
    resolve_binary,
    run_command_capture,
    sanitized_subprocess_env,
)


def _resolve_ts_import(test_rel: str, spec: str, repo_files: set[str]) -> str | None:
    """Resolve a relative TS/JS import or test stem inside workspace_dir without requiring node_modules."""
    if not spec.startswith("."):
        return None
    base_dir = Path(test_rel).parent
    raw = (base_dir / spec).as_posix()
    # Normalize '..' segments cleanly
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    norm = "/".join(parts)
    for ext in ("", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js"):
        cand = norm + ext
        if cand in repo_files:
            return cand
    return None


def _extract_test_case_names(src: str, is_python: bool) -> dict[str, Any]:
    cases: list[str] = []
    skips: list[str] = []
    if is_python:
        cases = re.findall(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\s*\(", src, re.MULTILINE)
        skips = re.findall(r"@pytest\.mark\.skip(?:if)?\(([^\n)]{1,120})\)", src)
    else:
        for pat in (
            r"\b(?:it|test)(?:\.(?:only|skip|todo|skipIf\([^)]*\)))?\(\s*(['\"`])(.+?)\1",
        ):
            for _, title in re.findall(pat, src):
                cases.append(title.strip()[:120])
        for cond in re.findall(r"\bdescribe\.skipIf\(\s*([^)]+)\)", src):
            skips.append(f"describe.skipIf({cond.strip()[:120]})")
        for cond in re.findall(r"\b(?:it|test)\.skipIf\(\s*([^)]+)\)", src):
            skips.append(f"test.skipIf({cond.strip()[:120]})")
    return {"test_cases": cases[:40], "platform_or_conditional_skips": skips[:10]}


def build_test_coverage_map(
    workspace_dir: Path,
    changed_file_paths: list[str],
    discovered: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """
    Static Cross-File Test-Import & Case Coverage Engine.
    Maps every test file in the entire repository (direct + indirect imports vs vi.mock-only)
    and extracts real test case titles & conditional skips so agents never misclaim missing tests.
    """
    discovered = discovered or discover_test_files(workspace_dir)
    all_tests = discovered["python"] + discovered["js_ts"]

    repo_files: set[str] = set()
    for p in workspace_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in (".git", ".venv", "node_modules", ".next", "dist") for part in p.parts):
            continue
        repo_files.add(str(p.relative_to(workspace_dir)).replace("\\", "/"))

    direct_by_target: dict[str, list[str]] = {}
    indirect_by_target: dict[str, list[str]] = {}
    mocked_by_target: dict[str, list[str]] = {}
    test_suites: dict[str, dict[str, Any]] = {}

    import_re = re.compile(r"""(?:from\s+|import\s*\(\s*|require\s*\(\s*)(['"])(\.[^'"]+)\1""")
    mock_re = re.compile(r"""(?:vi|jest)\.mock\s*\(\s*(['"])(\.[^'"]+)\1""")
    py_from_re = re.compile(r"^\s*from\s+([A-Za-z0-9_.]+)\s+import\b", re.MULTILINE)
    py_imp_re = re.compile(r"^\s*import\s+([A-Za-z0-9_.]+)", re.MULTILINE)

    for test_rel in all_tests:
        tp = workspace_dir / test_rel
        if not tp.exists() or tp.stat().st_size > 200_000:
            continue
        src = tp.read_text(encoding="utf-8", errors="replace")
        is_py = test_rel.endswith(".py")
        summary = _extract_test_case_names(src, is_py)

        mocked_targets: set[str] = set()
        imported_targets: set[str] = set()

        if is_py:
            mods = set(py_from_re.findall(src)) | set(py_imp_re.findall(src))
            for mod in mods:
                rel_guess = mod.replace(".", "/") + ".py"
                if rel_guess in repo_files:
                    imported_targets.add(rel_guess)
                # Also match suffix if test imports from package root
                for rf in repo_files:
                    if rf.endswith("/" + rel_guess) or rf == rel_guess:
                        imported_targets.add(rf)
        else:
            for _, spec in mock_re.findall(src):
                resolved = _resolve_ts_import(test_rel, spec, repo_files)
                if resolved:
                    mocked_targets.add(resolved)
            for _, spec in import_re.findall(src):
                resolved = _resolve_ts_import(test_rel, spec, repo_files)
                if resolved and resolved not in mocked_targets and not is_test_file_path(resolved):
                    imported_targets.add(resolved)

        for target in sorted(mocked_targets):
            mocked_by_target.setdefault(target, []).append(test_rel)
        for target in sorted(imported_targets):
            target_stem = Path(target).stem
            test_name = Path(test_rel).name
            if (
                Path(test_rel).parent == Path(target).parent
                and (
                    test_name.startswith(f"{target_stem}.")
                    or test_name == f"test_{target_stem}.py"
                    or test_name == f"{target_stem}_test.py"
                )
            ):
                direct_by_target.setdefault(target, []).append(test_rel)
            else:
                indirect_by_target.setdefault(target, []).append(test_rel)

        # Keep metadata if this test is among changed files or directly tests one
        if test_rel in changed_file_paths or any(t in changed_file_paths for t in imported_targets):
            test_suites[test_rel] = {
                "test_cases_count": len(summary["test_cases"]),
                "test_cases": summary["test_cases"][:25],
                "skips": summary["platform_or_conditional_skips"],
                "imports_targets": sorted(imported_targets)[:12],
                "mocks_targets": sorted(mocked_targets)[:12],
            }

    source_map: dict[str, dict[str, Any]] = {}
    targets = [
        p
        for p in prioritize_repo_files(changed_file_paths)
        if not is_test_file_path(p) and not p.endswith((".json", ".yml", ".yaml", ".md"))
    ][:40]

    for rel in targets:
        direct = sorted(set(direct_by_target.get(rel, [])))
        indirect = sorted(set(indirect_by_target.get(rel, [])))
        mocked_only = sorted(set(mocked_by_target.get(rel, [])) - set(direct) - set(indirect))
        if direct and indirect:
            cov_status = "direct_and_indirect"
        elif direct:
            cov_status = "direct_tests_present"
        elif indirect:
            cov_status = "indirect_tests_present"
        elif mocked_only:
            cov_status = "mocked_only_untested"
        else:
            cov_status = "no_importing_tests_found"

        source_map[rel] = {
            "direct_tests": direct,
            "indirect_importing_tests": indirect,
            "mocked_only_in_tests": mocked_only,
            "has_any_unmocked_test": bool(direct or indirect),
            "coverage_status": cov_status,
        }

    return {
        "source_file_test_map": source_map,
        "test_suites": dict(list(test_suites.items())[:20]),
    }


def discover_test_files(workspace_dir: Path) -> dict[str, list[str]]:
    py_tests: list[str] = []
    js_tests: list[str] = []
    for p in workspace_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(part in (".git", ".venv", "node_modules", ".next", "dist") for part in p.parts):
            continue
        name = p.name
        rel = str(p.relative_to(workspace_dir))
        if name.endswith(".py") and (
            name.startswith("test_") or name.endswith("_test.py") or "tests" in p.parts
        ):
            py_tests.append(rel)
        elif name.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".test.js", ".spec.js")):
            js_tests.append(rel)
    return {"python": sorted(py_tests), "js_ts": sorted(js_tests)}


async def run_test_and_coverage(
    workspace_dir: Path,
    changed_file_paths: list[str],
    *,
    enable_execution: bool = True,
) -> dict[str, Any]:
    discovered = discover_test_files(workspace_dir)
    py_tests = discovered["python"]
    js_tests = discovered["js_ts"]
    coverage_map = build_test_coverage_map(workspace_dir, changed_file_paths, discovered)

    if not enable_execution:
        return {
            "status": "skipped_by_policy",
            "runner": "disabled",
            "tests_found": len(py_tests) + len(js_tests),
            "test_files": py_tests + js_tests,
            "js_test_files": js_tests,
            "test_import_map": coverage_map,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "total_coverage_percent": None,
            "file_coverage": {},
            "output": "Test execution disabled by review policy.",
        }

    # Try runnable Vitest suite when repo has JS/TS tests and local node_modules Vitest binary
    if not py_tests:
        local_vitest = workspace_dir / "node_modules" / ".bin" / "vitest"
        if js_tests and local_vitest.exists():
            run_res = await run_command_capture(
                [str(local_vitest), "run"],
                cwd=workspace_dir,
                timeout=90,
                env=sanitized_subprocess_env(),
            )
            combined = (run_res["stdout"] + "\n" + run_res["stderr"]).strip()
            passed = failed = skipped = 0
            m_pass = re.search(r"Tests\s+[^\n]*?(\d+)\s+passed", combined)
            m_fail = re.search(r"Tests\s+[^\n]*?(\d+)\s+failed", combined)
            m_file_fail = re.search(r"Test Files\s+[^\n]*?(\d+)\s+failed", combined)
            m_errors = re.search(r"Errors\s+(\d+)\s+error", combined)
            m_skip = re.search(r"Tests\s+[^\n]*?(\d+)\s+skipped", combined)
            if m_pass:
                passed = int(m_pass.group(1))
            failed_tests = int(m_fail.group(1)) if m_fail else 0
            failed_files = int(m_file_fail.group(1)) if m_file_fail else 0
            err_count = int(m_errors.group(1)) if m_errors else 0
            failed = (failed_tests if failed_tests > 0 else failed_files) + err_count
            if m_skip:
                skipped = int(m_skip.group(1))
            if run_res["returncode"] not in (0, 124) and failed == 0:
                failed = 1
            return {
                "status": "incomplete" if run_res["returncode"] == 124 else "completed",
                "error": "Vitest execution timed out" if run_res["returncode"] == 124 else None,
                "runner": "vitest",
                "returncode": run_res["returncode"],
                "tests_found": len(js_tests),
                "test_files": js_tests,
                "python_test_files": [],
                "js_test_files": js_tests,
                "test_import_map": coverage_map,
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "total_coverage_percent": None,
                "file_coverage": {},
                "output": combined[-4000:],
            }

        return {
            "status": "completed",
            "runner": "static_js_ts_inspection" if js_tests else "none",
            "tests_found": len(js_tests),
            "test_files": js_tests,
            "python_test_files": [],
            "js_test_files": js_tests,
            "test_import_map": coverage_map,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "total_coverage_percent": None,
            "file_coverage": {},
            "output": (
                f"Discovered {len(js_tests)} JS/TS test file(s); runtime Vitest execution skipped because package dependencies/runner are not installed in workspace snapshot. Static cross-file test-import mapping completed cleanly."
                if js_tests
                else "No automated test files discovered in repository."
            ),
        }

    coverage_bin = resolve_binary("coverage")
    pytest_bin = resolve_binary("pytest")
    if not pytest_bin:
        return {
            "status": "tool_unavailable",
            "tests_found": len(py_tests),
            "test_files": py_tests,
            "error": "pytest binary not found",
        }

    env = sanitized_subprocess_env()
    env["PYTHONPATH"] = str(workspace_dir)

    cov_json_path = workspace_dir / ".rb_coverage.json"
    if coverage_bin:
        run_res = await run_command_capture(
            [coverage_bin, "run", "--source=.", "-m", "pytest", "-v", "--tb=short"],
            cwd=workspace_dir,
            timeout=90,
            env=env,
        )
        await run_command_capture(
            [coverage_bin, "json", "-o", str(cov_json_path)],
            cwd=workspace_dir,
            timeout=30,
            env=env,
        )
    else:
        run_res = await run_command_capture(
            [pytest_bin, "-v", "--tb=short"],
            cwd=workspace_dir,
            timeout=90,
            env=env,
        )

    stdout = run_res["stdout"]
    stderr = run_res["stderr"]
    combined = (stdout + "\n" + stderr).strip()

    passed = failed = skipped = errors = 0
    for pat, target in [
        (r"(\d+)\s+passed", "passed"),
        (r"(\d+)\s+failed", "failed"),
        (r"(\d+)\s+skipped", "skipped"),
        (r"(\d+)\s+error", "errors"),
    ]:
        m = re.search(pat, combined)
        if m:
            if target == "passed":
                passed = int(m.group(1))
            elif target == "failed":
                failed = int(m.group(1))
            elif target == "skipped":
                skipped = int(m.group(1))
            else:
                errors = int(m.group(1))

    file_coverage: dict[str, dict[str, Any]] = {}
    total_cov: float | None = None
    if cov_json_path.exists():
        try:
            cov_data = json.loads(cov_json_path.read_text(encoding="utf-8"))
            total_cov = round(float((cov_data.get("totals") or {}).get("percent_covered", 0.0)), 2)
            for fname, info in (cov_data.get("files") or {}).items():
                norm = fname.lstrip("./")
                summary = info.get("summary") or {}
                file_coverage[norm] = {
                    "percent_covered": round(float(summary.get("percent_covered", 0.0)), 2),
                    "covered_lines": len(info.get("executed_lines", [])),
                    "missing_lines": info.get("missing_lines", [])[:40],
                }
        except (OSError, json.JSONDecodeError, ValueError):
            file_coverage = {}
        finally:
            cov_json_path.unlink(missing_ok=True)
            (workspace_dir / ".coverage").unlink(missing_ok=True)

    changed_cov = {
        path: file_coverage.get(path)
        for path in changed_file_paths
        if path.endswith(".py") and path in file_coverage
    }

    rc = run_res["returncode"]
    status = "completed"
    err_msg: str | None = None
    if rc == 124 or run_res.get("timed_out"):
        status = "incomplete"
        err_msg = "pytest execution timed out"
    elif rc in (2, 3, 4) and passed == 0 and failed == 0:
        status = "incomplete"
        err_msg = combined[-300:] or f"pytest exited with code {rc} during test collection/execution"

    return {
        "status": status,
        "error": err_msg,
        "runner": "pytest",
        "returncode": rc,
        "tests_found": len(py_tests) + len(js_tests),
        "test_files": py_tests + js_tests,
        "js_test_files": js_tests,
        "test_import_map": coverage_map,
        "passed": passed,
        "failed": failed + errors,
        "skipped": skipped,
        "total_coverage_percent": total_cov,
        "changed_file_coverage": changed_cov,
        "file_coverage": file_coverage,
        "output": combined[-4000:],
    }
