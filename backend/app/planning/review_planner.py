from __future__ import annotations

import re
from typing import Any

from app.intelligence.context_builder import AGENT_TOKEN_BUDGETS
from app.skills.permissions import AGENT_CAPABILITY_REGISTRY

_DOC_EXTENSIONS = (".md", ".mdx", ".txt", ".rst", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".license")
_PYTHON_EXTENSIONS = (".py", ".pyi")
_JS_TS_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
}
_AUTH_PATH_RE = re.compile(
    r"(auth|login|oauth|token|jwt|session|secret|crypto|security|perm|rbac|admin|middleware|webhook|sql|db|api/|routes/)",
    re.IGNORECASE,
)
_HIGH_RISK_DIFF_RE = re.compile(
    r"(eval\s*\(|exec\s*\(|subprocess|shell\s*=\s*True|dangerouslySetInnerHTML|"
    r"SELECT\s+.*FROM|jwt|oauth|api[_-]?key|secret|password|chmod|CORS)",
    re.IGNORECASE,
)


def _is_doc_or_asset(path: str) -> bool:
    lower = path.lower().strip()
    if lower.endswith(_DOC_EXTENSIONS):
        return True
    return lower.startswith("docs/") and not lower.endswith((".py", ".ts", ".js", ".tsx", ".jsx"))


def build_review_plan(
    *,
    changed_files: list[dict[str, Any]],
    structure_index: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    diff_text: str = "",
) -> dict[str, Any]:
    """
    Central Review Planning Engine (P3):
      - Classifies change risk tier (`high`, `medium`, `low`) with explicit rationales.
      - Selects applicable languages/scanners (never failing docs-only diffs as Incomplete).
      - Emits focused skills and per-agent token budgets prior to Fan-Out.
    """
    changed_paths = [str(c.get("path") or "").strip() for c in changed_files if c.get("path")]
    docs_only = bool(changed_paths) and all(_is_doc_or_asset(p) for p in changed_paths)
    has_python = any(p.lower().endswith(_PYTHON_EXTENSIONS) for p in changed_paths)
    has_js_ts = any(p.lower().endswith(_JS_TS_EXTENSIONS) for p in changed_paths)
    touches_deps = any(p.split("/")[-1] in _DEPENDENCY_FILES for p in changed_paths)
    touches_auth_or_api = any(_AUTH_PATH_RE.search(p) for p in changed_paths)
    has_risky_diff_pattern = bool(_HIGH_RISK_DIFF_RE.search(diff_text or ""))

    total_churn = sum(
        int(c.get("additions") or 0) + int(c.get("deletions") or 0)
        for c in changed_files
    )

    graphs = (structure_index or {}).get("graphs") or {}
    imported_by = graphs.get("imported_by") or {}
    downstream_consumers = sum(len(imported_by.get(p, [])) for p in changed_paths)

    risk_reasons: list[str] = []
    risk_score = 0
    if docs_only:
        risk_reasons.append("Changed files are documentation or static assets only")
    else:
        if touches_auth_or_api:
            risk_score += 3
            risk_reasons.append("Modifies authentication, security, routing, or database paths")
        if has_risky_diff_pattern:
            risk_score += 3
            risk_reasons.append("Diff touches sensitive execution, SQL, auth, or secret handling constructs")
        if touches_deps:
            risk_score += 2
            risk_reasons.append("Updates package or dependency manifests")
        if downstream_consumers >= 4:
            risk_score += 2
            risk_reasons.append(f"High dependency fan-in ({downstream_consumers} downstream importers)")
        if total_churn >= 350 or len(changed_paths) >= 10:
            risk_score += 1
            risk_reasons.append(f"Large diff footprint ({len(changed_paths)} files, {total_churn} lines changed)")

    if docs_only:
        risk_tier = "low"
    elif risk_score >= 3:
        risk_tier = "high"
    elif risk_score >= 1 or changed_paths:
        risk_tier = "medium"
    else:
        risk_tier = "low"
        risk_reasons.append("Minimal or empty change scope")

    high_risk = risk_tier == "high"
    skip_heavy_scanners = docs_only and not has_risky_diff_pattern

    # Determine per-agent execution plans and focus skills
    diff_skills = ["ast_change_impact", "semantic_diff", "api_contract_analysis"]
    if touches_deps or any(p.endswith((".yml", ".yaml", ".json", ".toml", ".env")) for p in changed_paths):
        diff_skills.append("config_and_dependency_impact")

    style_skills = [
        "language_specific_linting",
        "code_smell_detection",
        "dead_code_detection",
        "naming_and_convention_analysis",
        "maintainability_analysis",
        "safe_refactoring_suggestions",
        "existing_pattern_detection",
    ]
    security_skills = [
        "taint_analysis",
        "data_flow_analysis",
        "auth_and_authz_analysis",
        "injection_analysis",
        "secrets_detection",
        "cryptography_analysis",
        "threat_modelling",
        "exploitability_reasoning",
    ]
    if touches_deps:
        security_skills.append("dependency_vulnerability_analysis")
    test_skills = [
        "test_discovery",
        "test_to_code_mapping",
        "coverage_gap_analysis",
        "regression_test_generation",
        "property_based_testing",
        "mutation_testing",
        "failure_triage",
        "minimal_reproduction",
    ]

    agent_plans: dict[str, dict[str, Any]] = {
        "diff_agent": {
            "mode": "deep" if high_risk else ("light" if docs_only else "standard"),
            "token_budget": AGENT_TOKEN_BUDGETS["diff_agent"],
            "focus_skills": diff_skills,
            "permissions": AGENT_CAPABILITY_REGISTRY["diff_agent"].to_dict(),
            "skip_scanners": False,
            "focus_files": changed_paths[:10],
        },
        "style_agent": {
            "mode": "light" if skip_heavy_scanners else "standard",
            "token_budget": AGENT_TOKEN_BUDGETS["style_agent"],
            "focus_skills": style_skills,
            "permissions": AGENT_CAPABILITY_REGISTRY["style_agent"].to_dict(),
            "skip_scanners": skip_heavy_scanners,
            "run_ruff": has_python and not skip_heavy_scanners,
            "run_eslint": has_js_ts and not skip_heavy_scanners,
            "run_pylint": has_python and not skip_heavy_scanners,
            "run_js_ast": has_js_ts and not skip_heavy_scanners,
            "focus_files": [p for p in changed_paths if not _is_doc_or_asset(p)][:10],
        },
        "security_agent": {
            "mode": "deep" if high_risk else ("light" if skip_heavy_scanners else "standard"),
            "token_budget": int(AGENT_TOKEN_BUDGETS["security_agent"] * (1.3 if high_risk else 1.0)),
            "focus_skills": security_skills,
            "permissions": AGENT_CAPABILITY_REGISTRY["security_agent"].to_dict(),
            "skip_scanners": skip_heavy_scanners,
            "run_bandit": has_python and not skip_heavy_scanners,
            "run_semgrep": not skip_heavy_scanners,
            "run_gitleaks": not skip_heavy_scanners,
            "run_osv": touches_deps or (not skip_heavy_scanners and len(changed_paths) > 0),
            "run_taint": not skip_heavy_scanners,
            "run_codeql": high_risk and not skip_heavy_scanners,
            "run_trivy": (high_risk or touches_deps) and not skip_heavy_scanners,
            "focus_files": changed_paths[:10],
        },
        "test_coverage_agent": {
            "mode": "light" if skip_heavy_scanners else ("deep" if high_risk else "standard"),
            "token_budget": AGENT_TOKEN_BUDGETS["test_coverage_agent"],
            "focus_skills": test_skills,
            "permissions": AGENT_CAPABILITY_REGISTRY["test_coverage_agent"].to_dict(),
            "skip_scanners": skip_heavy_scanners,
            "selective_test_mode": not high_risk and not touches_deps,
            "require_tests_pass": bool((policy or {}).get("require_tests_pass", True)),
            "focus_files": changed_paths[:10],
        },
        "reviewer_manager": {
            "mode": "deep" if high_risk else "standard",
            "token_budget": int(AGENT_TOKEN_BUDGETS["reviewer_manager"] * (1.3 if high_risk else 1.0)),
            "focus_skills": list(AGENT_CAPABILITY_REGISTRY["reviewer_manager"].skills),
            "permissions": AGENT_CAPABILITY_REGISTRY["reviewer_manager"].to_dict(),
        },
        "fix_suggestion_agent": {
            "mode": "standard",
            "token_budget": AGENT_TOKEN_BUDGETS["fix_suggestion_agent"],
            "focus_skills": list(AGENT_CAPABILITY_REGISTRY["fix_suggestion_agent"].skills),
            "permissions": AGENT_CAPABILITY_REGISTRY["fix_suggestion_agent"].to_dict(),
        },
    }

    return {
        "risk_tier": risk_tier,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "docs_only": docs_only,
        "languages_in_diff": [
            lang
            for lang, present in (("python", has_python), ("js_ts", has_js_ts))
            if present
        ],
        "touches_dependencies": touches_deps,
        "touches_auth_or_api": touches_auth_or_api,
        "downstream_consumers": downstream_consumers,
        "agent_plans": agent_plans,
        "task_dag": [
            {"stage": "intelligence", "nodes": ["structure_indexer", "review_planner"]},
            {"stage": "fan_out", "nodes": ["diff_agent", "style_agent", "security_agent", "test_coverage_agent"]},
            {"stage": "fan_in_verify", "nodes": ["evidence_guard", "reviewer_manager"]},
            {"stage": "patch_validation", "nodes": ["fix_suggestion_agent", "patch_security_recheck"]},
        ],
    }
