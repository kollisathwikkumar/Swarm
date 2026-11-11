from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentCapabilities:
    """Explicit separation between agent skills (what it knows), engines (tools it runs), and permissions (what it can alter or claim)."""

    agent_key: str
    skills: tuple[str, ...]
    allowed_engines: tuple[str, ...]
    optional_engines: tuple[str, ...] = ()
    can_read_workspace: bool = True
    can_propose_patches: bool = False
    can_commit_directly: bool = False
    can_self_certify_verified: bool = False
    can_verify_test_execution: bool = False
    require_verified_findings_for_patches: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_key": self.agent_key,
            "skills": list(self.skills),
            "allowed_engines": list(self.allowed_engines),
            "optional_engines": list(self.optional_engines),
            "can_read_workspace": self.can_read_workspace,
            "can_propose_patches": self.can_propose_patches,
            "can_commit_directly": self.can_commit_directly,
            "can_self_certify_verified": self.can_self_certify_verified,
            "can_verify_test_execution": self.can_verify_test_execution,
            "require_verified_findings_for_patches": self.require_verified_findings_for_patches,
        }


AGENT_CAPABILITY_REGISTRY: dict[str, AgentCapabilities] = {
    "diff_agent": AgentCapabilities(
        agent_key="diff_agent",
        skills=(
            "ast_change_detection",
            "change_impact_analysis",
            "semantic_diff",
            "api_contract_analysis",
            "configuration_impact_analysis",
            "regression_risk_classification",
        ),
        allowed_engines=("git-diff", "diff-ast-engine", "llm-review"),
        optional_engines=("tree_sitter",),
        can_verify_test_execution=False,
    ),
    "style_agent": AgentCapabilities(
        agent_key="style_agent",
        skills=(
            "language_specific_linting",
            "code_smell_detection",
            "dead_code_detection",
            "naming_and_convention_analysis",
            "maintainability_analysis",
            "safe_refactoring_suggestions",
            "existing_pattern_detection",
        ),
        allowed_engines=(
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
            "llm-style-review",
            "llm-review",
        ),
        optional_engines=("eslint", "pylint"),
        can_verify_test_execution=False,
    ),
    "security_agent": AgentCapabilities(
        agent_key="security_agent",
        skills=(
            "taint_analysis",
            "data_flow_analysis",
            "auth_and_authz_analysis",
            "injection_analysis",
            "secrets_detection",
            "dependency_vulnerability_analysis",
            "cryptography_analysis",
            "threat_modelling",
            "exploitability_reasoning",
        ),
        allowed_engines=(
            "semgrep",
            "bandit",
            "gitleaks",
            "osv-scanner",
            "security-guard",
            "security-taint",
            "codeql",
            "trivy",
            "llm-security-review",
            "llm-review",
        ),
        optional_engines=("codeql", "trivy"),
        can_verify_test_execution=False,
    ),
    "test_coverage_agent": AgentCapabilities(
        agent_key="test_coverage_agent",
        skills=(
            "test_discovery",
            "test_to_code_mapping",
            "coverage_gap_analysis",
            "regression_test_generation",
            "property_based_testing",
            "mutation_testing",
            "failure_triage",
            "minimal_reproduction",
        ),
        allowed_engines=(
            "pytest",
            "vitest",
            "coverage.py",
            "test-mapper",
            "hypothesis",
            "mutmut",
            "llm-test-review",
            "llm-review",
        ),
        optional_engines=("hypothesis", "mutmut"),
        can_verify_test_execution=True,
    ),
    "reviewer_manager": AgentCapabilities(
        agent_key="reviewer_manager",
        skills=(
            "evidence_provenance_tracking",
            "finding_deduplication",
            "evidence_matching",
            "contradiction_detection",
            "confidence_calibration",
            "severity_normalization",
            "false_positive_triage",
            "review_prioritization",
            "incomplete_review_detection",
        ),
        allowed_engines=(
            "evidence-guard",
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
            "pytest",
            "vitest",
            "coverage.py",
            "test-mapper",
            "diff-ast-engine",
            "git-diff",
            "llm-review",
        ),
        can_verify_test_execution=False,
    ),
    "fix_suggestion_agent": AgentCapabilities(
        agent_key="fix_suggestion_agent",
        skills=(
            "root_cause_analysis",
            "minimal_patch_generation",
            "ast_aware_editing",
            "repository_pattern_reuse",
            "patch_conflict_detection",
            "regression_test_creation",
            "syntax_and_type_validation",
            "security_revalidation",
            "rollback_awareness",
        ),
        allowed_engines=(
            "git-apply-check",
            "python-ast",
            "ts-syntax-checker",
            "mypy",
            "tsc",
            "security-guard",
            "security-taint",
            "pytest",
            "vitest",
        ),
        optional_engines=("mypy", "tsc"),
        can_propose_patches=True,
        can_commit_directly=False,
        can_verify_test_execution=True,
        require_verified_findings_for_patches=True,
    ),
}

_EXECUTION_CLAIM_RE = re.compile(
    r"\b(ran\s+(?:the\s+)?tests?|tests?\s+(?:passed|executed|verified)|executed\s+(?:pytest|vitest)|mutation\s+tested)\b",
    re.IGNORECASE,
)


def get_agent_capabilities(agent_key: str) -> AgentCapabilities | None:
    return AGENT_CAPABILITY_REGISTRY.get(agent_key)


def is_engine_permitted(agent_key: str, engine_name: str) -> bool:
    caps = AGENT_CAPABILITY_REGISTRY.get(agent_key)
    if caps is None:
        return False
    return engine_name in caps.allowed_engines


def enforce_agent_permissions(
    agent_key: str,
    finding: dict[str, Any],
    execution_telemetry: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """
    Enforce agent capability boundaries so code-inspection agents cannot falsely claim
    verified test execution or emit citations for unauthorized engines.
    Returns `(sanitized_finding, violation_notes)`.
    """
    out = dict(finding)
    violations: list[str] = []
    caps = AGENT_CAPABILITY_REGISTRY.get(agent_key)
    tool_name = str(out.get("tool_name") or "llm-review").strip()

    if caps is not None:
        if tool_name not in caps.allowed_engines:
            violations.append(
                f"Agent `{agent_key}` is not permitted to cite engine `{tool_name}`; downgraded to `llm-review`."
            )
            out["tool_name"] = "llm-review"
            out["verification_status"] = "Needs Verification"
            out["evidence_ids"] = []

        # Block any agent (including non-executed test runs) from claiming runtime test execution without runner telemetry
        combined = f"{out.get('title', '')} {out.get('description', '')} {out.get('evidence', '')}"
        if _EXECUTION_CLAIM_RE.search(combined):
            telemetry = execution_telemetry or {}
            runner = str(telemetry.get("runner") or "")
            runner_status = str(telemetry.get("status") or "")
            ran_real_tests = runner in ("pytest", "vitest") and runner_status == "completed"
            if not caps.can_verify_test_execution or not ran_real_tests:
                violations.append(
                    f"Agent `{agent_key}` claimed test/mutation execution without verified runner telemetry."
                )
                out["verification_status"] = "Needs Verification"
                out["evidence_ids"] = []

    return out, violations
