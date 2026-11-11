"""Independent EvidenceGuard verification, provenance tracking, and contradiction detection."""

from app.verification.evidence_guard import (
    DETERMINISTIC_TOOL_NAMES,
    LLM_ONLY_TOOLS,
    EvidenceRecord,
    build_evidence_store,
    check_finding_contradiction,
    is_patch_eligible,
    verify_file_and_line,
    verify_finding_provenance,
)

__all__ = [
    "DETERMINISTIC_TOOL_NAMES",
    "EvidenceRecord",
    "LLM_ONLY_TOOLS",
    "build_evidence_store",
    "check_finding_contradiction",
    "is_patch_eligible",
    "verify_file_and_line",
    "verify_finding_provenance",
]
