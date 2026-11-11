from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AgentExecutionConfig:
    agent_name: str
    label: str
    model: str
    base_url: str
    api_key: str
    temperature: float = 0.1


@dataclass
class StructuredFinding:
    agent: str
    category: str
    severity: str  # Critical | High | Medium | Low
    title: str
    description: str
    file_path: str
    line_number: int | None
    end_line: int | None
    evidence: str
    recommendation: str
    verification_status: str = "Needs Verification"  # Verified | Needs Verification | Unverified
    tool_name: str | None = None
    rule_id: str | None = None
    deduplicated_sources: list[str] = field(default_factory=list)
    priority_rank: int = 100
    is_blocking: bool = False
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "end_line": self.end_line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "verification_status": self.verification_status,
            "tool_name": self.tool_name,
            "rule_id": self.rule_id,
            "deduplicated_sources": self.deduplicated_sources,
            "priority_rank": self.priority_rank,
            "is_blocking": self.is_blocking,
            "evidence_ids": self.evidence_ids,
            "confidence": self.confidence,
        }


@dataclass
class AgentExecutionOutput:
    agent_name: str
    agent_label: str
    model_used: str
    status: str  # completed | incomplete | failed
    summary: str
    findings: list[StructuredFinding] = field(default_factory=list)
    tool_results: dict[str, Any] = field(default_factory=dict)
    raw_output: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "agent_label": self.agent_label,
            "model_used": self.model_used,
            "status": self.status,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "tool_results": self.tool_results,
            "raw_output": self.raw_output,
            "error_message": self.error_message,
            "duration_ms": self.duration_ms,
        }


@dataclass
class PatchProposal:
    finding_index: int
    file_path: str
    title: str
    original_code: str
    proposed_code: str
    unified_diff: str
    explanation: str
    applicability_verified: bool
    validation_output: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_index": self.finding_index,
            "file_path": self.file_path,
            "title": self.title,
            "original_code": self.original_code,
            "proposed_code": self.proposed_code,
            "unified_diff": self.unified_diff,
            "explanation": self.explanation,
            "applicability_verified": self.applicability_verified,
            "validation_output": self.validation_output,
        }


@dataclass
class ReviewState:
    review_id: str
    repository_id: str
    repository_name: str
    source_type: str
    base_commit: str
    target_commit: str
    workspace_dir: Path
    diff_text: str
    changed_files: list[dict[str, Any]]
    policy: dict[str, Any]
    agent_configs: dict[str, AgentExecutionConfig]
    diff_summary: str = ""
    diff_context: dict[str, Any] = field(default_factory=dict)
    cache_dir: Path | None = None
    structure_index: dict[str, Any] = field(default_factory=dict)
    review_plan: dict[str, Any] = field(default_factory=dict)
    evidence_store: list[dict[str, Any]] = field(default_factory=list)
    cache_stats: dict[str, Any] = field(default_factory=dict)
    agent_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = "Pending"  # Approve | Request Changes | Incomplete
    recommendation_reason: str = ""
    patch_proposals: list[dict[str, Any]] = field(default_factory=list)
    review_status: str = "running"

    def to_snapshot(self) -> dict[str, Any]:
        return {
            "review_id": self.review_id,
            "repository_id": self.repository_id,
            "repository_name": self.repository_name,
            "source_type": self.source_type,
            "base_commit": self.base_commit,
            "target_commit": self.target_commit,
            "changed_files": [
                {
                    "path": f.get("path"),
                    "status": f.get("status"),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                    "changed_lines": f.get("changed_lines", []),
                }
                for f in self.changed_files
            ],
            "diff_summary": self.diff_summary,
            "agent_results": {
                k: {
                    "status": v.get("status"),
                    "model_used": v.get("model_used"),
                    "summary": v.get("summary"),
                    "duration_ms": v.get("duration_ms"),
                    "error_message": v.get("error_message"),
                    "findings_count": len(v.get("findings", [])),
                }
                for k, v in self.agent_results.items()
            },
            "findings": self.findings,
            "recommendation": self.recommendation,
            "recommendation_reason": self.recommendation_reason,
            "patch_proposals": [
                {
                    "file_path": p.get("file_path"),
                    "title": p.get("title"),
                    "applicability_verified": p.get("applicability_verified"),
                }
                for p in self.patch_proposals
            ],
            "review_plan": self.review_plan,
            "structure_index_summary": {
                "files_indexed": self.structure_index.get("files_indexed", 0),
                "symbols_indexed": self.structure_index.get("symbols_indexed", 0),
                "edges_indexed": self.structure_index.get("edges_indexed", 0),
                "tree_sitter_active": self.structure_index.get("tree_sitter_active", False),
                "languages": self.structure_index.get("languages", []),
            },
            "evidence_store_count": len(self.evidence_store),
            "cache_stats": self.cache_stats,
            "review_status": self.review_status,
        }
