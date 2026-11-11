from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="developer", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    connected_accounts: Mapped[list[ConnectedAccount]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    repositories: Mapped[list[Repository]] = relationship(
        back_populates="owner_user", cascade="all, delete-orphan"
    )


class ConnectedAccount(Base):
    __tablename__ = "connected_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="github", nullable=False)
    auth_mode: Mapped[str] = mapped_column(String(32), default="pat", nullable=False)  # pat | oauth
    provider_user_id: Mapped[str] = mapped_column(String(100), nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scopes: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user: Mapped[User] = relationship(back_populates="connected_accounts")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)  # github | local
    full_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    default_branch: Mapped[str] = mapped_column(String(120), default="main", nullable=False)
    remote_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    html_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    local_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    github_repo_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    auto_review_webhooks: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner_user: Mapped[User] = relationship(back_populates="repositories")
    code_changes: Mapped[list[CodeChange]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )
    reviews: Mapped[list[Review]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )


class CodeChange(Base):
    __tablename__ = "code_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    source_mode: Mapped[str] = mapped_column(String(32), nullable=False)  # github_pr | github_compare | local_diff | local_commits
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pr_title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    base_branch: Mapped[str] = mapped_column(String(150), default="main", nullable=False)
    target_branch: Mapped[str] = mapped_column(String(150), default="HEAD", nullable=False)
    base_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    target_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    diff_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    changed_files: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    file_snapshots: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    repository: Mapped[Repository] = relationship(back_populates="code_changes")
    reviews: Mapped[list[Review]] = relationship(back_populates="code_change")


class Review(Base):
    __tablename__ = "reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    code_change_id: Mapped[str] = mapped_column(ForeignKey("code_changes.id", ondelete="CASCADE"), index=True)
    triggered_by: Mapped[str] = mapped_column(String(64), default="manual", nullable=False)
    base_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    target_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    review_status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False, index=True)
    recommendation: Mapped[str] = mapped_column(String(32), default="Pending", nullable=False)
    recommendation_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    diff_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    shared_state_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    github_review_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    github_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    repository: Mapped[Repository] = relationship(back_populates="reviews")
    code_change: Mapped[CodeChange] = relationship(back_populates="reviews")
    agent_runs: Mapped[list[AgentRun]] = relationship(
        back_populates="review", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="review", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[ReviewArtifact]] = relationship(
        back_populates="review", cascade="all, delete-orphan"
    )
    patch_suggestions: Mapped[list[PatchSuggestion]] = relationship(
        back_populates="review", cascade="all, delete-orphan"
    )


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id", ondelete="CASCADE"), index=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_label: Mapped[str] = mapped_column(String(100), nullable=False)
    model_used: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)  # queued|running|completed|incomplete|failed
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    tool_results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    raw_output: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    review: Mapped[Review] = relationship(back_populates="agent_runs")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id", ondelete="CASCADE"), index=True)
    agent: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="general", nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, index=True)  # Critical|High|Medium|Low
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    verification_status: Mapped[str] = mapped_column(
        String(32), default="Needs Verification", nullable=False
    )  # Verified|Needs Verification|Unverified
    deduplicated_sources: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    priority_rank: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    is_blocking: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    review: Mapped[Review] = relationship(back_populates="findings")
    patch_suggestions: Mapped[list[PatchSuggestion]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class ReviewArtifact(Base):
    __tablename__ = "review_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id", ondelete="CASCADE"), index=True)
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    content_type: Mapped[str] = mapped_column(String(64), default="application/json", nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    review: Mapped[Review] = relationship(back_populates="artifacts")


class PatchSuggestion(Base):
    __tablename__ = "patch_suggestions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    review_id: Mapped[str] = mapped_column(ForeignKey("reviews.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_code: Mapped[str] = mapped_column(Text, nullable=False)
    unified_diff: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    applicability_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    validation_output: Mapped[str] = mapped_column(Text, default="", nullable=False)
    approval_status: Mapped[str] = mapped_column(
        String(32), default="pending_approval", nullable=False
    )  # pending_approval|approved|rejected|applied
    applied_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(150), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    review: Mapped[Review] = relationship(back_populates="patch_suggestions")
    finding: Mapped[Finding | None] = relationship(back_populates="patch_suggestions")


class ReviewPolicy(Base):
    __tablename__ = "review_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True, default="default", nullable=False)
    block_on_critical: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    block_on_high: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_tests_pass: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_all_mandatory_scans: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enable_test_execution: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_publish_github_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    excluded_paths: Mapped[list] = mapped_column(
        JSON,
        default=lambda: [".env", ".env.*", "*.pem", "*.key", "*.p12", "id_rsa*", "node_modules/**", ".git/**"],
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AgentLLMConfig(Base):
    __tablename__ = "agent_llm_configs"
    __table_args__ = (UniqueConstraint("agent_name", name="uq_agent_llm_config_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(300), default="https://api.deepseek.com", nullable=False)
    encrypted_api_key: Mapped[str] = mapped_column(Text, default="", nullable=False)
    temperature: Mapped[str] = mapped_column(String(16), default="0.1", nullable=False)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_status: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
