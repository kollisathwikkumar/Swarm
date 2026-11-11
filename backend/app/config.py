from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

AgentKey = Literal[
    "diff_agent",
    "style_agent",
    "security_agent",
    "test_coverage_agent",
    "reviewer_manager",
    "fix_suggestion_agent",
]

AGENT_METADATA: dict[str, dict[str, str]] = {
    "diff_agent": {
        "label": "Diff Agent",
        "role": "Change analysis & risk context",
        "default_model": "deepseek-flash",
    },
    "style_agent": {
        "label": "Style Agent",
        "role": "Code quality, formatting & maintainability",
        "default_model": "deepseek-flash",
    },
    "security_agent": {
        "label": "Security Agent",
        "role": "Vulnerability, secret & dependency detection",
        "default_model": "deepseek-v4-pro",
    },
    "test_coverage_agent": {
        "label": "Test-Coverage Agent",
        "role": "Pytest execution & coverage gap analysis",
        "default_model": "deepseek-flash",
    },
    "reviewer_manager": {
        "label": "Reviewer Manager",
        "role": "Evidence verification, deduplication & policy decision",
        "default_model": "deepseek-v4-pro",
    },
    "fix_suggestion_agent": {
        "label": "Fix-Suggestion Agent",
        "role": "Minimal validated patch synthesis & explanation",
        "default_model": "deepseek-v4-pro",
    },
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    secret_key: str = "reviewboard-local-dev-secret-change-me"
    encryption_key: str = ""
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    workspace_dir: str = "./.reviewboard_workspaces"

    database_url: str = "sqlite+aiosqlite:///./reviewboard.db"
    celery_enabled: bool = False
    redis_url: str = "redis://localhost:6379/0"

    # DeepSeek LLM global & per-agent settings
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_api_key: str = ""

    diff_agent_model: str = "deepseek-flash"
    diff_agent_base_url: str = ""
    diff_agent_api_key: str = ""

    style_agent_model: str = "deepseek-flash"
    style_agent_base_url: str = ""
    style_agent_api_key: str = ""

    security_agent_model: str = "deepseek-v4-pro"
    security_agent_base_url: str = ""
    security_agent_api_key: str = ""

    test_coverage_agent_model: str = "deepseek-flash"
    test_coverage_agent_base_url: str = ""
    test_coverage_agent_api_key: str = ""

    reviewer_manager_model: str = "deepseek-v4-pro"
    reviewer_manager_base_url: str = ""
    reviewer_manager_api_key: str = ""

    fix_suggestion_agent_model: str = "deepseek-v4-pro"
    fix_suggestion_agent_base_url: str = ""
    fix_suggestion_agent_api_key: str = ""

    # GitHub integration
    github_token: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    github_oauth_redirect_uri: str = "http://localhost:3000/settings?github_oauth=callback"
    github_webhook_secret: str = ""

    # Local Companion
    local_companion_url: str = "http://127.0.0.1:8765"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def resolved_workspace_dir(self) -> Path:
        path = Path(self.workspace_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_env_agent_config(self, agent_name: str) -> dict[str, str]:
        model = getattr(self, f"{agent_name}_model", AGENT_METADATA[agent_name]["default_model"])
        base_url = getattr(self, f"{agent_name}_base_url", "") or self.deepseek_base_url
        api_key = getattr(self, f"{agent_name}_api_key", "") or self.deepseek_api_key
        return {
            "agent_name": agent_name,
            "model": model.strip() or AGENT_METADATA[agent_name]["default_model"],
            "base_url": base_url.strip() or "https://api.deepseek.com",
            "api_key": api_key.strip(),
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
