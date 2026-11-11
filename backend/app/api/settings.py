from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.llm_factory import test_agent_connection
from app.api.deps import get_current_user
from app.config import AGENT_METADATA, get_settings
from app.database.session import get_db
from app.models.tables import AgentLLMConfig, ReviewPolicy, User
from app.orchestration.coordinator import load_effective_agent_configs
from app.scanners.tool_runner import check_installed_scanners
from app.services.crypto import decrypt_secret, encrypt_secret, mask_secret

router = APIRouter(prefix="/api/settings", tags=["settings"])


class UpdateAgentLLMConfigRequest(BaseModel):
    model: str = Field(min_length=2, max_length=120)
    base_url: str = Field(default="https://api.deepseek.com", min_length=4, max_length=300)
    api_key: str | None = None
    clear_api_key: bool = False
    temperature: str = "0.1"

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, val: str) -> str:
        parsed = urlparse(val.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must be a valid http(s) URL")
        return val.strip()


class BulkAPIKeyRequest(BaseModel):
    api_key: str = Field(min_length=6, max_length=500)
    agent_names: list[str] | None = None


class UpdatePolicyRequest(BaseModel):
    block_on_critical: bool = True
    block_on_high: bool = True
    require_tests_pass: bool = True
    require_all_mandatory_scans: bool = True
    enable_test_execution: bool = True
    auto_publish_github_review: bool = False
    excluded_paths: list[str] = Field(default_factory=list)


@router.get("/llm-agents")
async def get_llm_agents_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    settings = get_settings()
    rows = {
        r.agent_name: r
        for r in (await db.execute(select(AgentLLMConfig))).scalars().all()
    }
    agents = []
    for agent_name, meta in AGENT_METADATA.items():
        env_cfg = settings.get_env_agent_config(agent_name)
        row = rows.get(agent_name)
        db_key = decrypt_secret(row.encrypted_api_key) if row and row.encrypted_api_key else ""
        effective_key = db_key or env_cfg["api_key"]
        source = "database" if db_key else ("env" if env_cfg["api_key"] else "unconfigured")
        agents.append(
            {
                "agent_name": agent_name,
                "label": meta["label"],
                "role": meta["role"],
                "default_model": meta["default_model"],
                "model": row.model if row and row.model else env_cfg["model"],
                "base_url": row.base_url if row and row.base_url else env_cfg["base_url"],
                "temperature": row.temperature if row else "0.1",
                "has_api_key": bool(effective_key),
                "masked_api_key": mask_secret(effective_key),
                "key_source": source,
                "last_tested_at": row.last_tested_at.isoformat() if row and row.last_tested_at else None,
                "last_test_status": row.last_test_status if row else None,
            }
        )
    return {"agents": agents}


@router.put("/llm-agents/{agent_name}")
async def update_llm_agent_config(
    agent_name: str,
    payload: UpdateAgentLLMConfigRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if agent_name not in AGENT_METADATA:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")

    row = (
        await db.execute(select(AgentLLMConfig).where(AgentLLMConfig.agent_name == agent_name))
    ).scalar_one_or_none()
    if not row:
        row = AgentLLMConfig(
            agent_name=agent_name,
            model=payload.model.strip(),
            base_url=payload.base_url.strip(),
            temperature=payload.temperature,
        )
        db.add(row)
    else:
        row.model = payload.model.strip()
        row.base_url = payload.base_url.strip()
        row.temperature = payload.temperature

    if payload.clear_api_key:
        row.encrypted_api_key = ""
    elif payload.api_key and payload.api_key.strip():
        row.encrypted_api_key = encrypt_secret(payload.api_key.strip())

    await db.commit()
    return {"updated": True, "agent_name": agent_name}


@router.post("/llm-agents/bulk-key")
async def apply_bulk_api_key(
    payload: BulkAPIKeyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    targets = payload.agent_names or list(AGENT_METADATA.keys())
    enc = encrypt_secret(payload.api_key.strip())
    settings = get_settings()
    for agent_name in targets:
        if agent_name not in AGENT_METADATA:
            continue
        row = (
            await db.execute(select(AgentLLMConfig).where(AgentLLMConfig.agent_name == agent_name))
        ).scalar_one_or_none()
        env_cfg = settings.get_env_agent_config(agent_name)
        if not row:
            row = AgentLLMConfig(
                agent_name=agent_name,
                model=env_cfg["model"],
                base_url=env_cfg["base_url"],
                encrypted_api_key=enc,
            )
            db.add(row)
        else:
            row.encrypted_api_key = enc
    await db.commit()
    return {"updated": True, "count": len(targets)}


@router.post("/llm-agents/{agent_name}/test")
async def test_llm_agent(
    agent_name: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if agent_name not in AGENT_METADATA:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_name}")

    configs = await load_effective_agent_configs(db)
    res = await test_agent_connection(configs[agent_name])

    row = (
        await db.execute(select(AgentLLMConfig).where(AgentLLMConfig.agent_name == agent_name))
    ).scalar_one_or_none()
    if not row:
        row = AgentLLMConfig(
            agent_name=agent_name,
            model=configs[agent_name].model,
            base_url=configs[agent_name].base_url,
        )
        db.add(row)
    row.last_tested_at = datetime.now(UTC)
    row.last_test_status = ("OK: " if res["ok"] else "ERROR: ") + res["message"][:180]
    await db.commit()
    return res


@router.get("/policy")
async def get_review_policy(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    policy = (
        await db.execute(select(ReviewPolicy).where(ReviewPolicy.name == "default"))
    ).scalar_one_or_none()
    if not policy:
        policy = ReviewPolicy(name="default")
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
    return {
        "policy": {
            "block_on_critical": policy.block_on_critical,
            "block_on_high": policy.block_on_high,
            "require_tests_pass": policy.require_tests_pass,
            "require_all_mandatory_scans": policy.require_all_mandatory_scans,
            "enable_test_execution": policy.enable_test_execution,
            "auto_publish_github_review": policy.auto_publish_github_review,
            "excluded_paths": list(policy.excluded_paths or []),
        }
    }


@router.put("/policy")
async def update_review_policy(
    payload: UpdatePolicyRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    policy = (
        await db.execute(select(ReviewPolicy).where(ReviewPolicy.name == "default"))
    ).scalar_one_or_none()
    if not policy:
        policy = ReviewPolicy(name="default")
        db.add(policy)

    policy.block_on_critical = payload.block_on_critical
    policy.block_on_high = payload.block_on_high
    policy.require_tests_pass = payload.require_tests_pass
    policy.require_all_mandatory_scans = payload.require_all_mandatory_scans
    policy.enable_test_execution = payload.enable_test_execution
    policy.auto_publish_github_review = payload.auto_publish_github_review
    policy.excluded_paths = [p.strip() for p in payload.excluded_paths if p.strip()]
    await db.commit()
    return {"updated": True}


@router.get("/scanners")
async def get_scanners_status(user: User = Depends(get_current_user)) -> dict:
    scanners = await check_installed_scanners()
    return {"scanners": scanners}
