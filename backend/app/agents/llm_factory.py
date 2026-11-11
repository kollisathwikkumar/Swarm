from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

from agent_framework.openai import OpenAIChatCompletionClient
from openai import AsyncOpenAI

from app.orchestration.cancellation import (
    ReviewCancelledError,
    is_review_cancelled,
    register_http_client,
    review_id_var,
    unregister_http_client,
)
from app.orchestration.shared_state import AgentExecutionConfig


class MissingAPIKeyError(RuntimeError):
    """Raised when an agent has no configured LLM API key."""


def _normalize_base_url(base_url: str) -> str:
    url = (base_url or "https://api.deepseek.com").strip().rstrip("/")
    if url == "https://api.deepseek.com":
        return "https://api.deepseek.com/v1"
    return url


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("LLM returned empty response")

    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fence_match:
        text = fence_match.group(1).strip()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed

    raise ValueError(f"Could not parse structured JSON from agent response: {text[:300]}")


async def run_structured_agent(
    cfg: AgentExecutionConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: float = 65.0,
) -> dict[str, Any]:
    """
    Execute a Microsoft Agent Framework Agent backed by DeepSeek (OpenAIChatCompletionClient)
    with explicit HTTP + asyncio timeouts so slow/stalled calls can never wedge the Fan-In barrier.
    """
    if not cfg.api_key:
        raise MissingAPIKeyError(
            f"API key not configured for {cfg.label} (model: {cfg.model}). "
            "Configure it in Settings -> LLM Agents or in .env."
        )

    rid = review_id_var.get("")
    if rid and is_review_cancelled(rid):
        raise ReviewCancelledError("Review stopped by user before LLM call.")

    sdk_client = AsyncOpenAI(
        api_key=cfg.api_key,
        base_url=_normalize_base_url(cfg.base_url),
        timeout=max(10.0, timeout_seconds - 5.0),
        max_retries=1,
    )
    register_http_client(rid, sdk_client)
    client = OpenAIChatCompletionClient(
        model=cfg.model,
        async_client=sdk_client,
    )
    try:
        agent = client.as_agent(
            id=cfg.agent_name,
            name=cfg.label,
            instructions=system_prompt,
            default_options={
                "temperature": cfg.temperature,
                "max_tokens": 3500,
                "response_format": {"type": "json_object"},
            },
        )
        try:
            response = await asyncio.wait_for(agent.run(user_prompt), timeout=timeout_seconds)
            if rid and is_review_cancelled(rid):
                raise ReviewCancelledError("Review stopped by user.")
            try:
                return _extract_json_object(response.text or "")
            except ValueError:
                if rid and is_review_cancelled(rid):
                    raise ReviewCancelledError("Review stopped by user.")
                retry_agent = client.as_agent(
                    id=f"{cfg.agent_name}_json_retry",
                    name=cfg.label,
                    instructions=system_prompt + "\nCRITICAL: Output ONE valid complete JSON object only. No markdown or commentary.",
                    default_options={
                        "temperature": 0.0,
                        "max_tokens": 3500,
                        "response_format": {"type": "json_object"},
                    },
                )
                retry_resp = await asyncio.wait_for(
                    retry_agent.run(user_prompt), timeout=timeout_seconds
                )
                return _extract_json_object(retry_resp.text or "")
        except TimeoutError:
            if rid and is_review_cancelled(rid):
                raise ReviewCancelledError("Review stopped by user.")
            raise TimeoutError(
                f"{cfg.label} ({cfg.model}) exceeded {int(timeout_seconds)}s response timeout."
            )
    except ReviewCancelledError:
        raise
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if rid and is_review_cancelled(rid):
            raise ReviewCancelledError("Review stopped by user.") from exc
        err_str = str(exc).lower()
        if "response_format" in err_str or "json_object" in err_str:
            agent = client.as_agent(
                id=cfg.agent_name,
                name=cfg.label,
                instructions=system_prompt + "\nRespond with valid JSON ONLY (no extra prose).",
                default_options={"temperature": cfg.temperature, "max_tokens": 3500},
            )
            response = await asyncio.wait_for(agent.run(user_prompt), timeout=timeout_seconds)
            return _extract_json_object(response.text or "")
        raise
    finally:
        unregister_http_client(rid, sdk_client)
        try:
            await client.close()
        except Exception:
            pass
        try:
            await sdk_client.close()
        except Exception:
            pass


async def test_agent_connection(cfg: AgentExecutionConfig) -> dict[str, Any]:
    if not cfg.api_key:
        return {
            "ok": False,
            "agent_name": cfg.agent_name,
            "model": cfg.model,
            "latency_ms": 0,
            "message": "No API key configured for this agent.",
        }

    t0 = time.perf_counter()
    sdk_client = AsyncOpenAI(
        api_key=cfg.api_key,
        base_url=_normalize_base_url(cfg.base_url),
        timeout=20.0,
        max_retries=0,
    )
    client = OpenAIChatCompletionClient(
        model=cfg.model,
        async_client=sdk_client,
    )
    try:
        agent = client.as_agent(
            id=f"{cfg.agent_name}_healthcheck",
            name=cfg.label,
            instructions="Reply concisely.",
            default_options={"max_tokens": 16, "temperature": 0.0},
        )
        resp = await asyncio.wait_for(agent.run("Reply with OK"), timeout=22.0)
        latency = int((time.perf_counter() - t0) * 1000)
        return {
            "ok": True,
            "agent_name": cfg.agent_name,
            "model": cfg.model,
            "latency_ms": latency,
            "message": f"Connected cleanly ({resp.text.strip()[:40] or 'OK'})",
        }
    except Exception as exc:
        latency = int((time.perf_counter() - t0) * 1000)
        return {
            "ok": False,
            "agent_name": cfg.agent_name,
            "model": cfg.model,
            "latency_ms": latency,
            "message": str(exc)[:300],
        }
    finally:
        await client.close()
        await sdk_client.close()
