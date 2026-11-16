from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

import httpx
from agent_framework.exceptions import AgentFrameworkException
from agent_framework.openai import OpenAIChatCompletionClient
from openai import AsyncOpenAI, OpenAIError

from app.orchestration.cancellation import (
    ReviewCancelledError,
    is_review_cancelled,
    register_http_client,
    review_id_var,
    unregister_http_client,
)
from app.orchestration.shared_state import AgentExecutionConfig

logger = logging.getLogger(__name__)

LLM_FALLBACK_EXCEPTIONS = (
    TimeoutError,
    OSError,
    ValueError,
    RuntimeError,
    OpenAIError,
    httpx.HTTPError,
    AgentFrameworkException,
)


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


def _extract_usage_dict(response: Any) -> dict[str, int] | None:
    usage = getattr(response, "usage_details", None)
    if not usage:
        return None
    if isinstance(usage, dict):
        inp = usage.get("input_token_count") or usage.get("input_tokens") or 0
        out = usage.get("output_token_count") or usage.get("output_tokens") or 0
        tot = usage.get("total_token_count") or usage.get("total_tokens") or (inp + out)
    else:
        inp = getattr(usage, "input_token_count", None) or getattr(usage, "input_tokens", 0) or 0
        out = getattr(usage, "output_token_count", None) or getattr(usage, "output_tokens", 0) or 0
        tot = getattr(usage, "total_token_count", None) or getattr(usage, "total_tokens", None) or (inp + out)
    return {
        "input_tokens": int(inp),
        "output_tokens": int(out),
        "total_tokens": int(tot),
    }


def effective_agent_timeout(cfg: AgentExecutionConfig, base_timeout: float) -> float:
    """Grant Pro/reasoning models higher streamed latency headroom while keeping standard models crisp."""
    model_lower = (cfg.model or "").lower()
    if cfg.agent_name == "fix_suggestion_agent":
        return min(base_timeout, 60.0) if any(tok in model_lower for tok in ("pro", "reasoner", "r1", "thinking")) else min(base_timeout, 45.0)
    if any(tok in model_lower for tok in ("pro", "reasoner", "r1", "thinking")):
        return max(base_timeout, 110.0)
    return base_timeout


async def _run_with_stream_fallback(
    agent: Any,
    user_prompt: str,
    *,
    rid: str,
    timeout_seconds: float,
) -> Any:
    """Run an Agent Framework call using streaming SSE updates (falling back cleanly if mock/provider lacks stream)."""

    async def _collect_stream() -> Any:
        stream_obj = agent.run(user_prompt, stream=True)
        try:
            async for _update in stream_obj:
                if rid and is_review_cancelled(rid):
                    raise ReviewCancelledError("Review stopped by user.")
            return await stream_obj.get_final_response()
        finally:
            close_fn = getattr(stream_obj, "close", None)
            if callable(close_fn):
                try:
                    res = close_fn()
                    if asyncio.iscoroutine(res):
                        await res
                except (OSError, RuntimeError, httpx.HTTPError, OpenAIError, AgentFrameworkException) as close_exc:
                    logger.debug("Ignoring stream close error: %s", close_exc)

    try:
        return await asyncio.wait_for(_collect_stream(), timeout=timeout_seconds)
    except (ReviewCancelledError, asyncio.CancelledError, TimeoutError):
        raise
    except Exception as exc:
        err_lower = str(exc).lower()
        if any(k in err_lower for k in ("stream", "not iterable", "attribute")):
            return await asyncio.wait_for(agent.run(user_prompt), timeout=timeout_seconds)
        raise


async def run_structured_agent(
    cfg: AgentExecutionConfig,
    *,
    system_prompt: str,
    user_prompt: str,
    timeout_seconds: float = 75.0,
    max_tokens: int = 2500,
) -> dict[str, Any]:
    """
    Execute a Microsoft Agent Framework Agent backed by DeepSeek (OpenAIChatCompletionClient)
    using SSE streaming + bounded asyncio timeouts so slow/stalled calls can never wedge the Fan-In barrier.
    """
    if not cfg.api_key:
        raise MissingAPIKeyError(
            f"API key not configured for {cfg.label} (model: {cfg.model}). "
            "Configure it in Settings -> LLM Agents or in .env."
        )

    rid = review_id_var.get("")
    if rid and is_review_cancelled(rid):
        raise ReviewCancelledError("Review stopped by user before LLM call.")

    total_budget = effective_agent_timeout(cfg, timeout_seconds)
    started_at = time.monotonic()

    # Use explicit connect/read httpx timeout with max_retries=0 so stalled sockets don't silently double-wait
    sdk_client = AsyncOpenAI(
        api_key=cfg.api_key,
        base_url=_normalize_base_url(cfg.base_url),
        timeout=httpx.Timeout(total_budget, connect=15.0, read=max(45.0, total_budget - 5.0)),
        max_retries=0,
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
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
            },
        )
        try:
            response = await _run_with_stream_fallback(
                agent, user_prompt, rid=rid, timeout_seconds=total_budget
            )
            if rid and is_review_cancelled(rid):
                raise ReviewCancelledError("Review stopped by user.")
            try:
                parsed = _extract_json_object(response.text or "")
                usage = _extract_usage_dict(response)
                if usage:
                    parsed["_token_usage"] = usage
                return parsed
            except ValueError:
                if rid and is_review_cancelled(rid):
                    raise ReviewCancelledError("Review stopped by user.")
                remaining = max(15.0, total_budget - (time.monotonic() - started_at))
                retry_timeout = min(40.0, remaining)
                retry_agent = client.as_agent(
                    id=f"{cfg.agent_name}_json_retry",
                    name=cfg.label,
                    instructions=system_prompt + "\nCRITICAL: Output ONE valid complete JSON object only. No markdown or commentary.",
                    default_options={
                        "temperature": 0.0,
                        "max_tokens": max_tokens,
                        "response_format": {"type": "json_object"},
                    },
                )
                retry_resp = await _run_with_stream_fallback(
                    retry_agent, user_prompt, rid=rid, timeout_seconds=retry_timeout
                )
                parsed_retry = _extract_json_object(retry_resp.text or "")
                usage = _extract_usage_dict(retry_resp)
                if usage:
                    parsed_retry["_token_usage"] = usage
                return parsed_retry
        except TimeoutError:
            if rid and is_review_cancelled(rid):
                raise ReviewCancelledError("Review stopped by user.")
            raise TimeoutError(
                f"{cfg.label} ({cfg.model}) exceeded {int(total_budget)}s response timeout."
            )
    except ReviewCancelledError:
        raise
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if rid and is_review_cancelled(rid):
            raise ReviewCancelledError("Review stopped by user.") from exc
        err_str = str(exc).lower()
        if any(tok in err_str for tok in ("response_format", "json_object", "temperature")):
            remaining = max(20.0, total_budget - (time.monotonic() - started_at))
            agent = client.as_agent(
                id=cfg.agent_name,
                name=cfg.label,
                instructions=system_prompt + "\nRespond with valid JSON ONLY (no extra prose).",
                default_options={"max_tokens": max_tokens},
            )
            response = await _run_with_stream_fallback(
                agent, user_prompt, rid=rid, timeout_seconds=remaining
            )
            parsed = _extract_json_object(response.text or "")
            usage = _extract_usage_dict(response)
            if usage:
                parsed["_token_usage"] = usage
            return parsed
        raise
    finally:
        unregister_http_client(rid, sdk_client)
        try:
            await client.close()
        except (OSError, RuntimeError, OpenAIError) as exc:
            logger.debug("Ignoring client close error: %s", exc)
        try:
            await sdk_client.close()
        except (OSError, RuntimeError, OpenAIError) as exc:
            logger.debug("Ignoring SDK client close error: %s", exc)


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
    except Exception as exc:  # noqa: BLE001 — connectivity probe surfaces exact SDK/network error
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
