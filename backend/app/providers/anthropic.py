"""
CIPHER01 — Anthropic Provider Adapter
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from app.config import settings
from app.providers.base import BaseProviderAdapter, ProviderResponse


class AnthropicAdapter(BaseProviderAdapter):
    name = "anthropic"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self._api_key = api_key or settings.anthropic_api_key or ""
        self._base_url = (base_url or settings.anthropic_base_url).rstrip("/")

    def is_configured(self) -> bool:
        return bool(self._api_key and len(self._api_key) > 8)

    def _convert_messages(self, messages: list[dict]) -> tuple[Optional[str], list[dict]]:
        """Separate system message from chat messages for Anthropic API format."""
        system_prompt = None
        chat_messages = []
        for msg in messages:
            if msg.get("role") == "system":
                system_prompt = msg.get("content", "")
            else:
                chat_messages.append(msg)
        return system_prompt, chat_messages

    async def chat(
        self,
        messages: list[dict],
        model: str = "claude-3-haiku-20240307",
        temperature: float = 0.7,
        max_tokens: Optional[int] = 1024,
        **kwargs: Any,
    ) -> ProviderResponse:
        import logging
        logger = logging.getLogger(__name__)
        request_id = kwargs.get("request_id", "unknown")

        if not self.is_configured():
            logger.warning(
                "[DEBUG-SAFE] Provider Call SKIPPED - provider=%s model=%s "
                "request_id=%s reason=api_key_not_configured",
                self.name, model, request_id,
            )
            return ProviderResponse(
                success=False,
                content="",
                model=model,
                provider=self.name,
                latency_ms=0.0,
                error="Anthropic API key not configured",
            )

        system_prompt, chat_messages = self._convert_messages(messages)
        payload: dict[str, Any] = {
            "model": model,
            "messages": chat_messages,
            "max_tokens": max_tokens or 1024,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt

        start = time.perf_counter()
        elapsed: float = 0.0
        http_status = None
        success = False
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self._base_url}/v1/messages",
                    json=payload,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": self.API_VERSION,
                        "Content-Type": "application/json",
                    },
                )
                elapsed = (time.perf_counter() - start) * 1000
                http_status = resp.status_code

                if resp.status_code != 200:
                    return ProviderResponse(
                        success=False,
                        content="",
                        model=model,
                        provider=self.name,
                        latency_ms=elapsed,
                        error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    )

                data = resp.json()
                content = data["content"][0]["text"]
                usage = data.get("usage", {})
                success = True
                return ProviderResponse(
                    success=True,
                    content=content,
                    model=model,
                    provider=self.name,
                    latency_ms=elapsed,
                    prompt_tokens=usage.get("input_tokens", 0),
                    completion_tokens=usage.get("output_tokens", 0),
                    raw=data,
                )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ProviderResponse(
                success=False,
                content="",
                model=model,
                provider=self.name,
                latency_ms=elapsed,
                error=str(exc),
            )
        finally:
            logger.info(
                "[DEBUG-SAFE] Provider Call - provider=%s model=%s "
                "request_id=%s latency_ms=%.2f http_status=%s success=%s",
                self.name, model, request_id, elapsed, http_status, success,
            )


    async def health_check(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"status": "not_configured", "provider": self.name}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                start = time.perf_counter()
                resp = await client.get(
                    f"{self._base_url}/v1/models",
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": self.API_VERSION,
                    },
                )
                latency = (time.perf_counter() - start) * 1000
                if resp.status_code == 200:
                    return {"status": "healthy", "provider": self.name, "latency_ms": round(latency, 1)}
                return {"status": "unhealthy", "provider": self.name, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "unreachable", "provider": self.name, "error": str(e)}
