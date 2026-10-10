"""
CIPHER01 — OpenAI Provider Adapter
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx
import logging

from app.config import settings
from app.providers.base import BaseProviderAdapter, ProviderResponse

logger = logging.getLogger(__name__)


class OpenAIAdapter(BaseProviderAdapter):
    name = "openai"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self._api_key = api_key or settings.openai_api_key or ""
        self._base_url = (base_url or settings.openai_base_url).rstrip("/")

    def is_configured(self) -> bool:
        return bool(self._api_key and len(self._api_key) > 8)

    async def chat(
        self,
        messages: list[dict],
        model: str = "gpt-4o-mini",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
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
                error="OpenAI API key not configured",
            )

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        start_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        start = time.perf_counter()
        elapsed: float = 0.0
        http_status = None
        success = False
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
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
                choice = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                success = True
                return ProviderResponse(
                    success=True,
                    content=choice,
                    model=model,
                    provider=self.name,
                    latency_ms=elapsed,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
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
            end_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # Safe metadata logging — never logs API key, auth headers, or raw PII
            logger.info(
                "[DEBUG-SAFE] Provider Call - provider=%s model=%s "
                "request_id=%s start=%s end=%s latency_ms=%.2f http_status=%s success=%s",
                self.name, model, request_id,
                start_time_iso, end_time_iso,
                elapsed, http_status, success,
            )


    async def health_check(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "configured": self.is_configured(),
            "reachable": False,
            "operational": False,
        }
        if not result["configured"]:
            result["status"] = "not_configured"
            return result
            
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                start = time.perf_counter()
                resp = await client.get(
                    f"{self._base_url}/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                latency = (time.perf_counter() - start) * 1000
                result["reachable"] = True
                
                if resp.status_code == 200:
                    result["operational"] = True
                    result["status"] = "healthy"
                    result["latency_ms"] = round(latency, 1)
                else:
                    result["status"] = "unhealthy"
                    result["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            result["status"] = "unreachable"
            result["error"] = str(e)
            
        return result
