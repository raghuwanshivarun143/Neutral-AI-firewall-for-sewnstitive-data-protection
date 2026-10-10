"""
CIPHER01 — Generic OpenAI-Compatible Provider Adapter
Works with: Ollama, Groq, vLLM, LM Studio, LocalAI, Azure OpenAI, and any
endpoint that implements the OpenAI chat completions API format.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx

from app.providers.base import BaseProviderAdapter, ProviderResponse


class GenericOpenAIAdapter(BaseProviderAdapter):
    """Generic adapter for any OpenAI-compatible endpoint."""

    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: Optional[str] = None,
        default_model: Optional[str] = None,
        extra_headers: Optional[dict] = None,
    ):
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key or "none"
        self._default_model = default_model or "default"
        self._extra_headers = extra_headers or {}

    def is_configured(self) -> bool:
        return bool(self._base_url)

    def _headers(self) -> dict:
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }
        h.update(self._extra_headers)
        return h

    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        resolved_model = model or self._default_model
        payload: dict[str, Any] = {
            "model": resolved_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=self._headers(),
                )
                elapsed = (time.perf_counter() - start) * 1000

                if resp.status_code != 200:
                    return ProviderResponse(
                        success=False,
                        content="",
                        model=resolved_model,
                        provider=self.name,
                        latency_ms=elapsed,
                        error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    )

                data = resp.json()
                choice = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                return ProviderResponse(
                    success=True,
                    content=choice,
                    model=resolved_model,
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
                model=resolved_model,
                provider=self.name,
                latency_ms=elapsed,
                error=str(exc),
            )

    async def health_check(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                start = time.perf_counter()
                # Try /models endpoint — works for most compatible providers
                resp = await client.get(
                    f"{self._base_url}/models",
                    headers=self._headers(),
                )
                latency = (time.perf_counter() - start) * 1000
                if resp.status_code == 200:
                    return {
                        "status": "healthy",
                        "provider": self.name,
                        "latency_ms": round(latency, 1),
                    }
                return {
                    "status": "unhealthy",
                    "provider": self.name,
                    "error": f"HTTP {resp.status_code}",
                }
        except Exception as e:
            return {"status": "unreachable", "provider": self.name, "error": str(e)}


class OllamaAdapter(GenericOpenAIAdapter):
    """Convenience adapter pre-configured for Ollama."""

    def __init__(self, base_url: str = "http://localhost:11434/v1", default_model: str = "llama3"):
        super().__init__(
            name="ollama",
            base_url=base_url,
            api_key="ollama",  # Ollama doesn't require a real key
            default_model=default_model,
        )
