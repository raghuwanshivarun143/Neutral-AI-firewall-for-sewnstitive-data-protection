"""
CIPHER01 â€” Provider Router
Routes sanitized requests to the correct AI provider adapter.
Supports failover with privacy-aware fallback.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from app.config import settings
from app.providers.base import BaseProviderAdapter, ProviderResponse
from app.providers.openai import OpenAIAdapter
from app.providers.anthropic import AnthropicAdapter
from app.providers.generic import GenericOpenAIAdapter, OllamaAdapter

logger = logging.getLogger(__name__)


class ProviderRouter:
    """
    Registry of all configured provider adapters.
    Resolves provider by name and handles failover.
    """

    def __init__(self):
        self._adapters: dict[str, BaseProviderAdapter] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register all built-in providers based on settings."""
        self.register("openai", OpenAIAdapter())
        self.register("anthropic", AnthropicAdapter())
        self.register(
            "ollama",
            OllamaAdapter(
                base_url=settings.ollama_base_url,
                default_model="llama3",
            ),
        )
        # Groq (OpenAI-compatible)
        if settings.groq_api_key:
            self.register(
                "groq",
                GenericOpenAIAdapter(
                    name="groq",
                    base_url="https://api.groq.com/openai/v1",
                    api_key=settings.groq_api_key,
                    default_model="openai/gpt-oss-20b",
                ),
            )

    def register(self, name: str, adapter: BaseProviderAdapter) -> None:
        self._adapters[name.lower()] = adapter
        logger.debug("Registered provider: %s", name)

    def get(self, name: str) -> Optional[BaseProviderAdapter]:
        return self._adapters.get(name.lower())

    def list_providers(self) -> list[str]:
        return list(self._adapters.keys())

    def get_configured(self) -> list[str]:
        return [k for k, v in self._adapters.items() if v.is_configured()]

    async def route(
        self,
        provider_name: str,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        risk_score: float = 0.0,
        fallback_providers: Optional[list[str]] = None,
        request_id: Optional[str] = None,
    ) -> ProviderResponse:
        """
        Route a sanitized request to the specified provider.
        If the provider fails and fallback_providers is given, tries them in order.
        Privacy rule: never fall back to an external provider if risk_score >= 8.0.
        """
        adapter = self.get(provider_name)
        if adapter is None:
            # Try default
            adapter = self.get(settings.default_provider)
            if adapter is None:
                return ProviderResponse(
                    success=False,
                    content="",
                    model=model or settings.default_model,
                    provider=provider_name,
                    latency_ms=0.0,
                    error=f"Provider '{provider_name}' not found",
                )

        resolved_model = model or getattr(adapter, "_default_model", None) or settings.default_model
        result = await adapter.chat(
            messages=messages,
            model=resolved_model,
            temperature=temperature,
            max_tokens=max_tokens,
            request_id=request_id,
        )

        if result.success:
            return result

        # Failover
        if fallback_providers:
            for fallback_name in fallback_providers:
                if fallback_name == provider_name:
                    continue
                # Privacy guard: don't send high-risk data to external fallback
                fallback_adapter = self.get(fallback_name)
                if fallback_adapter is None:
                    continue
                is_local = fallback_name in ("ollama", "vllm", "localai", "lmstudio")
                if risk_score >= 8.0 and not is_local:
                    logger.warning(
                        "Skipping external fallback '%s' for CRITICAL risk request",
                        fallback_name,
                    )
                    continue
                logger.info("Failing over to provider: %s", fallback_name)
                fallback_result = await fallback_adapter.chat(
                    messages=messages,
                    model=resolved_model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    request_id=request_id,
                )
                if fallback_result.success:
                    return fallback_result

        return result  # Return last failure

    async def health_all(self) -> dict[str, Any]:
        results = {}
        for name, adapter in self._adapters.items():
            results[name] = await adapter.health_check()
        return results


# Global singleton
provider_router = ProviderRouter()



