"""
CIPHER01 — Provider Base Adapter
All AI provider adapters implement this interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ProviderResponse:
    success: bool
    content: str
    model: str
    provider: str
    latency_ms: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    error: Optional[str] = None
    raw: Optional[dict] = None


class BaseProviderAdapter(ABC):
    name: str = "base"

    @abstractmethod
    async def chat(
        self,
        messages: list[dict],
        model: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> ProviderResponse:
        ...

    @abstractmethod
    async def health_check(self) -> dict[str, Any]:
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        ...
