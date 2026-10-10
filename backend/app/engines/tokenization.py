"""
CIPHER01 — Tokenization Engine
Reversible session-scoped tokenization. Raw PII is never sent externally.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Optional


TOKEN_TTL_SECONDS = 3600  # 1 hour


@dataclass
class TokenMapping:
    token: str
    original_value: str
    entity_type: str
    created_at: float = field(default_factory=time.time)


class TokenizationEngine:
    """
    Maps sensitive values to short opaque tokens per session.
    The mapping is stored in-process only (or optionally Redis).
    External providers NEVER see the original values.
    """

    def __init__(self):
        # {session_id: {token: TokenMapping}}
        self._store: dict[str, dict[str, TokenMapping]] = {}
        # {session_id: {original_value: token}} for deduplication
        self._reverse: dict[str, dict[str, str]] = {}

    def _prune(self, session_id: str) -> None:
        """Remove expired mappings."""
        now = time.time()
        if session_id not in self._store:
            return
        expired = [
            tok
            for tok, mapping in self._store[session_id].items()
            if now - mapping.created_at > TOKEN_TTL_SECONDS
        ]
        for tok in expired:
            orig = self._store[session_id][tok].original_value
            del self._store[session_id][tok]
            self._reverse.get(session_id, {}).pop(orig, None)

    def tokenize(
        self, session_id: str, value: str, entity_type: str
    ) -> str:
        """Return an opaque token representing `value` for this session."""
        self._prune(session_id)
        rev = self._reverse.setdefault(session_id, {})
        if value in rev:
            return rev[value]

        # Generate a short readable token
        store = self._store.setdefault(session_id, {})
        count = sum(
            1
            for m in store.values()
            if m.entity_type == entity_type
        )
        prefix = entity_type[:6].upper().replace("_", "")
        token = f"<{prefix}_{count + 1:03d}>"
        store[token] = TokenMapping(
            token=token,
            original_value=value,
            entity_type=entity_type,
        )
        rev[value] = token
        return token

    def detokenize(self, session_id: str, text: str) -> str:
        """Replace tokens in text with original values (for internal use only)."""
        store = self._store.get(session_id, {})
        for token, mapping in store.items():
            text = text.replace(token, mapping.original_value)
        return text

    def get_mappings(self, session_id: str) -> list[dict]:
        """Return safe mapping info (no raw values) for display."""
        self._prune(session_id)
        result = []
        for token, mapping in self._store.get(session_id, {}).items():
            # Never expose the original value in API responses
            masked = mapping.original_value[:2] + "***" if len(mapping.original_value) > 4 else "***"
            result.append(
                {
                    "token": token,
                    "entity_type": mapping.entity_type,
                    "masked_original": masked,
                    "created_at": mapping.created_at,
                }
            )
        return result

    def apply_tokenization(
        self,
        text: str,
        entities: list,  # list[DetectedEntity]
        session_id: str,
        entity_types_to_tokenize: set[str],
    ) -> str:
        """Replace specified entity types with tokens in text."""
        if not entities:
            return text
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        chars = list(text)
        for entity in sorted_entities:
            if entity.entity_type in entity_types_to_tokenize:
                token = self.tokenize(session_id, entity.value, entity.entity_type)
                chars[entity.start : entity.end] = list(token)
        return "".join(chars)


tokenization_engine = TokenizationEngine()
