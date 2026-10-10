"""
CIPHER01 — Security Hashing & Hash-Chain Audit Integrity
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime


def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_event_hash(
    event_kind: str,
    summary: str,
    metadata: dict | None,
    prev_hash: str | None,
    timestamp: datetime,
) -> str:
    """
    Compute a SHA-256 hash of this event chained to the previous hash.
    This creates a tamper-evident audit chain.
    """
    payload = json.dumps(
        {
            "event_kind": event_kind,
            "summary": summary,
            "metadata": metadata,
            "prev_hash": prev_hash or "GENESIS",
            "timestamp": timestamp.isoformat(),
        },
        sort_keys=True,
    )
    return sha256_hash(payload)


def hmac_sign(data: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def mask_secret(value: str, show_prefix: int = 4) -> str:
    """Return a safe representation of a secret — never expose raw value."""
    if not value:
        return "[EMPTY]"
    if len(value) <= show_prefix:
        return "***"
    return value[:show_prefix] + "***" + f"[{len(value)} chars]"
