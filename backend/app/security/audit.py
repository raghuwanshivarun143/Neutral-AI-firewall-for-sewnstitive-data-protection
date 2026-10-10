"""
CIPHER01 — Audit Logger (Immutable Hash-Chain)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from app.database.models import AuditEvent
from app.security.hashing import compute_event_hash

logger = logging.getLogger(__name__)

_last_hash: Optional[str] = None  # In-memory chain head (reset on restart)


def _get_prev_hash(db: Session) -> Optional[str]:
    global _last_hash
    if _last_hash:
        return _last_hash
    result = db.execute(
        select(AuditEvent.self_hash).order_by(desc(AuditEvent.timestamp)).limit(1)
    )
    row = result.scalar_one_or_none()
    _last_hash = row
    return _last_hash


def log_audit_event(
    db: Session,
    event_kind: str,
    summary: str,
    request_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> AuditEvent:
    """
    Persist an immutable audit event with hash-chain integrity.
    Never stores raw secrets in summary or metadata.
    """
    global _last_hash
    now = datetime.now(timezone.utc)
    prev_hash = _get_prev_hash(db)

    self_hash = compute_event_hash(
        event_kind=event_kind,
        summary=summary,
        metadata=metadata,
        prev_hash=prev_hash,
        timestamp=now,
    )

    event = AuditEvent(
        request_id=request_id,
        timestamp=now,
        event_kind=event_kind,
        summary=summary,
        metadata_json=json.dumps(metadata) if metadata else None,
        prev_hash=prev_hash,
        self_hash=self_hash,
    )
    db.add(event)
    db.flush()
    _last_hash = self_hash
    return event
