"""
CIPHER01 — Database Models (SQLAlchemy 2.x async)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────────────
class Request(Base):
    """One inbound request processed by CIPHER01."""

    __tablename__ = "requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    provider: Mapped[Optional[str]] = mapped_column(String(64))
    model: Mapped[Optional[str]] = mapped_column(String(128))
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(16), default="LOW")
    action: Mapped[str] = mapped_column(String(16), default="ALLOW")
    entity_types: Mapped[Optional[str]] = mapped_column(Text)  # JSON list
    policy_rule: Mapped[Optional[str]] = mapped_column(String(64))
    processing_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    provider_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    is_redteam: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relations
    security_events: Mapped[list[SecurityEvent]] = relationship(
        back_populates="request", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="request", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
class SecurityEvent(Base):
    """Detailed security finding attached to a request."""

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("requests.id"), index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64))   # PII, SECRET, INJECTION...
    entity_type: Mapped[Optional[str]] = mapped_column(String(64))
    risk_contribution: Mapped[float] = mapped_column(Float, default=0.0)
    action: Mapped[str] = mapped_column(String(16))
    reason: Mapped[Optional[str]] = mapped_column(Text)
    masked_value: Mapped[Optional[str]] = mapped_column(Text)   # safe repr only
    direction: Mapped[str] = mapped_column(String(8), default="inbound")  # inbound|outbound

    request: Mapped[Request] = relationship(back_populates="security_events")


# ─────────────────────────────────────────────────────────────────────────────
class AuditEvent(Base):
    """Immutable audit log with hash-chain integrity."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("requests.id"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    event_kind: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[Optional[str]] = mapped_column(Text)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64))
    self_hash: Mapped[Optional[str]] = mapped_column(String(64))

    request: Mapped[Optional[Request]] = relationship(back_populates="audit_events")


# ─────────────────────────────────────────────────────────────────────────────
class Session(Base):
    """Multi-turn conversation security context."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_active: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    cumulative_risk: Mapped[float] = mapped_column(Float, default=0.0)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    detected_entities_json: Mapped[Optional[str]] = mapped_column(Text)
    security_events_count: Mapped[int] = mapped_column(Integer, default=0)
    provider: Mapped[Optional[str]] = mapped_column(String(64))
    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False)


# ─────────────────────────────────────────────────────────────────────────────
class ProviderCall(Base):
    """Record of every actual call made to an external AI provider."""

    __tablename__ = "provider_calls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[Optional[str]] = mapped_column(String(36))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[Optional[str]] = mapped_column(Text)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)


# ─────────────────────────────────────────────────────────────────────────────
class Policy(Base):
    """Configurable security policy rules."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(String(64), unique=True)
    action: Mapped[str] = mapped_column(String(16), default="MASK")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    description: Mapped[Optional[str]] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# ─────────────────────────────────────────────────────────────────────────────
class EvaluationRun(Base):
    """Evaluation lab run metadata."""

    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    name: Mapped[str] = mapped_column(String(128))
    total_samples: Mapped[int] = mapped_column(Integer, default=0)
    accuracy: Mapped[float] = mapped_column(Float, default=0.0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1_score: Mapped[float] = mapped_column(Float, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    false_negative_rate: Mapped[float] = mapped_column(Float, default=0.0)
    results_json: Mapped[Optional[str]] = mapped_column(Text)


# ─────────────────────────────────────────────────────────────────────────────
class CanaryEvent(Base):
    """Fired when a canary token reappears unexpectedly."""

    __tablename__ = "canary_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    token: Mapped[str] = mapped_column(String(64))
    session_id: Mapped[Optional[str]] = mapped_column(String(36))
    direction: Mapped[str] = mapped_column(String(16))
    context: Mapped[Optional[str]] = mapped_column(Text)


# ─────────────────────────────────────────────────────────────────────────────
class SystemHealth(Base):
    """Periodic health snapshots."""

    __tablename__ = "system_health"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    component: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    latency_ms: Mapped[Optional[float]] = mapped_column(Float)
    details: Mapped[Optional[str]] = mapped_column(Text)
