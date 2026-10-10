"""
CIPHER01 — Main Firewall Pipeline
The core security processing pipeline: inbound → risk → policy → provider → outbound.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.scanners.pii import pii_scanner, DetectedEntity
from app.scanners.injection import injection_detector
from app.scanners.decoder import encoding_decoder
from app.scanners.outbound import outbound_scanner
from app.engines.risk import risk_engine, RiskResult
from app.engines.policy import policy_engine, PolicyAction
from app.engines.redaction import redact_messages
from app.engines.routing import provider_router
from app.database.models import Request, SecurityEvent, ProviderCall, Policy, Session
from app.security.audit import log_audit_event

logger = logging.getLogger(__name__)


@dataclass
class FirewallResult:
    request_id: str
    session_id: str
    action: str                    # ALLOW | MASK | TOKENIZE | BLOCK
    risk_score: float
    risk_level: str
    risk_reasons: list[str]
    detected_entities: list[dict]
    policy_explanation: str
    sanitized_messages: list[dict]
    provider_response: Optional[str]
    provider_name: Optional[str]
    provider_model: Optional[str]
    provider_latency_ms: float
    processing_time_ms: float
    outbound_safe: bool
    outbound_issues: list[str]
    blocked: bool
    error: Optional[str] = None


def _load_db_policies(db: Session) -> dict[str, str]:
    result = db.execute(
        select(Policy.entity_type, Policy.action).where(Policy.enabled == True)
    )
    return {row.entity_type: row.action for row in result}


def _get_or_create_session(
    db: Session, session_id: str, provider: str
) -> Session:
    result = db.execute(select(Session).where(Session.id == session_id))
    sess = result.scalar_one_or_none()
    if not sess:
        sess = Session(id=session_id, provider=provider)
        db.add(sess)
        db.flush()
    return sess


async def run_firewall_pipeline(
    messages: list[dict],
    provider_name: str,
    model: str,
    session_id: Optional[str],
    db: Session,
    temperature: float = 0.7,
    max_tokens: Optional[int] = None,
    is_redteam: bool = False,
) -> FirewallResult:
    t_start = time.monotonic()
    request_id = str(uuid.uuid4())
    session_id = session_id or str(uuid.uuid4())

    # ── 1. Load DB policies ───────────────────────────────────────────────────
    db_policies = _load_db_policies(db)
    policy_engine.update(db_policies)

    # ── 2. Load session state ────────────────────────────────────────────────
    session = _get_or_create_session(db, session_id, provider_name)

    # ── 3. Extract all text content ──────────────────────────────────────────
    full_text = " ".join(
        m.get("content", "") for m in messages if isinstance(m.get("content"), str)
    )

    # ── 4. Encoding / obfuscation detection ──────────────────────────────────
    decode_result = encoding_decoder.decode(full_text)
    scan_text = decode_result.final_text if decode_result.encoding_detected else full_text

    # Also check embedded encoded segments
    extra_entities: list[DetectedEntity] = []
    for seg in encoding_decoder.extract_decodable_segments(full_text):
        decoded_seg = encoding_decoder.decode(seg)
        if decoded_seg.encoding_detected:
            extra_entities.extend(pii_scanner.scan(decoded_seg.final_text))

    # ── 5. PII / Secret scanning ─────────────────────────────────────────────
    entities = pii_scanner.scan(scan_text)
    entities.extend(extra_entities)
    # Deduplicate
    seen = set()
    unique_entities: list[DetectedEntity] = []
    for e in entities:
        key = (e.entity_type, e.value[:20])
        if key not in seen:
            seen.add(key)
            unique_entities.append(e)
    entities = unique_entities

    # ── 6. Prompt injection detection ────────────────────────────────────────
    injection_result = injection_detector.detect(full_text)

    # ── 7. Risk scoring ───────────────────────────────────────────────────────
    risk_result: RiskResult = risk_engine.calculate(
        entities=entities,
        injection_detected=injection_result.injection_detected,
        injection_confidence=injection_result.confidence,
        injection_risk=injection_result.risk_contribution,
        encoding_detected=decode_result.encoding_detected,
        encoding_risk=decode_result.risk_contribution,
        session_risk_history=session.cumulative_risk,
        message_count=session.request_count + 1,
    )

    # ── 8. Policy decision ────────────────────────────────────────────────────
    all_entity_types = [e.entity_type for e in entities]
    if injection_result.injection_detected:
        all_entity_types.append("PROMPT_INJECTION")
    if decode_result.encoding_detected and entities:
        all_entity_types.append("ENCODED_SECRET")

    agg_action = policy_engine.aggregate(all_entity_types) if all_entity_types else PolicyAction.ALLOW
    policy_explanation = policy_engine.explain(all_entity_types)

    # ── 9. Apply redaction ────────────────────────────────────────────────────
    blocked = False
    sanitized_messages = messages
    provider_response: Optional[str] = None
    provider_latency_ms = 0.0
    outbound_safe = True
    outbound_issues: list[str] = []

    if agg_action == PolicyAction.BLOCK or injection_result.injection_detected:
        blocked = True
        agg_action = PolicyAction.BLOCK
    else:
        sanitized_messages, _, _, blocked = redact_messages(
            messages, session_id, db_policies
        )

    # ── 10. Provider call ─────────────────────────────────────────────────────
    if not blocked:
        provider_resp = await provider_router.route(
            provider_name=provider_name,
            messages=sanitized_messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            risk_score=risk_result.risk_score,
            request_id=request_id,
        )
        provider_latency_ms = provider_resp.latency_ms

        # ── 11. Outbound scan ─────────────────────────────────────────────────
        if provider_resp.success and provider_resp.content:
            ob_result = outbound_scanner.scan(provider_resp.content)
            if not ob_result.safe:
                outbound_safe = False
                
                outbound_issues = (
                    [f"{e.entity_type} in response" for e in ob_result.entities]
                    + [f"suspicious URL: {u[:40]}" for u in ob_result.suspicious_urls]
                    + [f"canary token: {t}" for t in ob_result.canary_tokens_found]
                    + ob_result.data_leak_indicators[:3]
                    + (["prompt injection in response"] if ob_result.injection_in_response else [])
                )

                # Apply outbound masking per policy
                outbound_action = policy_engine.aggregate(
                    [e.entity_type for e in ob_result.entities]
                )
                if outbound_action == PolicyAction.BLOCK:
                    provider_response = "[RESPONSE BLOCKED — sensitive data detected in AI output]"
                else:
                    provider_response = ob_result.sanitized_text or provider_resp.content
            else:
                provider_response = provider_resp.content

        # Log provider call — use provider_resp.provider (actual adapter, accounting for failover)
        db.add(
            ProviderCall(
                request_id=request_id,
                provider=provider_resp.provider,
                model=provider_resp.model,
                latency_ms=provider_resp.latency_ms,
                success=provider_resp.success,
                error=provider_resp.error,
                prompt_tokens=provider_resp.prompt_tokens,
                completion_tokens=provider_resp.completion_tokens,
            )
        )

    # ── 12. Persist request record ────────────────────────────────────────────
    processing_time_ms = (time.monotonic() - t_start) * 1000
    entity_types_json = json.dumps(list({e.entity_type for e in entities}))

    db_request = Request(
        id=request_id,
        session_id=session_id,
        provider=provider_name,
        model=model,
        risk_score=risk_result.risk_score,
        risk_level=risk_result.risk_level,
        action=agg_action.value,
        entity_types=entity_types_json,
        processing_time_ms=processing_time_ms,
        provider_latency_ms=provider_latency_ms,
        status="blocked" if blocked else "completed",
        is_redteam=is_redteam,
    )
    db.add(db_request)

    # Persist security events
    for entity in entities:
        decision = policy_engine.get_action(entity.entity_type)
        db.add(
            SecurityEvent(
                request_id=request_id,
                event_type="PII" if "KEY" not in entity.entity_type and "PASSWORD" not in entity.entity_type else "SECRET",
                entity_type=entity.entity_type,
                risk_contribution=entity.risk_contribution,
                action=decision.action.value,
                reason=decision.reason,
                masked_value=entity.masked_value,
                direction="inbound",
            )
        )
    if injection_result.injection_detected:
        db.add(
            SecurityEvent(
                request_id=request_id,
                event_type="INJECTION",
                entity_type="PROMPT_INJECTION",
                risk_contribution=injection_result.risk_contribution,
                action="BLOCK",
                reason="; ".join(injection_result.reasons),
                direction="inbound",
            )
        )

    # Update session
    session.request_count += 1
    session.cumulative_risk = (session.cumulative_risk + risk_result.risk_score) / 2
    if entities or injection_result.injection_detected:
        session.security_events_count += 1
    if risk_result.risk_score >= 8.0:
        session.is_flagged = True

    # Audit event
    log_audit_event(
        db=db,
        event_kind="firewall_decision",
        summary=f"Request {request_id}: {agg_action.value} | risk={risk_result.risk_score} | provider={provider_name}",
        request_id=request_id,
        metadata={
            "risk_level": risk_result.risk_level,
            "action": agg_action.value,
            "entity_count": len(entities),
            "injection_detected": injection_result.injection_detected,
            "provider": provider_name,
        },
    )

    detected_entities_out = [
        {
            "entity_type": e.entity_type,
            "masked_value": e.masked_value,
            "confidence": round(e.confidence, 2),
            "risk_contribution": e.risk_contribution,
        }
        for e in entities
    ]

    db.commit()

    return FirewallResult(
        request_id=request_id,
        session_id=session_id,
        action=agg_action.value,
        risk_score=risk_result.risk_score,
        risk_level=risk_result.risk_level,
        risk_reasons=risk_result.reasons,
        detected_entities=detected_entities_out,
        policy_explanation=policy_explanation,
        sanitized_messages=sanitized_messages,
        provider_response=provider_response,
        provider_name=provider_name,
        provider_model=model,
        provider_latency_ms=provider_latency_ms,
        processing_time_ms=processing_time_ms,
        outbound_safe=outbound_safe,
        outbound_issues=outbound_issues,
        blocked=blocked,
        error=provider_resp.error if not blocked and provider_resp else None,
    )
