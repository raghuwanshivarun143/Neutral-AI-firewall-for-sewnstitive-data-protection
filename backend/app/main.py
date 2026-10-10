"""
CIPHER01 â€” FastAPI Application Entry Point
The main AI security gateway server.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Optional

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, and_, case
from sqlalchemy.orm import Session

from app.config import settings
from app.database.database import init_db, get_db, SessionLocal
from app.database.models import (
    Request as DBRequest,
    SecurityEvent,
    AuditEvent,
    Policy,
    ProviderCall,
    EvaluationRun,
    Session as DBSession,
)
from app.api.firewall import run_firewall_pipeline
from app.scanners.pii import pii_scanner
from app.scanners.injection import injection_detector
from app.scanners.decoder import encoding_decoder
from app.engines.routing import provider_router
from app.engines.policy import policy_engine
from app.engines.risk import risk_engine

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("ðŸ”’ CIPHER01 AI Firewall starting up...")
    init_db()
    logger.info("âœ… Database initialized")
    yield
    logger.info("CIPHER01 shutting down")


app = FastAPI(
    title="CIPHER01 AI Firewall",
    description="Provider-neutral AI security gateway",
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PYDANTIC SCHEMAS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: Optional[str] = None
    messages: list[ChatMessage]
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = None
    provider: Optional[str] = None
    session_id: Optional[str] = None
    stream: bool = False


class ScanTextRequest(BaseModel):
    text: str
    include_injection: bool = True
    include_encoding: bool = True


class PolicyUpdateRequest(BaseModel):
    action: str
    enabled: Optional[bool] = None
    description: Optional[str] = None


class ProviderTestRequest(BaseModel):
    provider: str
    model: Optional[str] = None
    message: str = "Hello, this is a test message from CIPHER01."


class EvaluationRequest(BaseModel):
    name: str
    samples: list[dict]  # [{text, label, entity_type, expected_action}]


class RedTeamRequest(BaseModel):
    test_type: str
    payload: str
    expected_action: str
    provider: Optional[str] = None
    model: Optional[str] = None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# HEALTH ENDPOINTS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/health")
async def health():
    default_provider = settings.default_provider
    adapter = provider_router.get(default_provider)
    provider_health = await adapter.health_check() if adapter else {}
    
    return {
        "status": "online",
        "version": settings.app_version,
        "firewall": "active",
        "timestamp": time.time(),
        "provider": provider_health,
    }


@app.get("/health/providers")
async def health_providers():
    results = await provider_router.health_all()
    return {"providers": results}


@app.get("/health/scanner")
async def health_scanner():
    test = pii_scanner.scan("test@example.com sk-test12345678901234")
    return {
        "status": "healthy",
        "entities_detected_in_test": len(test),
        "scanner": "regex-based",
    }


@app.get("/health/database")
async def health_database(db: Session = Depends(get_db)):
    try:
        result = db.execute(select(func.count()).select_from(DBRequest))
        count = result.scalar_one()
        return {"status": "healthy", "total_requests": count}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# OPENAI-COMPATIBLE GATEWAY ENDPOINT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest,
    db: Session = Depends(get_db),
):
    """
    OpenAI-compatible chat completions endpoint.
    All requests pass through the full CIPHER01 security pipeline.

    Usage example:
        from openai import OpenAI
        client = OpenAI(api_key="CIPHER01", base_url="http://localhost:8000/v1")
    """
    provider_name = req.provider or settings.default_provider
    session_id = req.session_id or str(uuid.uuid4())
    messages = [m.dict() for m in req.messages]

    result = await run_firewall_pipeline(
        messages=messages,
        provider_name=provider_name,
        model=req.model,
        session_id=session_id,
        db=db,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
    )

    if result.blocked:
        # Return structured error in OpenAI format
        return JSONResponse(
            status_code=200,
            content={
                "id": f"cipher01-{result.request_id}",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"[CIPHER01 BLOCKED] {result.policy_explanation}",
                        },
                        "finish_reason": "content_filter",
                    }
                ],
                "cipher01": {
                    "blocked": True,
                    "risk_score": result.risk_score,
                    "risk_level": result.risk_level,
                    "action": result.action,
                    "reasons": result.risk_reasons,
                },
            },
        )

    return {
        "id": f"cipher01-{result.request_id}",
        "object": "chat.completion",
        "model": result.provider_model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": result.provider_response or "",
                },
                "finish_reason": "stop",
            }
        ],
        "cipher01": {
            "blocked": False,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "action": result.action,
            "provider": result.provider_name,
            "processing_ms": round(result.processing_time_ms, 1),
            "provider_latency_ms": round(result.provider_latency_ms, 1),
            "detected_entities": result.detected_entities,
            "outbound_safe": result.outbound_safe,
        },
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FIREWALL CHECK (Dashboard Inspector)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/api/firewall/check")
async def firewall_check(
    req: ChatCompletionRequest,
    db: Session = Depends(get_db),
):
    """Full firewall check with detailed diagnostics for the dashboard."""
    provider_name = req.provider or settings.default_provider
    session_id = req.session_id or str(uuid.uuid4())
    messages = [m.dict() for m in req.messages]

    result = await run_firewall_pipeline(
        messages=messages,
        provider_name=provider_name,
        model=req.model,
        session_id=session_id,
        db=db,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
    )

    return {
        "request_id": result.request_id,
        "session_id": result.session_id,
        "action": result.action,
        "blocked": result.blocked,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "risk_reasons": result.risk_reasons,
        "detected_entities": result.detected_entities,
        "policy_explanation": result.policy_explanation,
        "provider_response": result.provider_response if not result.blocked else None,
        "provider_name": result.provider_name,
        "provider_model": result.provider_model,
        "provider_latency_ms": round(result.provider_latency_ms, 1),
        "processing_time_ms": round(result.processing_time_ms, 1),
        "outbound_safe": result.outbound_safe,
        "outbound_issues": result.outbound_issues,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEXT SCAN ONLY (no provider call)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/api/scan/text")
async def scan_text(req: ScanTextRequest):
    """Scan text for PII, secrets, injection, and encoding â€” no provider call."""
    results: dict[str, Any] = {}

    # Encoding
    if req.include_encoding:
        decode_result = encoding_decoder.decode(req.text)
        results["encoding"] = {
            "detected": decode_result.encoding_detected,
            "layers": [
                {"encoding": l.encoding, "depth": l.depth}
                for l in decode_result.layers
            ],
            "final_text": decode_result.final_text[:500] if decode_result.encoding_detected else None,
        }
        scan_text = decode_result.final_text
    else:
        scan_text = req.text

    # PII/Secrets
    entities = pii_scanner.scan(scan_text)
    results["entities"] = [
        {
            "entity_type": e.entity_type,
            "masked_value": e.masked_value,
            "confidence": round(e.confidence, 2),
            "risk_contribution": e.risk_contribution,
            "detector": e.detector,
        }
        for e in entities
    ]

    # Injection
    if req.include_injection:
        inj = injection_detector.detect(req.text)
        results["injection"] = {
            "detected": inj.injection_detected,
            "confidence": round(inj.confidence, 2),
            "reasons": inj.reasons,
            "matched_indicators": inj.matched_indicators,
        }

    # Risk
    inj_detected = req.include_injection and results.get("injection", {}).get("detected", False)
    risk = risk_engine.calculate(
        entities=entities,
        injection_detected=inj_detected,
        injection_confidence=results.get("injection", {}).get("confidence", 0),
        injection_risk=9.0 if inj_detected else 0,
        encoding_detected=results.get("encoding", {}).get("detected", False),
        encoding_risk=decode_result.risk_contribution if req.include_encoding else 0,
    )
    results["risk"] = {
        "score": risk.risk_score,
        "level": risk.risk_level,
        "reasons": risk.reasons,
    }
    results["redacted_text"] = pii_scanner.redact(scan_text, entities) if entities else scan_text

    return results


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FILE SCAN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """Scan uploaded file for PII/secrets before any external processing."""
    content_bytes = await file.read()

    if len(content_bytes) > settings.max_payload_size_mb * 1024 * 1024:
        raise HTTPException(413, "File exceeds maximum allowed size")

    filename = file.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    extracted_text = ""

    try:
        if ext in ("txt", "csv", "json", "md", "log"):
            extracted_text = content_bytes.decode("utf-8", errors="replace")

        elif ext == "pdf":
            try:
                import io
                import PyPDF2
                reader = PyPDF2.PdfReader(io.BytesIO(content_bytes))
                extracted_text = " ".join(
                    page.extract_text() or "" for page in reader.pages
                )
            except ImportError:
                extracted_text = content_bytes.decode("utf-8", errors="replace")

        elif ext == "docx":
            try:
                import io
                import docx as python_docx
                doc = python_docx.Document(io.BytesIO(content_bytes))
                extracted_text = " ".join(p.text for p in doc.paragraphs)
            except ImportError:
                extracted_text = content_bytes.decode("utf-8", errors="replace")

        else:
            extracted_text = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        extracted_text = content_bytes.decode("utf-8", errors="replace")

    entities = pii_scanner.scan(extracted_text)
    risk = risk_engine.calculate(entities=entities)

    return {
        "filename": filename,
        "file_type": ext,
        "text_length": len(extracted_text),
        "entities": [
            {
                "entity_type": e.entity_type,
                "masked_value": e.masked_value,
                "confidence": round(e.confidence, 2),
            }
            for e in entities
        ],
        "risk": {
            "score": risk.risk_score,
            "level": risk.risk_level,
            "reasons": risk.reasons,
        },
        "safe_to_share": risk.risk_score < 3.0,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PROVIDERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/api/providers")
async def list_providers():
    return {
        "providers": provider_router.list_providers(),
        "configured": provider_router.get_configured(),
        "default": settings.default_provider,
    }


@app.post("/api/providers/test")
async def test_provider(req: ProviderTestRequest):
    adapter = provider_router.get(req.provider)
    if not adapter:
        raise HTTPException(404, f"Provider '{req.provider}' not found")
    messages = [{"role": "user", "content": req.message}]
    resp = await adapter.chat(messages=messages, model=req.model or getattr(adapter, "_default_model", None) or settings.default_model)
    return {
        "provider": req.provider,
        "success": resp.success,
        "content": resp.content[:200] if resp.success else None,
        "latency_ms": round(resp.latency_ms, 1),
        "error": resp.error,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# POLICIES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/api/policies")
async def get_policies(db: Session = Depends(get_db)):
    result = db.execute(select(Policy).order_by(Policy.priority.desc()))
    policies = result.scalars().all()
    return [
        {
            "id": p.id,
            "entity_type": p.entity_type,
            "action": p.action,
            "enabled": p.enabled,
            "priority": p.priority,
            "description": p.description,
        }
        for p in policies
    ]


@app.put("/api/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    req: PolicyUpdateRequest,
    db: Session = Depends(get_db),
):
    result = db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    if req.action:
        if req.action not in ("ALLOW", "MASK", "TOKENIZE", "BLOCK"):
            raise HTTPException(400, "Invalid action")
        policy.action = req.action
    if req.enabled is not None:
        policy.enabled = req.enabled
    if req.description:
        policy.description = req.description
    db.commit()
    return {"success": True, "id": policy_id}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# AUDIT LOGS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/api/audit")
async def get_audit(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    result = db.execute(
        select(AuditEvent)
        .order_by(desc(AuditEvent.timestamp))
        .limit(limit)
        .offset(offset)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_kind": e.event_kind,
            "summary": e.summary,
            "prev_hash": e.prev_hash,
            "self_hash": e.self_hash,
        }
        for e in events
    ]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# REQUEST LOG (Firewall Live Feed)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/api/requests")
async def get_requests(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    is_redteam: bool = False,
    db: Session = Depends(get_db),
):
    """Return paginated request log for the Firewall Live dashboard."""
    q = select(DBRequest).where(DBRequest.is_redteam == is_redteam)
    if action:
        q = q.where(DBRequest.action == action.upper())
    q = q.order_by(desc(DBRequest.timestamp)).limit(limit).offset(offset)
    rows = db.execute(q).scalars().all()

    # Fetch security events for each request in one query
    req_ids = [r.id for r in rows]
    events_q = db.execute(
        select(SecurityEvent).where(SecurityEvent.request_id.in_(req_ids))
    )
    events_by_req: dict[str, list] = {}
    for ev in events_q.scalars().all():
        events_by_req.setdefault(ev.request_id, []).append({
            "entity_type": ev.entity_type,
            "event_type": ev.event_type,
            "action": ev.action,
            "masked_value": ev.masked_value,
        })

    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "session_id": r.session_id,
            "provider": r.provider,
            "model": r.model,
            "risk_score": round(r.risk_score, 2),
            "risk_level": r.risk_level,
            "action": r.action,
            "status": r.status,
            "processing_time_ms": round(r.processing_time_ms or 0, 1),
            "provider_latency_ms": round(r.provider_latency_ms or 0, 1),
            "security_events": events_by_req.get(r.id, []),
            "entity_count": len(events_by_req.get(r.id, [])),
        }
        for r in rows
    ]




# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ANALYTICS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.get("/api/analytics")
async def get_analytics(db: Session = Depends(get_db)):
    # Total requests (production only)
    total_q = db.execute(
        select(func.count()).select_from(DBRequest).where(DBRequest.is_redteam == False)
    )
    total = total_q.scalar_one()

    blocked_q = db.execute(
        select(func.count()).select_from(DBRequest)
        .where(and_(DBRequest.action == "BLOCK", DBRequest.is_redteam == False))
    )
    blocked = blocked_q.scalar_one()

    masked_q = db.execute(
        select(func.count()).select_from(DBRequest)
        .where(and_(DBRequest.action == "MASK", DBRequest.is_redteam == False))
    )
    masked = masked_q.scalar_one()

    allowed_q = db.execute(
        select(func.count()).select_from(DBRequest)
        .where(and_(DBRequest.action == "ALLOW", DBRequest.is_redteam == False))
    )
    allowed = allowed_q.scalar_one()

    avg_risk_q = db.execute(
        select(func.avg(DBRequest.risk_score))
        .where(DBRequest.is_redteam == False)
    )
    avg_risk = avg_risk_q.scalar_one() or 0.0

    # Entity type breakdown
    entity_q = db.execute(
        select(SecurityEvent.entity_type, func.count().label("count"))
        .where(SecurityEvent.direction == "inbound")
        .group_by(SecurityEvent.entity_type)
        .order_by(desc("count"))
        .limit(10)
    )
    entity_breakdown = [{"entity_type": r.entity_type, "count": r.count} for r in entity_q]

    # Provider stats
    provider_q = db.execute(
        select(
            ProviderCall.provider,
            func.count().label("calls"),
            func.sum(case((ProviderCall.success == True, 1), else_=0)).label("successful_calls"),
            func.sum(case((ProviderCall.success == False, 1), else_=0)).label("failed_calls"),
            func.avg(case((ProviderCall.success == True, ProviderCall.latency_ms), else_=None)).label("avg_latency")
        )
        .group_by(ProviderCall.provider)
    )
    provider_stats = []
    for r in provider_q:
        avg_latency = round(r.avg_latency, 2) if r.avg_latency is not None else None
        provider_stats.append({
            "provider": r.provider,
            "calls": r.calls,
            "successful_calls": r.successful_calls or 0,
            "failed_calls": r.failed_calls or 0,
            "avg_latency_ms": avg_latency,
        })

    # Recent security events
    recent_events_q = db.execute(
        select(SecurityEvent, DBRequest.timestamp, DBRequest.provider)
        .join(DBRequest, SecurityEvent.request_id == DBRequest.id)
        .where(DBRequest.is_redteam == False)
        .order_by(desc(DBRequest.timestamp))
        .limit(10)
    )
    recent_events = []
    for row in recent_events_q:
        ev = row[0]
        ts = row[1]
        provider = row[2]
        recent_events.append({
            "entity_type": ev.entity_type,
            "event_type": ev.event_type,
            "action": ev.action,
            "provider": provider,
            "timestamp": ts.isoformat() if ts else None,
        })

    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "masked_requests": masked,
        "allowed_requests": allowed,
        "average_risk_score": round(avg_risk, 2),
        "entity_breakdown": entity_breakdown,
        "provider_stats": provider_stats,
        "recent_security_events": recent_events,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# EVALUATION LAB
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/api/evaluation/run")
async def run_evaluation(
    req: EvaluationRequest,
    db: Session = Depends(get_db),
):
    """Run the real firewall against labelled samples and calculate metrics."""
    if not req.samples:
        raise HTTPException(400, "No samples provided")

    tp = fp = tn = fn = 0
    results = []

    for sample in req.samples:
        text = sample.get("text", "")
        expected_action = sample.get("expected_action", "ALLOW").upper()
        expected_entity = sample.get("entity_type", "")

        entities = pii_scanner.scan(text)
        inj = injection_detector.detect(text)
        risk = risk_engine.calculate(
            entities=entities,
            injection_detected=inj.injection_detected,
            injection_confidence=inj.confidence,
            injection_risk=inj.risk_contribution,
        )
        entity_types = [e.entity_type for e in entities]
        if inj.injection_detected:
            entity_types.append("PROMPT_INJECTION")
        actual_action = policy_engine.aggregate(entity_types).value if entity_types else "ALLOW"

        correct = actual_action == expected_action
        detected_target = any(
            e.entity_type == expected_entity for e in entities
        ) or (expected_entity == "PROMPT_INJECTION" and inj.injection_detected)

        if expected_action != "ALLOW":
            if detected_target:
                tp += 1
            else:
                fn += 1
        else:
            if not entities and not inj.injection_detected:
                tn += 1
            else:
                fp += 1

        results.append({
            "text_preview": text[:60] + "..." if len(text) > 60 else text,
            "expected_action": expected_action,
            "actual_action": actual_action,
            "expected_entity": expected_entity,
            "detected_entities": entity_types,
            "risk_score": risk.risk_score,
            "correct": correct,
        })

    total = len(req.samples)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    run = EvaluationRun(
        name=req.name,
        total_samples=total,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        results_json=json.dumps(results),
    )
    db.add(run)
    db.commit()

    return {
        "run_id": run.id,
        "name": req.name,
        "total_samples": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "results": results,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RED TEAM LAB
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@app.post("/api/redteam/run")
async def run_redteam(
    req: RedTeamRequest,
    db: Session = Depends(get_db),
):
    """
    Controlled red team test â€” clearly isolated from production statistics.
    All records are flagged is_redteam=True.
    """
    messages = [{"role": "user", "content": req.payload}]

    result = await run_firewall_pipeline(
        messages=messages,
        provider_name=req.provider or "openai",
        model=req.model or getattr(adapter, "_default_model", None) or settings.default_model,
        session_id=f"redteam-{uuid.uuid4()}",
        db=db,
        is_redteam=True,
    )

    passed = result.action == req.expected_action or (
        req.expected_action == "BLOCK" and result.blocked
    )

    return {
        "test_type": req.test_type,
        "payload_preview": req.payload[:100] + ("..." if len(req.payload) > 100 else ""),
        "expected_action": req.expected_action,
        "actual_action": result.action,
        "passed": passed,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "detected_entities": result.detected_entities,
        "blocked": result.blocked,
        "provider_called": not result.blocked,
        "note": "RED TEAM TEST â€” results are isolated from production analytics",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=True,
    )




