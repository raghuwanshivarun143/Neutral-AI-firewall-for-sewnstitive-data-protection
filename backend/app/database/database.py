"""
CIPHER01 — Database Engine & Session Management
"""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.config import settings
from app.database.models import Base, Policy

logger = logging.getLogger(__name__)

# Ensure sqlite3 is used
db_url = settings.database_url
if db_url.startswith("sqlite+aiosqlite:///"):
    db_url = db_url.replace("sqlite+aiosqlite:///", "sqlite:///")

engine = create_engine(
    db_url,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in db_url else {},
)

SessionLocal = sessionmaker(
    engine,
    class_=Session,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        try:
            yield session
        finally:
            session.close()


DEFAULT_POLICIES = [
    {"entity_type": "API_KEY",          "action": "BLOCK",    "priority": 100, "description": "Cloud/service API credentials"},
    {"entity_type": "OPENAI_KEY",       "action": "BLOCK",    "priority": 100, "description": "OpenAI API key"},
    {"entity_type": "ANTHROPIC_KEY",    "action": "BLOCK",    "priority": 100, "description": "Anthropic API key"},
    {"entity_type": "AWS_ACCESS_KEY",   "action": "BLOCK",    "priority": 100, "description": "AWS access key ID"},
    {"entity_type": "AWS_SECRET_KEY",   "action": "BLOCK",    "priority": 100, "description": "AWS secret access key"},
    {"entity_type": "GITHUB_TOKEN",     "action": "BLOCK",    "priority": 100, "description": "GitHub personal access token"},
    {"entity_type": "JWT",              "action": "BLOCK",    "priority": 90,  "description": "JSON Web Token"},
    {"entity_type": "PRIVATE_KEY",      "action": "BLOCK",    "priority": 100, "description": "PEM private key"},
    {"entity_type": "SSH_KEY",          "action": "BLOCK",    "priority": 100, "description": "SSH private key"},
    {"entity_type": "PASSWORD",         "action": "BLOCK",    "priority": 95,  "description": "Password or passphrase"},
    {"entity_type": "BEARER_TOKEN",     "action": "BLOCK",    "priority": 90,  "description": "HTTP bearer token"},
    {"entity_type": "DB_PASSWORD",      "action": "BLOCK",    "priority": 95,  "description": "Database connection password"},
    {"entity_type": "CREDIT_CARD",      "action": "MASK",     "priority": 85,  "description": "Credit/debit card number"},
    {"entity_type": "BANK_ACCOUNT",     "action": "MASK",     "priority": 85,  "description": "Bank account number"},
    {"entity_type": "AADHAAR",          "action": "MASK",     "priority": 85,  "description": "Indian Aadhaar number"},
    {"entity_type": "PAN",              "action": "MASK",     "priority": 80,  "description": "Indian PAN card number"},
    {"entity_type": "IFSC",             "action": "MASK",     "priority": 70,  "description": "Indian IFSC code"},
    {"entity_type": "EMAIL",            "action": "MASK",     "priority": 60,  "description": "Email address"},
    {"entity_type": "PHONE",            "action": "MASK",     "priority": 60,  "description": "Phone number"},
    {"entity_type": "IP_ADDRESS",       "action": "MASK",     "priority": 50,  "description": "IP address"},
    {"entity_type": "SSN",              "action": "MASK",     "priority": 85,  "description": "Social Security Number"},
    {"entity_type": "PERSON",           "action": "TOKENIZE", "priority": 40,  "description": "Person name (NER)"},
    {"entity_type": "CONFIDENTIAL_DOC", "action": "TOKENIZE", "priority": 70,  "description": "Confidential document"},
    {"entity_type": "PROMPT_INJECTION", "action": "BLOCK",    "priority": 99,  "description": "Prompt injection attempt"},
    {"entity_type": "HIGH_ENTROPY",     "action": "MASK",     "priority": 75,  "description": "High-entropy random string"},
    {"entity_type": "ENCODED_SECRET",   "action": "BLOCK",    "priority": 95,  "description": "Encoded/obfuscated secret"},
    {"entity_type": "URL_WITH_CREDS",   "action": "MASK",     "priority": 80,  "description": "URL containing credentials"},
    {"entity_type": "EMPLOYEE_ID",      "action": "MASK",     "priority": 55,  "description": "Employee identifier"},
]


def init_db() -> None:
    Base.metadata.create_all(engine)

    # Seed default policies if table is empty
    with SessionLocal() as session:
        from sqlalchemy import select, func as sfunc
        count_result = session.execute(
            select(sfunc.count()).select_from(Policy)
        )
        count = count_result.scalar_one()
        if count == 0:
            for p in DEFAULT_POLICIES:
                session.add(Policy(**p))
            session.commit()
            logger.info("Seeded %d default policies", len(DEFAULT_POLICIES))
