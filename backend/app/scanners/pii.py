"""
CIPHER01 — PII & Secrets Scanner
Regex-first, layered approach. No external ML model required.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectedEntity:
    entity_type: str
    value: str           # original matched value
    masked_value: str    # safe representation (never raw secret)
    start: int
    end: int
    confidence: float
    risk_contribution: float
    detector: str        # which regex/detector fired


# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS: list[tuple[str, str, re.Pattern, float, float]] = [
    # (entity_type, masked_template, pattern, confidence, risk_contribution)

    # ── AI / Cloud Keys ───────────────────────────────────────────────────────
    ("OPENAI_KEY",      "[OPENAI_KEY_REDACTED]",     re.compile(r"sk-[A-Za-z0-9]{20,}"),                               0.98, 9.5),
    ("ANTHROPIC_KEY",   "[ANTHROPIC_KEY_REDACTED]",  re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),                       0.98, 9.5),
    ("GITHUB_TOKEN",    "[GITHUB_TOKEN_REDACTED]",   re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),                       0.98, 9.0),
    ("AWS_ACCESS_KEY",  "[AWS_ACCESS_KEY_REDACTED]", re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"), 0.99, 9.5),
    ("AWS_SECRET_KEY",  "[AWS_SECRET_KEY_REDACTED]", re.compile(r"(?i)aws.{0,20}secret.{0,10}['\"]?([A-Za-z0-9/+=]{40})['\"]?"), 0.95, 9.5),
    ("GOOGLE_KEY",      "[GOOGLE_KEY_REDACTED]",     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                            0.97, 9.0),
    ("BEARER_TOKEN",    "[BEARER_TOKEN_REDACTED]",   re.compile(r"(?i)bearer\s+([A-Za-z0-9\-_=.]{20,})"),              0.85, 8.0),
    ("API_KEY",         "[API_KEY_REDACTED]",        re.compile(r"(?i)(api[_\-\s]?key|apikey)\s*(?:is|[=:])\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?"), 0.90, 8.5),

    # ── JWT ───────────────────────────────────────────────────────────────────
    ("JWT",             "[JWT_REDACTED]",            re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"), 0.99, 8.0),

    # ── Private / SSH Keys ────────────────────────────────────────────────────
    ("PRIVATE_KEY",     "[PRIVATE_KEY_REDACTED]",   re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----"), 0.99, 10.0),
    ("SSH_KEY",         "[SSH_KEY_REDACTED]",        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),                0.99, 10.0),

    # ── Passwords ─────────────────────────────────────────────────────────────
    ("PASSWORD",        "[PASSWORD_REDACTED]",       re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?"), 0.88, 9.0),
    ("DB_PASSWORD",     "[DB_PASSWORD_REDACTED]",    re.compile(r"(?i)(db_pass|database_password|mysql_password|postgres_password)\s*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?"), 0.90, 9.0),

    # ── URLs with credentials ─────────────────────────────────────────────────
    ("URL_WITH_CREDS",  "[URL_CREDS_REDACTED]",     re.compile(r"(https?|ftp)://[^:@\s]+:[^@\s]+@[^\s]+"),             0.95, 8.0),

    # ── Financial ─────────────────────────────────────────────────────────────
    ("CREDIT_CARD",     "[CREDIT_CARD_REDACTED]",   re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b"), 0.90, 8.5),
    ("BANK_ACCOUNT",    "[BANK_ACCOUNT_REDACTED]",  re.compile(r"(?i)\b[0-9]{9,18}\b(?=.*(account|acct|bank))"),       0.70, 7.5),
    ("IFSC",            "[IFSC_REDACTED]",           re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),                           0.85, 5.0),

    # ── Indian IDs ────────────────────────────────────────────────────────────
    ("AADHAAR",         "[AADHAAR_REDACTED]",        re.compile(r"\b[2-9]{1}[0-9]{3}\s*[0-9]{4}\s*[0-9]{4}\b"),        0.90, 8.0),
    ("PAN",             "[PAN_REDACTED]",            re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),                         0.88, 7.0),

    # ── US IDs ────────────────────────────────────────────────────────────────
    ("SSN",             "[SSN_REDACTED]",            re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"), 0.85, 8.5),

    # ── Contact ───────────────────────────────────────────────────────────────
    ("EMAIL",           "[EMAIL_REDACTED]",          re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), 0.98, 5.0),
    ("PHONE",           "[PHONE_REDACTED]",          re.compile(r"(?:(?:\+91|0091|91)?[\s\-]?)?[6-9]\d{9}\b|(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"), 0.80, 4.0),
    ("IP_ADDRESS",      "[IP_REDACTED]",             re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), 0.95, 3.5),

    # ── Employee/Customer IDs ─────────────────────────────────────────────────
    ("EMPLOYEE_ID",     "[EMP_ID_REDACTED]",         re.compile(r"\b(?:EMP|EID|EMPID)[_\-]?[0-9]{4,10}\b", re.IGNORECASE), 0.75, 4.0),
    ("CUSTOMER_ID",     "[CUST_ID_REDACTED]",        re.compile(r"\b(?:CUST|CID|CUSTID)[_\-]?[0-9]{4,12}\b", re.IGNORECASE), 0.75, 4.0),

    # ── Cloud credentials ─────────────────────────────────────────────────────
    ("GCP_CREDENTIAL",  "[GCP_CRED_REDACTED]",      re.compile(r'"type"\s*:\s*"service_account"'),                     0.90, 9.0),
]


def _mask_value(value: str, entity_type: str, masked_template: str) -> str:
    """Return a safe representation — never include the raw secret."""
    if len(value) <= 6:
        return masked_template
    # Show first 2 + last 2 chars for email-like patterns; else redact fully
    if entity_type == "EMAIL":
        parts = value.split("@")
        if len(parts) == 2:
            local = parts[0]
            domain = parts[1]
            safe_local = local[:2] + "***" if len(local) > 2 else "***"
            return f"{safe_local}@{domain}"
    return masked_template


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ln = len(s)
    return -sum((v / ln) * math.log2(v / ln) for v in freq.values())


HIGH_ENTROPY_THRESHOLD = 4.2
MIN_HIGH_ENTROPY_LEN = 20


def _detect_high_entropy_strings(text: str) -> list[DetectedEntity]:
    """Detect generic high-entropy strings that may be secrets."""
    results: list[DetectedEntity] = []
    # Look for long alphanumeric+special strings
    for m in re.finditer(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]", text):
        candidate = m.group(1)
        ent = _entropy(candidate)
        if ent >= HIGH_ENTROPY_THRESHOLD:
            start = m.start(1)
            end = m.end(1)
            results.append(
                DetectedEntity(
                    entity_type="HIGH_ENTROPY",
                    value=candidate,
                    masked_value="[HIGH_ENTROPY_REDACTED]",
                    start=start,
                    end=end,
                    confidence=min(0.5 + (ent - HIGH_ENTROPY_THRESHOLD) * 0.1, 0.90),
                    risk_contribution=6.0,
                    detector="entropy",
                )
            )
    return results


class PIIScanner:
    """
    Scans text for PII, secrets, credentials using regex patterns.
    Returns a list of DetectedEntity objects.
    """

    def scan(self, text: str) -> list[DetectedEntity]:
        if not text or not text.strip():
            return []
        results: list[DetectedEntity] = []
        seen_spans: list[tuple[int, int]] = []

        for entity_type, masked_template, pattern, confidence, risk in PATTERNS:
            for m in pattern.finditer(text):
                span = (m.start(), m.end())
                # Avoid duplicate overlapping spans
                overlap = any(
                    not (span[1] <= s[0] or span[0] >= s[1]) for s in seen_spans
                )
                if overlap:
                    continue
                seen_spans.append(span)

                raw_value = m.group(0)
                safe_value = _mask_value(raw_value, entity_type, masked_template)

                results.append(
                    DetectedEntity(
                        entity_type=entity_type,
                        value=raw_value,
                        masked_value=safe_value,
                        start=span[0],
                        end=span[1],
                        confidence=confidence,
                        risk_contribution=risk,
                        detector="regex",
                    )
                )

        # High-entropy detection
        he_results = _detect_high_entropy_strings(text)
        for he in he_results:
            overlap = any(
                not (he.end <= s[0] or he.start >= s[1]) for s in seen_spans
            )
            if not overlap:
                seen_spans.append((he.start, he.end))
                results.append(he)

        return results

    def redact(self, text: str, entities: list[DetectedEntity]) -> str:
        """Replace detected entities in text with their masked values."""
        if not entities:
            return text
        # Sort by start position descending to safely replace without offset shift
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        chars = list(text)
        for entity in sorted_entities:
            chars[entity.start : entity.end] = list(entity.masked_value)
        return "".join(chars)


# Singleton
pii_scanner = PIIScanner()
