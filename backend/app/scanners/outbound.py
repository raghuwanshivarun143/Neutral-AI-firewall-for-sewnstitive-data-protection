"""
CIPHER01 — Outbound Scanner
Scans AI provider responses before returning them to the user.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.scanners.pii import DetectedEntity, pii_scanner
from app.scanners.injection import injection_detector
from app.config import settings


SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"https?://[^\s]*\.(xyz|tk|ml|ga|cf|pw|top|click|link)(/[^\s]*)?", re.IGNORECASE),
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    re.compile(r"https?://[^\s]*?(login|phish|secure-|verify-|account-update)", re.IGNORECASE),
]

CANARY_PATTERN = re.compile(r"CIPHER01_CANARY_[A-Za-z0-9]{4,16}")

DATA_LEAK_PATTERNS = [
    re.compile(r"(?i)(your\s+)?(api\s+key|password|secret|token)\s+(is\s*:?\s*|:\s*)", ),
    re.compile(r"(?i)(here\s+is|found|retrieved|stored)\s+(your\s+)?(secret|credential|private\s+key|password)"),
    re.compile(r"(?i)(exposing|leaked|revealed)\s+(confidential|private|secret|sensitive)\s+(data|information)"),
]


@dataclass
class OutboundScanResult:
    safe: bool
    entities: list[DetectedEntity] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    canary_tokens_found: list[str] = field(default_factory=list)
    data_leak_indicators: list[str] = field(default_factory=list)
    injection_in_response: bool = False
    risk_contribution: float = 0.0
    sanitized_text: str = ""


class OutboundScanner:
    """
    Scans AI provider responses for:
    - PII/secrets accidentally exposed by the AI
    - Suspicious URLs
    - Canary token reappearance
    - Data leak language
    - Prompt injection embedded in AI responses (indirect injection)
    """

    def scan(self, response_text: str) -> OutboundScanResult:
        result = OutboundScanResult(safe=True, sanitized_text=response_text)
        if not response_text:
            return result

        # PII/Secrets in response
        entities = pii_scanner.scan(response_text)
        if entities:
            result.safe = False
            result.entities = entities
            result.risk_contribution += max((e.risk_contribution for e in entities), default=0)

        # Suspicious URLs
        for pattern in SUSPICIOUS_URL_PATTERNS:
            for m in pattern.finditer(response_text):
                result.suspicious_urls.append(m.group(0))
                result.safe = False
                result.risk_contribution += 5.0

        # Canary token detection
        if settings.enable_canary_tokens:
            for m in CANARY_PATTERN.finditer(response_text):
                result.canary_tokens_found.append(m.group(0))
                result.safe = False
                result.risk_contribution += 8.0

        # Data leak language
        for pattern in DATA_LEAK_PATTERNS:
            for m in pattern.finditer(response_text):
                result.data_leak_indicators.append(m.group(0)[:80])
                result.safe = False
                result.risk_contribution += 4.0

        # Indirect prompt injection in response
        inj = injection_detector.detect(response_text)
        if inj.injection_detected:
            result.injection_in_response = True
            result.safe = False
            result.risk_contribution += inj.risk_contribution

        # Sanitize
        if not result.safe and result.entities:
            result.sanitized_text = pii_scanner.redact(response_text, result.entities)

        return result


outbound_scanner = OutboundScanner()
