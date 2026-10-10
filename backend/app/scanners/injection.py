"""
CIPHER01 — Prompt Injection Detector
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


INJECTION_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # (reason, pattern, confidence)
    ("Ignore previous instructions",       re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|rules?|constraints?|guidelines?)"), 0.97),
    ("Reveal system prompt",               re.compile(r"(?i)(reveal|show|print|output|display|repeat|tell me|give me)\s+(the\s+)?(system\s+prompt|hidden\s+prompt|initial\s+instructions?|secret\s+instructions?)"), 0.95),
    ("Disregard security rules",           re.compile(r"(?i)(disregard|forget|bypass|ignore|override|skip)\s+(security|safety|firewall|content|filter|restriction|policy|guideline|rule)"), 0.95),
    ("DAN / jailbreak mode",               re.compile(r"(?i)(DAN|do\s+anything\s+now|unrestricted\s+mode|jailbreak|developer\s+mode|god\s+mode|evil\s+mode|no\s+filter\s+mode)"), 0.98),
    ("Print hidden/secret keys",           re.compile(r"(?i)(print|show|output|reveal|display)\s+(my\s+)?(secret|private|hidden|confidential)\s+(key|keys|token|tokens|password|credential)"), 0.93),
    ("Act as unrestricted",                re.compile(r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(an\s+)?(unrestricted|unfiltered|uncensored|free\s+from|no\s+restrictions)"), 0.92),
    ("Prompt leak attempt",                re.compile(r"(?i)(what\s+(are|is)\s+(your|the)\s+(instructions?|system\s+prompt|context|rules|guidelines))"), 0.85),
    ("Indirect injection marker",          re.compile(r"(?i)(<<<|>>>|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<system>|<\/system>|###\s*(SYSTEM|ASSISTANT|USER))"), 0.90),
    ("Bypass firewall",                    re.compile(r"(?i)(bypass|circumvent|evade|fool|trick)\s+(the\s+)?(firewall|filter|detector|scanner|security|censor|safety|ai\s+guard)"), 0.97),
    ("Inject new role",                    re.compile(r"(?i)(you\s+are\s+now|pretend\s+you\s+are|roleplay\s+as|act\s+like|simulate\s+being)\s+(a\s+)?(hacker|malicious|evil|unrestricted)"), 0.90),
    ("Extract training data",              re.compile(r"(?i)(training\s+data|training\s+examples|repeat\s+back|verbatim|word\s+for\s+word)\s+(from\s+your)?(memory|context|training)"), 0.88),
    ("Encoding bypass attempt",            re.compile(r"(?i)(base64|hex|rot13|unicode\s+escape|url\s+encode|obfuscat)\s+(this|the|my)\s+(instruction|prompt|command|request)"), 0.87),
    ("Overwrite instructions",             re.compile(r"(?i)(overwrite|replace|reset|clear|delete)\s+(all\s+)?(previous|prior|above|existing)\s+(instructions?|context|rules?|system)"), 0.93),
    ("Reveal confidential info",           re.compile(r"(?i)(reveal|expose|disclose|leak|output)\s+(confidential|private|sensitive|secret|protected|internal)\s+(information|data|details|documents?)"), 0.88),
    ("Exfiltration via tool call",         re.compile(r"(?i)(send|post|upload|transmit|forward|exfiltrate)\s+(all\s+)?(data|context|prompt|information|secrets?)\s+(to|via|through)\s+(url|endpoint|server|api|webhook)"), 0.92),
]

# Severity weights per confidence tier
def _tier_risk(confidence: float) -> float:
    if confidence >= 0.95:
        return 9.0
    elif confidence >= 0.90:
        return 7.5
    elif confidence >= 0.85:
        return 6.0
    return 4.5


@dataclass
class InjectionResult:
    injection_detected: bool
    confidence: float
    reasons: list[str] = field(default_factory=list)
    matched_indicators: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0


class InjectionDetector:
    """
    Detects prompt injection attempts using pattern matching.
    Checks both direct and indirect injection indicators.
    """

    def detect(self, text: str) -> InjectionResult:
        if not text or not text.strip():
            return InjectionResult(injection_detected=False, confidence=0.0)

        matched_reasons: list[str] = []
        matched_indicators: list[str] = []
        max_confidence = 0.0
        max_risk = 0.0

        for reason, pattern, confidence in INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                matched_reasons.append(reason)
                matched_indicators.append(m.group(0)[:80])  # truncate for safety
                if confidence > max_confidence:
                    max_confidence = confidence
                r = _tier_risk(confidence)
                if r > max_risk:
                    max_risk = r

        if matched_reasons:
            return InjectionResult(
                injection_detected=True,
                confidence=max_confidence,
                reasons=matched_reasons,
                matched_indicators=matched_indicators,
                risk_contribution=max_risk,
            )
        return InjectionResult(injection_detected=False, confidence=0.0)


injection_detector = InjectionDetector()
