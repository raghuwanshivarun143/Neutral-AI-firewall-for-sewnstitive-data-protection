"""
CIPHER01 — Risk Engine
Calculates a 0–10 risk score from all scan results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.scanners.pii import DetectedEntity


RISK_LEVELS = {
    (0.0, 2.9): "LOW",
    (3.0, 5.9): "MEDIUM",
    (6.0, 7.9): "HIGH",
    (8.0, 10.1): "CRITICAL",
}


def _risk_level(score: float) -> str:
    for (lo, hi), label in RISK_LEVELS.items():
        if lo <= score <= hi:
            return label
    return "CRITICAL"


@dataclass
class RiskResult:
    risk_score: float
    risk_level: str
    reasons: list[str] = field(default_factory=list)
    entity_types: list[str] = field(default_factory=list)


class RiskEngine:
    """
    Aggregates signals from all scanners into a single 0–10 risk score.
    Scoring is multiplicative / additive based on the severity of findings.
    """

    def calculate(
        self,
        entities: list[DetectedEntity],
        injection_detected: bool = False,
        injection_confidence: float = 0.0,
        injection_risk: float = 0.0,
        encoding_detected: bool = False,
        encoding_risk: float = 0.0,
        session_risk_history: float = 0.0,
        outbound_risk: float = 0.0,
        message_count: int = 1,
    ) -> RiskResult:
        score = 0.0
        reasons: list[str] = []
        entity_types: list[str] = []

        # ── Entity risk ───────────────────────────────────────────────────────
        if entities:
            # Use the single highest-risk entity as the base
            max_entity_risk = max(e.risk_contribution for e in entities)
            score = max(score, max_entity_risk)
            entity_types = list({e.entity_type for e in entities})

            for e in entities:
                reasons.append(f"{e.entity_type} detected (confidence: {e.confidence:.0%})")

            # Multiple entities increase risk slightly
            if len(entities) > 1:
                score = min(score + len(entities) * 0.2, 10.0)
                reasons.append(f"Multiple sensitive entities detected ({len(entities)} total)")

        # ── Prompt injection ──────────────────────────────────────────────────
        if injection_detected:
            score = max(score, injection_risk)
            reasons.append(
                f"Prompt injection attempt detected (confidence: {injection_confidence:.0%})"
            )

        # ── Encoded payload ───────────────────────────────────────────────────
        if encoding_detected:
            score = min(score + encoding_risk, 10.0)
            reasons.append("Encoded/obfuscated payload detected — decoded and rescanned")

        # ── Session history ────────────────────────────────────────────────────
        if session_risk_history > 5.0:
            bonus = min((session_risk_history - 5.0) * 0.3, 2.0)
            score = min(score + bonus, 10.0)
            reasons.append(
                f"Elevated session risk history (cumulative: {session_risk_history:.1f})"
            )

        # ── Outbound leak ─────────────────────────────────────────────────────
        if outbound_risk > 0:
            score = max(score, outbound_risk)
            reasons.append("Sensitive data detected in provider response (outbound)")

        # ── Multi-turn escalation ─────────────────────────────────────────────
        if message_count > 5 and score > 3.0:
            score = min(score + 0.5, 10.0)
            reasons.append("Multi-turn conversation with escalating risk")

        score = min(round(score, 2), 10.0)
        if not reasons:
            reasons = ["No sensitive content detected"]

        return RiskResult(
            risk_score=score,
            risk_level=_risk_level(score),
            reasons=reasons,
            entity_types=entity_types,
        )


risk_engine = RiskEngine()
