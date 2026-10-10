"""
CIPHER01 — Policy Engine
Determines ALLOW / MASK / TOKENIZE / BLOCK per entity type.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    BLOCK = "BLOCK"


# ─── Hard-coded fallback defaults (overridden by DB policies) ────────────────
_FALLBACK_POLICIES: dict[str, PolicyAction] = {
    "API_KEY": PolicyAction.BLOCK,
    "OPENAI_KEY": PolicyAction.BLOCK,
    "ANTHROPIC_KEY": PolicyAction.BLOCK,
    "AWS_ACCESS_KEY": PolicyAction.BLOCK,
    "AWS_SECRET_KEY": PolicyAction.BLOCK,
    "GITHUB_TOKEN": PolicyAction.BLOCK,
    "JWT": PolicyAction.BLOCK,
    "PRIVATE_KEY": PolicyAction.BLOCK,
    "SSH_KEY": PolicyAction.BLOCK,
    "PASSWORD": PolicyAction.BLOCK,
    "DB_PASSWORD": PolicyAction.BLOCK,
    "BEARER_TOKEN": PolicyAction.BLOCK,
    "PROMPT_INJECTION": PolicyAction.BLOCK,
    "ENCODED_SECRET": PolicyAction.BLOCK,
    "GCP_CREDENTIAL": PolicyAction.BLOCK,
    "CREDIT_CARD": PolicyAction.MASK,
    "BANK_ACCOUNT": PolicyAction.MASK,
    "AADHAAR": PolicyAction.MASK,
    "PAN": PolicyAction.MASK,
    "IFSC": PolicyAction.MASK,
    "EMAIL": PolicyAction.MASK,
    "PHONE": PolicyAction.MASK,
    "IP_ADDRESS": PolicyAction.MASK,
    "SSN": PolicyAction.MASK,
    "URL_WITH_CREDS": PolicyAction.MASK,
    "HIGH_ENTROPY": PolicyAction.MASK,
    "EMPLOYEE_ID": PolicyAction.MASK,
    "CUSTOMER_ID": PolicyAction.MASK,
    "GOOGLE_KEY": PolicyAction.BLOCK,
    "PERSON": PolicyAction.TOKENIZE,
    "CONFIDENTIAL_DOC": PolicyAction.TOKENIZE,
}


@dataclass
class PolicyDecision:
    action: PolicyAction
    entity_type: str
    reason: str
    policy_source: str = "database"  # database | fallback


class PolicyEngine:
    """
    Looks up the configured action for each entity type.
    Falls back to built-in defaults when database is unavailable.
    Aggregates multiple entity decisions to produce the most restrictive action.
    """

    def __init__(self, db_policies: Optional[dict[str, str]] = None):
        self._db: dict[str, PolicyAction] = {}
        if db_policies:
            self.update(db_policies)

    def update(self, db_policies: dict[str, str]) -> None:
        """Load current policies from the database."""
        self._db = {k: PolicyAction(v) for k, v in db_policies.items()}

    def get_action(self, entity_type: str) -> PolicyDecision:
        et = entity_type.upper()
        if et in self._db:
            action = self._db[et]
            return PolicyDecision(
                action=action,
                entity_type=entity_type,
                reason=f"Configured policy for {entity_type}: {action.value}",
                policy_source="database",
            )
        fallback = _FALLBACK_POLICIES.get(et, PolicyAction.MASK)
        return PolicyDecision(
            action=fallback,
            entity_type=entity_type,
            reason=f"Default policy for {entity_type}: {fallback.value}",
            policy_source="fallback",
        )

    def aggregate(self, entity_types: list[str]) -> PolicyAction:
        """Return the most restrictive action across multiple entity types."""
        priority = {
            PolicyAction.BLOCK: 3,
            PolicyAction.MASK: 2,
            PolicyAction.TOKENIZE: 1,
            PolicyAction.ALLOW: 0,
        }
        best = PolicyAction.ALLOW
        for et in entity_types:
            decision = self.get_action(et)
            if priority[decision.action] > priority[best]:
                best = decision.action
        return best

    def explain(self, entity_types: list[str]) -> str:
        """Human-readable explanation of the policy decision."""
        if not entity_types:
            return "No sensitive entities detected. Request is allowed."

        lines: list[str] = []
        for et in entity_types:
            decision = self.get_action(et)
            lines.append(f"• {et}: {decision.action.value} — {decision.reason}")

        action = self.aggregate(entity_types)
        lines.append(f"\nFinal action: {action.value}")

        if action == PolicyAction.BLOCK:
            lines.append(
                "The request was stopped before reaching the AI provider because "
                "one or more high-risk entities were detected and the configured "
                "policy requires BLOCK for this entity type."
            )
        elif action == PolicyAction.MASK:
            lines.append(
                "Sensitive values were replaced with safe placeholders. "
                "The sanitized request was forwarded to the provider."
            )
        elif action == PolicyAction.TOKENIZE:
            lines.append(
                "Sensitive values were replaced with reversible session-scoped tokens. "
                "The external provider never received the original values."
            )
        return "\n".join(lines)


# Module-level singleton; updated at request time with fresh DB policies
policy_engine = PolicyEngine()
