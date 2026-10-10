"""
CIPHER01 — Redaction Engine
Context-preserving redaction that maintains prompt structure.
"""
from __future__ import annotations

from app.scanners.pii import DetectedEntity, pii_scanner
from app.engines.tokenization import tokenization_engine
from app.engines.policy import PolicyAction, policy_engine


def redact_text(
    text: str,
    entities: list[DetectedEntity],
    session_id: str,
    db_policies: dict[str, str] | None = None,
) -> tuple[str, list[str]]:
    """
    Apply policy-driven redaction to text.
    Returns (sanitized_text, list_of_applied_actions).
    """
    if db_policies:
        policy_engine.update(db_policies)

    if not entities:
        return text, []

    actions_taken: list[str] = []
    tokenize_types: set[str] = set()
    mask_entities: list[DetectedEntity] = []
    block_found = False

    for entity in entities:
        decision = policy_engine.get_action(entity.entity_type)
        if decision.action == PolicyAction.BLOCK:
            block_found = True
            actions_taken.append(f"BLOCK: {entity.entity_type}")
        elif decision.action == PolicyAction.TOKENIZE:
            tokenize_types.add(entity.entity_type)
            actions_taken.append(f"TOKENIZE: {entity.entity_type}")
        elif decision.action == PolicyAction.MASK:
            mask_entities.append(entity)
            actions_taken.append(f"MASK: {entity.entity_type}")
        else:
            actions_taken.append(f"ALLOW: {entity.entity_type}")

    if block_found:
        return text, actions_taken  # caller should not send to provider

    # Apply tokenization first (replaces from end to start)
    result = tokenization_engine.apply_tokenization(
        text, entities, session_id, tokenize_types
    )

    # Apply masking on remaining entities
    # Re-scan positions may have shifted — safer to use entity masked values
    if mask_entities:
       result = pii_scanner.redact(result, [e for e in entities if e.entity_type not in tokenize_types])
    return result, actions_taken


def redact_messages(
    messages: list[dict],
    session_id: str,
    db_policies: dict[str, str] | None = None,
) -> tuple[list[dict], list[DetectedEntity], list[str], bool]:
    """
    Scan and redact all user/system messages in a chat request.
    Returns (sanitized_messages, all_entities, all_actions, block_flag).
    """
    all_entities: list[DetectedEntity] = []
    all_actions: list[str] = []
    blocked = False
    sanitized: list[dict] = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")

        if not isinstance(content, str):
            sanitized.append(msg)
            continue

        entities = pii_scanner.scan(content)
        all_entities.extend(entities)

        if entities:
            entity_types = [e.entity_type for e in entities]
            agg_action = policy_engine.aggregate(entity_types)

            if agg_action == PolicyAction.BLOCK:
                blocked = True
                all_actions.append(f"BLOCK triggered by: {entity_types}")
                sanitized.append(msg)  # doesn't matter, caller blocks
                continue

        clean_content, actions = redact_text(content, entities, session_id, db_policies)
        all_actions.extend(actions)
        sanitized.append({**msg, "content": clean_content})

    return sanitized, all_entities, all_actions, blocked
