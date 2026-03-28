"""Redaction helpers for replacing entities while preserving placeholders."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def _normalize_entity(entity: object) -> tuple[str, int, int, str]:
    if isinstance(entity, dict):
        entity_type = str(entity["entity_type"])
        start = int(entity["start"])
        end = int(entity["end"])
        text = str(entity.get("text", ""))
        return entity_type, start, end, text

    entity_type = str(getattr(entity, "entity_type"))
    start = int(getattr(entity, "start"))
    end = int(getattr(entity, "end"))
    text = str(getattr(entity, "text", ""))
    return entity_type, start, end, text


def redact(text: str, entities: Iterable[object]) -> tuple[str, dict[str, str]]:
    """Replace entities with [TYPE_N] tokens and return redacted text + mapping."""

    normalized = [_normalize_entity(e) for e in entities]
    normalized.sort(key=lambda item: item[1])

    counters: defaultdict[str, int] = defaultdict(int)
    substitution_map: dict[str, str] = {}

    chunks: list[str] = []
    cursor = 0
    for entity_type, start, end, ent_text in normalized:
        if start < cursor:
            continue  # overlap; keep the first replacement.

        chunks.append(text[cursor:start])
        counters[entity_type] += 1
        token = f"[{entity_type}_{counters[entity_type]}]"
        chunks.append(token)
        substitution_map[token] = ent_text or text[start:end]
        cursor = end

    chunks.append(text[cursor:])
    return "".join(chunks), substitution_map
