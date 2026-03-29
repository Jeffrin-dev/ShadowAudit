"""GDPR reporting helpers built from audit log events."""

from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


def _parse_date(value: str | date) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(value)


def generate_gdpr_report(from_date: str | date, to_date: str | date, *, log_path: str | Path = "audit.log") -> dict[str, Any]:
    """Build a structured GDPR Article 30 style processing report from audit events."""

    start = _parse_date(from_date)
    end = _parse_date(to_date)

    policy_counter: Counter[str] = Counter()
    model_counter: Counter[str] = Counter()
    action_counter: Counter[str] = Counter()
    entity_counter: Counter[str] = Counter()
    total_events = 0

    path = Path(log_path)
    if path.exists():
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                timestamp = str(event.get("timestamp", ""))
                event_day_raw = timestamp.split("T", 1)[0]
                if not event_day_raw:
                    continue

                event_day = date.fromisoformat(event_day_raw)
                if event_day < start or event_day > end:
                    continue

                total_events += 1
                policy_counter.update([event.get("policy_applied", "unknown")])
                model_counter.update([event.get("model_target", "unknown")])

                scan_result = event.get("scan_result", {}) or {}
                action_counter.update([scan_result.get("action_taken", "unknown")])
                detected_entities = scan_result.get("detected_entities", []) or []
                entity_counter.update(detected_entities)

                secrets_found = scan_result.get("secrets_found", []) or []
                if secrets_found:
                    entity_counter.update(["SECRET"])

    categories_of_personal_data = sorted(entity_counter.keys())
    if entity_counter.get("SECRET"):
        categories_of_personal_data.append("API keys and credentials")

    return {
        "article": "GDPR Article 30",
        "record_type": "Record of Processing Activities",
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "summary": {
            "total_events": total_events,
            "policies_applied": dict(policy_counter),
            "models_targeted": dict(model_counter),
            "actions_taken": dict(action_counter),
            "detected_entity_types": dict(entity_counter),
        },
        "processing": {
            "purposes": [
                "PII detection",
                "policy enforcement",
                "security and compliance monitoring",
            ],
            "categories_of_data_subjects": ["application users", "operators"],
            "categories_of_personal_data": categories_of_personal_data,
            "technical_measures": [
                "automated scanning of prompts",
                "event-level audit logging",
                "policy-based action controls",
            ],
            "retention": "Derived from audit.log retention policy",
        },
    }
