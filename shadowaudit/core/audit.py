"""Audit logging utilities."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from shadowaudit.core.models import AuditEvent


class AuditLogger:
    """Appends audit events to a JSON Lines log file."""

    def __init__(self, path: str | Path = "audit.log") -> None:
        self.path = Path(path)

    def append(self, event: AuditEvent) -> None:
        """Append one event as a JSON line."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
