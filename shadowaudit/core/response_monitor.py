"""Post-response monitoring for potential PII leakage."""

from __future__ import annotations

from typing import Any

from shadowaudit.core.models import ScanResult
from shadowaudit.core.scanner import PIIScanner


class ResponseMonitor:
    """Scan model responses for leaked PII and decoded redaction substitutions."""

    def __init__(
        self,
        original_scan: ScanResult,
        response_text: str,
        *,
        config: dict[str, Any] | None = None,
        scanner: PIIScanner | None = None,
        response_threshold: float = 0.35,
    ) -> None:
        self.original_scan = original_scan
        self.response_text = response_text
        self.config = config or {}
        self.scanner = scanner or PIIScanner(fast_mode=True)
        self.response_threshold = response_threshold

    def evaluate(self) -> dict[str, Any]:
        """Evaluate response text and return log/redact recommendation details."""

        findings: list[str] = []

        detections = self.scanner.detect(self.response_text, score_threshold=self.response_threshold)
        if detections:
            entities = sorted({item.entity_type for item in detections})
            findings.append(f"PII detected in response: {', '.join(entities)}")

        substitution_map = self.original_scan.substitution_map or {}
        for token, original in substitution_map.items():
            if original and original in self.response_text:
                findings.append(f"Decoded substitution detected: {token} -> {original}")

        configured_action = str(self.config.get("response_monitor_action", "log")).strip().lower()
        action = "redact" if configured_action == "redact" else "log"

        return {
            "flagged": bool(findings),
            "findings": findings,
            "action": action,
        }
