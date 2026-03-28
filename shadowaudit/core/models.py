"""Data models for ShadowAudit scan and audit records."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScanResult:
    """Represents the outcome of scanning a single request for sensitive content."""

    request_id: str
    detected_entities: list[str]
    secrets_found: list[str]
    action_taken: str
    tokens_before: int
    tokens_after: int
    substitution_map: dict[str, str] | None = None


@dataclass
class AuditEvent:
    """Represents an auditable event that records scan details and applied policy."""

    timestamp: str
    request_id: str
    scan_result: ScanResult
    policy_applied: str
    model_target: str
    response_clean: bool
