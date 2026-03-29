"""Audit logging and GDPR report tests."""

from __future__ import annotations

import json
from pathlib import Path

from shadowaudit.core.audit import AuditLogger
from shadowaudit.core.models import AuditEvent, ScanResult
from shadowaudit.reports.gdpr_report import generate_gdpr_report


def _event(ts: str, request_id: str, entities: list[str], *, secrets: list[str] | None = None) -> AuditEvent:
    return AuditEvent(
        timestamp=ts,
        request_id=request_id,
        scan_result=ScanResult(
            request_id=request_id,
            detected_entities=entities,
            secrets_found=secrets or [],
            action_taken="detected" if entities else "clean",
            tokens_before=3,
            tokens_after=3,
        ),
        policy_applied="gdpr_default",
        model_target="gpt-model",
        response_clean=not entities,
    )


def test_audit_logger_appends_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    logger.append(_event("2026-01-10T10:00:00Z", "req-1", ["EMAIL"]))

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["request_id"] == "req-1"
    assert payload["scan_result"]["detected_entities"] == ["EMAIL"]


def test_generate_gdpr_report_filters_date_range(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    logger.append(_event("2026-01-10T10:00:00Z", "req-1", ["EMAIL"]))
    logger.append(_event("2026-02-10T10:00:00Z", "req-2", ["PHONE"]))

    report = generate_gdpr_report("2026-01-01", "2026-01-31", log_path=log_path)

    assert report["article"] == "GDPR Article 30"
    assert report["summary"]["total_events"] == 1
    assert report["summary"]["detected_entity_types"] == {"EMAIL": 1}


def test_generate_gdpr_report_includes_secrets_in_summary_and_processing(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    logger.append(_event("2026-01-10T10:00:00Z", "req-1", [], secrets=["sk-abc123"]))

    report = generate_gdpr_report("2026-01-01", "2026-01-31", log_path=log_path)

    assert report["summary"]["detected_entity_types"] == {"SECRET": 1}
    assert "API keys and credentials" in report["processing"]["categories_of_personal_data"]
