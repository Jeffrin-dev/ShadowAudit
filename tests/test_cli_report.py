"""CLI tests for report generation."""

from __future__ import annotations

import json
from pathlib import Path

from shadowaudit.cli import main
from shadowaudit.core.audit import AuditLogger
from shadowaudit.core.models import AuditEvent, ScanResult


def test_report_gdpr_command(tmp_path: Path, capsys, monkeypatch) -> None:
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)
    logger.append(
        AuditEvent(
            timestamp="2026-01-15T12:00:00Z",
            request_id="r1",
            scan_result=ScanResult(
                request_id="r1",
                detected_entities=["EMAIL"],
                secrets_found=[],
                action_taken="detected",
                tokens_before=10,
                tokens_after=10,
            ),
            policy_applied="gdpr_default",
            model_target="gpt-model",
            response_clean=False,
        )
    )

    monkeypatch.chdir(tmp_path)

    import sys

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "report", "--format", "gdpr", "--from", "2026-01-01", "--to", "2026-01-31"]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["summary"]["total_events"] == 1
