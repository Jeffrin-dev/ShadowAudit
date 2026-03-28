"""Tests for response monitoring behavior."""

from __future__ import annotations

from shadowaudit.core.models import ScanResult
from shadowaudit.core.response_monitor import ResponseMonitor


def _base_scan_result(*, substitution_map: dict[str, str] | None = None) -> ScanResult:
    return ScanResult(
        request_id="req-response-monitor",
        detected_entities=["EMAIL"],
        secrets_found=["alice@example.com"],
        action_taken="redact",
        tokens_before=5,
        tokens_after=5,
        substitution_map=substitution_map,
    )


def test_response_monitor_clean_response_logs_no_findings() -> None:
    monitor = ResponseMonitor(_base_scan_result(), "Thanks, I can help with that request.")

    result = monitor.evaluate()

    assert result == {"flagged": False, "findings": [], "action": "log"}


def test_response_monitor_flags_response_with_pii() -> None:
    monitor = ResponseMonitor(_base_scan_result(), "Reach me at leaked@example.com")

    result = monitor.evaluate()

    assert result["flagged"] is True
    assert result["action"] == "log"
    assert any("PII detected in response" in finding for finding in result["findings"])


def test_response_monitor_flags_decoded_substitution_token() -> None:
    original_scan = _base_scan_result(substitution_map={"[EMAIL_1]": "alice@example.com"})
    monitor = ResponseMonitor(original_scan, "The original user email was alice@example.com")

    result = monitor.evaluate()

    assert result["flagged"] is True
    assert result["action"] == "log"
    assert "Decoded substitution detected: [EMAIL_1] -> alice@example.com" in result["findings"]
