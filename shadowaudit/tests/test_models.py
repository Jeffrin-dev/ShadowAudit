"""Basic tests for ShadowAudit core data models."""

from shadowaudit.core.models import AuditEvent, ScanResult


def test_models_hold_expected_values() -> None:
    """Ensure model instances can be created and fields are preserved."""
    scan_result = ScanResult(
        request_id="req-123",
        detected_entities=["email"],
        secrets_found=["api_key"],
        action_taken="redacted",
        tokens_before=100,
        tokens_after=84,
    )

    event = AuditEvent(
        timestamp="2026-03-28T00:00:00Z",
        request_id="req-123",
        scan_result=scan_result,
        policy_applied="default-policy",
        model_target="gpt-4.1",
        response_clean=True,
    )

    assert event.scan_result.request_id == "req-123"
    assert event.response_clean is True
