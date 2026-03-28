"""Tests for PII scanner, recognizers, and redactor behavior."""

from __future__ import annotations

import pytest

from shadowaudit.core.redactor import redact
from shadowaudit.core.scanner import PIIScanner


@pytest.mark.parametrize(
    ("prompt", "expected_entities"),
    [
        ("Reach me at alice@example.com", {"EMAIL"}),
        ("Aadhaar is 1234 5678 9123", {"AADHAAR"}),
        ("PAN is ABCDE1234F", {"PAN"}),
        ("IBAN: GB29NWBK60161331926819", {"IBAN"}),
        ("NHS number 943 476 5919", {"NHS_UK"}),
        ("Call +14155552671 now", {"PHONE"}),
        ("No pii in this harmless sentence.", set()),
        ("Email bob.smith@company.co.uk and PAN QWERT1234Y", {"EMAIL", "PAN"}),
        ("Two aadhaars 123456789123 and 9999 8888 7777", {"AADHAAR"}),
        ("IBAN FR1420041010050500013M02606 belongs to EU account", {"IBAN"}),
        ("NHS alt spacing 9434765919", {"NHS_UK"}),
        ("PAN lowercase should fail abcde1234f", set()),
        ("Aadhaar malformed 123 456 789", set()),
        ("Contact: jane-doe@foo.io", {"EMAIL"}),
        ("Phone 14155552671 works", {"PHONE"}),
        ("Mixed: 1234 1234 1234 and GHIKL6789Z", {"AADHAAR", "PAN"}),
        ("Bank code ES9121000418450200051332", {"IBAN"}),
        ("NHS and email 943 476 5919 test@nhs.uk", {"NHS_UK", "EMAIL"}),
        ("Another clean prompt with random numbers 12345", set()),
        ("Edge PAN ZZZZZ9999Z in text", {"PAN"}),
    ],
)
def test_fast_mode_scanner_examples(prompt: str, expected_entities: set[str]) -> None:
    scanner = PIIScanner(fast_mode=True)

    result = scanner.scan(prompt, request_id="req-test")

    assert set(result.detected_entities) == expected_entities
    assert result.request_id == "req-test"
    assert result.action_taken == ("detected" if expected_entities else "clean")


def test_entity_preserving_redaction_tokens_and_map() -> None:
    scanner = PIIScanner(fast_mode=True)
    text = "Contact Alice at alice@example.com with PAN ABCDE1234F"
    detections = scanner.detect(text)

    redacted_text, substitutions = redact(text, detections)

    assert "alice@example.com" not in redacted_text
    assert "ABCDE1234F" not in redacted_text
    assert "[EMAIL_1]" in redacted_text
    assert "[PAN_1]" in redacted_text
    assert substitutions["[EMAIL_1]"] == "alice@example.com"
    assert substitutions["[PAN_1]"] == "ABCDE1234F"


def test_non_fast_mode_falls_back_gracefully_without_presidio() -> None:
    scanner = PIIScanner(fast_mode=False)

    result = scanner.scan("Email me: fallback@example.com")

    assert "EMAIL" in result.detected_entities
