"""Tests for policy engine and secrets detector."""

from __future__ import annotations

from pathlib import Path

from shadowaudit.core.policy import PolicyEngine
from shadowaudit.core.secrets import SecretsDetector


def test_shannon_entropy_increases_for_random_like_strings() -> None:
    detector = SecretsDetector(entropy_threshold=4.5)

    low = detector.shannon_entropy("aaaaaaaaaaaaaaaa")
    high = detector.shannon_entropy("A1b2C3d4E5f6G7h8")

    assert high > low


def test_secrets_detector_flags_entropy_hits() -> None:
    detector = SecretsDetector(entropy_threshold=3.5)

    findings = detector.detect("token=sk_live_A1b2C3d4E5f6G7h8")

    assert any("sk_live" in item for item in findings)


def test_policy_engine_returns_first_match(tmp_path: Path) -> None:
    config = tmp_path / "policy.yaml"
    config.write_text(
        """
policies:
  - name: first
    when:
      detected: ["EMAIL"]
    action: log
    notify: ["sec@example.com"]
  - name: second
    when:
      entropy_score: 4.0
    action: block
    notify: ["ops@example.com"]
""".strip()
    )

    engine = PolicyEngine.from_file(config)
    decision = engine.evaluate(detected=["EMAIL", "PHONE"], model="gpt-4.1", entropy_score=5.0)

    assert decision is not None
    assert decision["name"] == "first"
    assert decision["action"] == "log"


def test_policy_engine_validation_rejects_bad_action(tmp_path: Path) -> None:
    config = tmp_path / "bad.yaml"
    config.write_text(
        """
policies:
  - name: bad
    when: {}
    action: quarantine
    notify: []
""".strip()
    )

    try:
        PolicyEngine.from_file(config)
    except ValueError as exc:
        assert "invalid 'action'" in str(exc)
    else:
        raise AssertionError("Expected PolicyEngine.from_file to reject bad action")
