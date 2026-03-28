"""Tests for ShadowAudit SDK client wrapping and config loading."""

from __future__ import annotations

from pathlib import Path

from shadowaudit.sdk.client import ShadowAudit


class _FakeCompletions:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def create(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return {
            "id": "resp_1",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Looks good."}}],
        }


class _FakeChat:
    def __init__(self) -> None:
        self.completions = _FakeCompletions()


class _FakeClient:
    def __init__(self) -> None:
        self.chat = _FakeChat()




class _FakeSecretsDetector:
    def detect(self, text: str):
        return []

    def shannon_entropy(self, value: str) -> float:
        return 0.0

class _FakeCache:
    def __init__(self) -> None:
        self.get_calls: list[tuple[str, str]] = []
        self.set_calls: list[tuple[str, str, str]] = []

    def get(self, prompt: str, session_id: str, *, scan_result=None):
        self.get_calls.append((prompt, session_id))
        return None

    def set(self, prompt: str, response: str, session_id: str, *, scan_result=None):
        self.set_calls.append((prompt, response, session_id))


def test_wrap_intercepts_and_sanitizes_prompt() -> None:
    sdk = ShadowAudit(config={}, semantic_cache=_FakeCache(), secrets_detector=_FakeSecretsDetector())
    client = _FakeClient()

    wrapped = sdk.wrap(client)
    wrapped.chat.completions.create(
        model="gpt-test",
        session_id="session-123",
        messages=[{"role": "user", "content": "Email me at leaked@example.com"}],
    )

    assert len(client.chat.completions.calls) == 1
    kwargs = client.chat.completions.calls[0]["kwargs"]
    sent_content = kwargs["messages"][0]["content"]
    assert sent_content == "Email me at [EMAIL_1]"


def test_from_config_loads_shadowaudit_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "shadowaudit.yaml"
    config_path.write_text(
        """
response_monitor_action: redact
semantic_cache:
  enabled: false
policies:
  - name: log-email
    when:
      detected: [EMAIL]
    action: log
    notify: []
""".strip(),
        encoding="utf-8",
    )

    sdk = ShadowAudit.from_config(config_path)

    assert sdk.config["response_monitor_action"] == "redact"
    assert sdk.policy_engine is not None
