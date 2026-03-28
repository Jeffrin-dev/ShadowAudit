"""CLI tests for proxy command wiring."""

from __future__ import annotations

import sys

from shadowaudit.cli import main


def test_proxy_command_invokes_runner(monkeypatch) -> None:
    captured = {}

    def _fake_runner(*, port: int, target: str) -> None:
        captured["port"] = port
        captured["target"] = target

    monkeypatch.setattr("shadowaudit.sdk.proxy.run_proxy_server", _fake_runner)

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "proxy", "--port", "9090", "--target", "https://api.openai.com"]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    assert code == 0
    assert captured == {"port": 9090, "target": "https://api.openai.com"}
