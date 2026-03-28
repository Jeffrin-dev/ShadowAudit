"""CLI tests for policy config validation."""

from __future__ import annotations

from pathlib import Path

from shadowaudit.cli import main


def test_policy_check_valid_file(tmp_path: Path, capsys) -> None:
    config = tmp_path / "valid.yaml"
    config.write_text(
        """
policies:
  - name: ok
    when: {}
    action: log
    notify: []
""".strip()
    )

    import sys

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "policy", "check", str(config)]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    assert code == 0
    assert "VALID" in captured.out


def test_policy_check_invalid_file(tmp_path: Path, capsys) -> None:
    config = tmp_path / "invalid.yaml"
    config.write_text("policies: [bad]")

    import sys

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "policy", "check", str(config)]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    assert code == 1
    assert "INVALID" in captured.out
