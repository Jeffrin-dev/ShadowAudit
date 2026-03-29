"""CLI tests for scan command."""

from __future__ import annotations

import json
import sys

from shadowaudit.cli import main


def test_scan_command_outputs_detected_entities(capsys) -> None:
    old_argv = sys.argv
    sys.argv = ["shadowaudit", "scan", "Email", "alice@example.com"]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert "EMAIL" in payload["detected_entities"]


def test_scan_command_outputs_detected_secrets(capsys) -> None:
    old_argv = sys.argv
    sys.argv = ["shadowaudit", "scan", "token", "sk-proj-abcXYZ123randomSTRING456moreRANDOM789"]
    try:
        code = main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["secrets_found"]
