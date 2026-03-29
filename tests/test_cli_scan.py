"""CLI tests for scan command."""

from __future__ import annotations

import json
import sys
from pathlib import Path

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


def test_scan_command_writes_and_appends_audit_log(capsys, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "scan", "Email", "alice@example.com"]
    try:
        first_code = main()
    finally:
        sys.argv = old_argv
    capsys.readouterr()

    old_argv = sys.argv
    sys.argv = ["shadowaudit", "scan", "Hello", "world"]
    try:
        second_code = main()
    finally:
        sys.argv = old_argv
    capsys.readouterr()

    log_path = tmp_path / "audit.log"
    assert first_code == 0
    assert second_code == 0
    assert log_path.exists()
    assert len(log_path.read_text(encoding="utf-8").strip().splitlines()) == 2
