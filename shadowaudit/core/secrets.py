"""Secret detection utilities backed by detect-secrets and entropy heuristics."""

from __future__ import annotations

import math
import re
from collections import Counter

try:  # pragma: no cover - optional dependency.
    from detect_secrets.core import scan
    from detect_secrets.settings import transient_settings
except Exception:  # pragma: no cover - fallback path when package is unavailable.
    scan = None
    transient_settings = None


class SecretsDetector:
    """Detect likely secrets with detect-secrets and Shannon entropy scoring."""

    def __init__(self, *, entropy_threshold: float = 4.5) -> None:
        self.entropy_threshold = entropy_threshold

    @staticmethod
    def shannon_entropy(value: str) -> float:
        """Calculate Shannon entropy for a string."""

        if not value:
            return 0.0

        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _candidate_strings(text: str) -> list[str]:
        return re.findall(r"[A-Za-z0-9_\-+/=]{8,}", text)

    def _detect_with_library(self, text: str) -> list[str]:
        if scan is None or transient_settings is None:
            return []

        plugin_settings = {
            "plugins_used": [
                {"name": "Base64HighEntropyString", "limit": self.entropy_threshold},
                {"name": "HexHighEntropyString", "limit": self.entropy_threshold},
            ]
        }

        findings: list[str] = []
        with transient_settings(plugin_settings):
            for secret in scan.scan_line(text):
                value = getattr(secret, "secret_value", None)
                if value:
                    findings.append(value)
        return findings

    def detect(self, text: str) -> list[str]:
        """Return unique secrets in a format compatible with ``ScanResult.secrets_found``."""

        found = self._detect_with_library(text)
        entropy_hits = [
            candidate
            for candidate in self._candidate_strings(text)
            if self.shannon_entropy(candidate) >= self.entropy_threshold
        ]

        merged = dict.fromkeys(found + entropy_hits)
        return list(merged)
