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

    MIN_ENTROPY_CANDIDATE_LENGTH = 12
    STOPWORDS = {"key", "is", "my", "the", "api", "and", "for", "not", "with"}
    PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
        re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9-]{19,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bxoxb-[0-9A-Za-z-]{10,}\b"),
    )

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

    def _is_entropy_candidate(self, value: str) -> bool:
        if len(value) < self.MIN_ENTROPY_CANDIDATE_LENGTH:
            return False
        return value.lower() not in self.STOPWORDS

    def _detect_prefix_patterns(self, text: str) -> list[str]:
        findings: list[str] = []
        for pattern in self.PREFIX_PATTERNS:
            findings.extend(pattern.findall(text))
        return findings

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

        prefix_hits = self._detect_prefix_patterns(text)
        found = [item for item in self._detect_with_library(text) if self._is_entropy_candidate(item)]
        entropy_hits = [
            candidate
            for candidate in self._candidate_strings(text)
            if self._is_entropy_candidate(candidate) and self.shannon_entropy(candidate) >= self.entropy_threshold
        ]

        merged = dict.fromkeys(prefix_hits + found + entropy_hits)
        return list(merged)
