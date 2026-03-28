"""Custom recognizers used by ShadowAudit's PII scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

try:  # pragma: no cover - exercised only when Presidio is installed.
    from presidio_analyzer import Pattern as PresidioPattern
    from presidio_analyzer import PatternRecognizer
except Exception:  # pragma: no cover - local fallback for lightweight environments.
    PresidioPattern = None

    class PatternRecognizer:  # type: ignore[override]
        """Minimal fallback interface matching Presidio's recognizer shape."""

        supported_entities: list[str]
        patterns: list[object]

        def __init__(self, supported_entity: str, pattern: str) -> None:
            self.supported_entities = [supported_entity]
            self.patterns = [pattern]


@dataclass(frozen=True)
class RegexEntity:
    """Compiled regex metadata for fallback scanning."""

    entity_type: str
    regex: Pattern[str]


class AadhaarRecognizer(PatternRecognizer):
    """Recognizer for Indian Aadhaar numbers (12 digits, optional spaces every 4)."""

    ENTITY = "AADHAAR"
    REGEX = r"\b\d{4}\s?\d{4}\s?\d{4}\b"

    def __init__(self) -> None:
        if PresidioPattern is not None:
            super().__init__(
                supported_entity=self.ENTITY,
                patterns=[
                    PresidioPattern(
                        name="aadhaar",
                        regex=self.REGEX,
                        score=0.75,
                    )
                ],
            )
        else:
            super().__init__(supported_entity=self.ENTITY, pattern=self.REGEX)


class PANRecognizer(PatternRecognizer):
    """Recognizer for Indian PAN card numbers."""

    ENTITY = "PAN"
    REGEX = r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"

    def __init__(self) -> None:
        if PresidioPattern is not None:
            super().__init__(
                supported_entity=self.ENTITY,
                patterns=[PresidioPattern(name="pan", regex=self.REGEX, score=0.8)],
            )
        else:
            super().__init__(supported_entity=self.ENTITY, pattern=self.REGEX)


class IBANRecognizer(PatternRecognizer):
    """Recognizer for International Bank Account Numbers (IBAN)."""

    ENTITY = "IBAN"
    REGEX = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"

    def __init__(self) -> None:
        if PresidioPattern is not None:
            super().__init__(
                supported_entity=self.ENTITY,
                patterns=[PresidioPattern(name="iban", regex=self.REGEX, score=0.7)],
            )
        else:
            super().__init__(supported_entity=self.ENTITY, pattern=self.REGEX)


class NHSNumberRecognizer(PatternRecognizer):
    """Recognizer for UK NHS numbers in 3-3-4 grouping."""

    ENTITY = "NHS_UK"
    REGEX = r"\b\d{3}\s?\d{3}\s?\d{4}\b"

    def __init__(self) -> None:
        if PresidioPattern is not None:
            super().__init__(
                supported_entity=self.ENTITY,
                patterns=[PresidioPattern(name="nhs", regex=self.REGEX, score=0.75)],
            )
        else:
            super().__init__(supported_entity=self.ENTITY, pattern=self.REGEX)


def regex_entities() -> list[RegexEntity]:
    """Return compiled regex entities used in fast regex-only mode."""

    return [
        RegexEntity(AadhaarRecognizer.ENTITY, re.compile(AadhaarRecognizer.REGEX)),
        RegexEntity(PANRecognizer.ENTITY, re.compile(PANRecognizer.REGEX)),
        RegexEntity(IBANRecognizer.ENTITY, re.compile(IBANRecognizer.REGEX)),
        RegexEntity(NHSNumberRecognizer.ENTITY, re.compile(NHSNumberRecognizer.REGEX)),
        RegexEntity("EMAIL", re.compile(r"\b[\w.%-]+@[\w.-]+\.[A-Za-z]{2,}\b")),
        RegexEntity("PHONE", re.compile(r"\b\+?\d{10,15}\b")),
    ]
