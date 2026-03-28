"""PII scanner wrapper around Microsoft Presidio's AnalyzerEngine."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from shadowaudit.core.models import ScanResult
from shadowaudit.core.recognizers import (
    AadhaarRecognizer,
    IBANRecognizer,
    NHSNumberRecognizer,
    PANRecognizer,
    regex_entities,
)

try:  # pragma: no cover - only used when Presidio is available.
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
except Exception:  # pragma: no cover - fallback path.
    AnalyzerEngine = None
    RecognizerRegistry = None


@dataclass(frozen=True)
class Detection:
    """A normalized detection result used for redaction and testing."""

    entity_type: str
    text: str
    start: int
    end: int


class PIIScanner:
    """PII scanner with optional Presidio engine and regex-only fast mode."""

    def __init__(self, *, fast_mode: bool = True, language: str = "en") -> None:
        self.fast_mode = fast_mode
        self.language = language
        self._analyzer = self._build_analyzer() if not fast_mode else None

    def _build_analyzer(self):
        if AnalyzerEngine is None or RecognizerRegistry is None:
            return None

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(languages=[self.language])
        registry.add_recognizer(AadhaarRecognizer())
        registry.add_recognizer(PANRecognizer())
        registry.add_recognizer(IBANRecognizer())
        registry.add_recognizer(NHSNumberRecognizer())

        nlp_engine_name = "spacy"  # transformer models are selected by Presidio/spaCy config.
        return AnalyzerEngine(registry=registry, supported_languages=[self.language], nlp_engine_name=nlp_engine_name)

    def detect(self, prompt: str) -> list[Detection]:
        """Detect entities in the prompt and return normalized detections."""

        if self.fast_mode or self._analyzer is None:
            return self._regex_detect(prompt)

        findings = self._analyzer.analyze(text=prompt, language=self.language)
        results: list[Detection] = []
        for match in findings:
            results.append(
                Detection(
                    entity_type=match.entity_type,
                    text=prompt[match.start : match.end],
                    start=match.start,
                    end=match.end,
                )
            )
        return results

    def scan(self, prompt: str, *, request_id: str | None = None) -> ScanResult:
        """Scan prompt text and return a ScanResult model."""

        detections = self.detect(prompt)
        entities = sorted({item.entity_type for item in detections})
        secrets = [item.text for item in detections]
        req_id = request_id or f"scan-{uuid.uuid4().hex[:8]}"

        return ScanResult(
            request_id=req_id,
            detected_entities=entities,
            secrets_found=secrets,
            action_taken="detected" if detections else "clean",
            tokens_before=len(prompt.split()),
            tokens_after=len(prompt.split()),
        )

    @staticmethod
    def _regex_detect(prompt: str) -> list[Detection]:
        candidates: list[Detection] = []
        for entity in regex_entities():
            for match in entity.regex.finditer(prompt):
                candidates.append(
                    Detection(
                        entity_type=entity.entity_type,
                        text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )

        priority = {"AADHAAR": 0, "PAN": 0, "IBAN": 0, "NHS_UK": 0, "EMAIL": 1, "PHONE": 2}
        candidates.sort(key=lambda item: (priority.get(item.entity_type, 99), item.start, -(item.end - item.start)))

        accepted: list[Detection] = []
        for detection in candidates:
            overlaps = any(not (detection.end <= kept.start or detection.start >= kept.end) for kept in accepted)
            if not overlaps:
                accepted.append(detection)

        accepted.sort(key=lambda item: item.start)
        return accepted
