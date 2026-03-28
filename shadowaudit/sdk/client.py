"""Client wrapper that intercepts OpenAI chat completions requests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shadowaudit.core.cache import SemanticCache
from shadowaudit.core.models import ScanResult
from shadowaudit.core.policy import Policy, PolicyEngine
from shadowaudit.core.redactor import redact
from shadowaudit.core.response_monitor import ResponseMonitor
from shadowaudit.core.scanner import PIIScanner
from shadowaudit.core.secrets import SecretsDetector

try:  # pragma: no cover - optional dependency.
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def _load_yaml_file(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if yaml is None:
        raise RuntimeError("PyYAML is required to load configuration files")
    data = yaml.safe_load(raw)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("shadowaudit config must be a mapping")
    return data


def _extract_prompt_text(messages: list[dict[str, Any]] | None) -> str:
    if not messages:
        return ""

    chunks: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
    return "\n".join(chunks)


def _replace_messages(messages: list[dict[str, Any]] | None, sanitized_text: str) -> list[dict[str, Any]]:
    if not messages:
        return [{"role": "user", "content": sanitized_text}]

    replaced: list[dict[str, Any]] = []
    swapped = False
    for message in messages:
        item = dict(message)
        if not swapped and item.get("role") == "user":
            item["content"] = sanitized_text
            swapped = True
        replaced.append(item)

    if not swapped and replaced:
        replaced[-1]["content"] = sanitized_text

    return replaced


def _response_text(response: Any) -> str:
    if isinstance(response, dict):
        choices = response.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            content = message.get("content")
            return content if isinstance(content, str) else ""
        return ""

    choices = getattr(response, "choices", None)
    if not choices:
        return ""

    first = choices[0]
    message = getattr(first, "message", None)
    if message is None and isinstance(first, dict):
        message = first.get("message")

    if isinstance(message, dict):
        content = message.get("content")
    else:
        content = getattr(message, "content", "")
    return content if isinstance(content, str) else ""


@dataclass
class ShadowAudit:
    """SDK entrypoint for wrapping OpenAI-compatible clients."""

    config: dict[str, Any]
    scanner: PIIScanner | None = None
    secrets_detector: SecretsDetector | None = None
    policy_engine: PolicyEngine | None = None
    semantic_cache: SemanticCache | None = None

    def __post_init__(self) -> None:
        self.scanner = self.scanner or PIIScanner(fast_mode=True)
        self.secrets_detector = self.secrets_detector or SecretsDetector()

        if self.policy_engine is None and isinstance(self.config.get("policies"), list):
            rules: list[Policy] = []
            for raw in self.config["policies"]:
                if not isinstance(raw, dict):
                    continue
                rules.append(
                    Policy(
                        name=str(raw.get("name", "default")),
                        when=dict(raw.get("when", {})),
                        action=str(raw.get("action", "log")),
                        notify=list(raw.get("notify", [])),
                    )
                )
            self.policy_engine = PolicyEngine(rules)

        if self.semantic_cache is None and self.config.get("semantic_cache", {}).get("enabled"):
            self.semantic_cache = SemanticCache(
                similarity_threshold=float(self.config.get("semantic_cache", {}).get("similarity_threshold", 0.95))
            )

    @classmethod
    def from_config(cls, path: str | Path) -> "ShadowAudit":
        """Load SDK configuration from a ``shadowaudit.yaml`` file."""

        config_path = Path(path)
        config = _load_yaml_file(config_path)
        return cls(config=config)

    def wrap(self, openai_client: Any) -> Any:
        """Return a proxy client that intercepts ``chat.completions.create``."""

        sdk = self

        class _CompletionsProxy:
            def __init__(self, upstream: Any) -> None:
                self._upstream = upstream

            def create(self, *args: Any, **kwargs: Any) -> Any:
                messages = kwargs.get("messages")
                prompt_text = _extract_prompt_text(messages)
                detections = sdk.scanner.detect(prompt_text)
                sanitized_prompt, substitutions = redact(prompt_text, detections)

                secrets = sdk.secrets_detector.detect(sanitized_prompt)
                detected_types = sorted({item.entity_type for item in detections})

                entropy_score = 0.0
                if secrets:
                    entropy_score = max(sdk.secrets_detector.shannon_entropy(value) for value in secrets)

                decision = None
                if sdk.policy_engine is not None:
                    decision = sdk.policy_engine.evaluate(
                        detected=detected_types,
                        model=str(kwargs.get("model", "")),
                        entropy_score=entropy_score,
                    )
                    if decision and decision.get("action") == "block":
                        raise ValueError("Request blocked by ShadowAudit policy")

                outgoing_scan = ScanResult(
                    request_id=str(kwargs.get("request_id", "sdk-request")),
                    detected_entities=detected_types,
                    secrets_found=secrets,
                    action_taken=(decision or {}).get("action", "detected" if (detections or secrets) else "clean"),
                    tokens_before=len(prompt_text.split()),
                    tokens_after=len(sanitized_prompt.split()),
                    substitution_map=substitutions,
                )

                session_id = str(kwargs.pop("session_id", "default"))
                if sdk.semantic_cache is not None:
                    cached = sdk.semantic_cache.get(sanitized_prompt, session_id, scan_result=outgoing_scan)
                    if cached is not None:
                        ResponseMonitor(outgoing_scan, cached, config=sdk.config).evaluate()
                        return {
                            "id": "shadowaudit-cache-hit",
                            "choices": [{"index": 0, "message": {"role": "assistant", "content": cached}}],
                        }

                sanitized_messages = _replace_messages(messages, sanitized_prompt)
                kwargs["messages"] = sanitized_messages
                response = self._upstream.create(*args, **kwargs)

                response_text = _response_text(response)
                ResponseMonitor(outgoing_scan, response_text, config=sdk.config).evaluate()

                if sdk.semantic_cache is not None:
                    sdk.semantic_cache.set(sanitized_prompt, response_text, session_id, scan_result=outgoing_scan)

                return response

        class _ChatProxy:
            def __init__(self, upstream: Any) -> None:
                self.completions = _CompletionsProxy(upstream.completions)

        class _OpenAIProxy:
            def __init__(self, upstream: Any) -> None:
                self._upstream = upstream
                self.chat = _ChatProxy(upstream.chat)

            def __getattr__(self, item: str) -> Any:
                return getattr(self._upstream, item)

        return _OpenAIProxy(openai_client)
