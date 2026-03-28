"""Policy evaluation engine for ShadowAudit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ALLOWED_ACTIONS = {"log", "tag", "redact", "block"}

try:  # pragma: no cover - optional dependency.
    import yaml
except Exception:  # pragma: no cover - fallback path.
    yaml = None


def _coerce_scalar(value: str) -> Any:
    if value in {"{}", "{ }"}:
        return {}
    if value in {"[]", "[ ]"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip('"').strip("'") for item in inner.split(",")]
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    try:
        return float(value)
    except ValueError:
        return value


def _simple_yaml_load(text: str) -> dict[str, Any]:
    """Very small YAML subset parser used when PyYAML is unavailable."""

    policies: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        stripped = line.strip()
        if stripped.startswith("policies:"):
            remainder = stripped.split(":", 1)[1].strip()
            if not remainder:
                continue
            return {"policies": _coerce_scalar(remainder)}

        if stripped.startswith("- name:"):
            if current:
                policies.append(current)
            current = {"name": stripped.split(":", 1)[1].strip().strip('"').strip("'")}
            section = None
            continue

        if current is None:
            continue

        if stripped.startswith("when:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                current["when"] = _coerce_scalar(value)
                section = None
            else:
                section = "when"
                current.setdefault("when", {})
            continue

        if stripped.startswith("notify:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                current["notify"] = _coerce_scalar(value)
                section = None
            else:
                section = "notify"
                current.setdefault("notify", [])
            continue

        if stripped.startswith("action:"):
            current["action"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            section = None
            continue

        if section == "when" and ":" in stripped:
            key, value = stripped.split(":", 1)
            current["when"][key.strip()] = _coerce_scalar(value.strip())
            continue

        if section == "notify" and stripped.startswith("-"):
            current["notify"].append(stripped[1:].strip().strip('"').strip("'"))
            continue

    if current:
        policies.append(current)

    return {"policies": policies}


@dataclass(frozen=True)
class Policy:
    """A single policy rule loaded from YAML."""

    name: str
    when: dict[str, Any]
    action: str
    notify: list[str]


class PolicyEngine:
    """Load and evaluate policy rules in declaration order."""

    def __init__(self, policies: list[Policy]) -> None:
        self.policies = policies

    @classmethod
    def from_file(cls, config_path: str | Path) -> "PolicyEngine":
        """Create a policy engine from a YAML config file."""

        path = Path(config_path)
        raw_text = path.read_text(encoding="utf-8")
        config = yaml.safe_load(raw_text) if yaml is not None else _simple_yaml_load(raw_text)
        if not isinstance(config, dict) or not isinstance(config.get("policies"), list):
            raise ValueError("Policy config must contain a top-level 'policies' list")

        rules: list[Policy] = []
        for idx, raw in enumerate(config["policies"]):
            if not isinstance(raw, dict):
                raise ValueError(f"Policy at index {idx} must be a mapping")

            name = raw.get("name")
            when = raw.get("when")
            action = raw.get("action")
            notify = raw.get("notify", [])

            if not isinstance(name, str) or not name:
                raise ValueError(f"Policy at index {idx} has invalid 'name'")
            if not isinstance(when, dict):
                raise ValueError(f"Policy '{name}' has invalid 'when' (must be a mapping)")
            if not isinstance(action, str) or action not in _ALLOWED_ACTIONS:
                raise ValueError(f"Policy '{name}' has invalid 'action': {action}")
            if not isinstance(notify, list) or not all(isinstance(item, str) for item in notify):
                raise ValueError(f"Policy '{name}' has invalid 'notify' (must be list[str])")

            rules.append(Policy(name=name, when=when, action=action, notify=notify))

        return cls(rules)

    @staticmethod
    def _is_match(when: dict[str, Any], context: dict[str, Any]) -> bool:
        detected_required = when.get("detected")
        if detected_required is not None:
            if not isinstance(detected_required, list):
                return False
            detected = context.get("detected", [])
            if not isinstance(detected, list) or not all(item in detected for item in detected_required):
                return False

        model_required = when.get("model")
        if model_required is not None and context.get("model") != model_required:
            return False

        entropy_required = when.get("entropy_score")
        if entropy_required is not None:
            try:
                required_value = float(entropy_required)
                actual_value = float(context.get("entropy_score", 0.0))
            except (TypeError, ValueError):
                return False
            if actual_value < required_value:
                return False

        return True

    def evaluate(self, *, detected: list[str], model: str, entropy_score: float) -> dict[str, Any] | None:
        """Evaluate policies in order and return the first matching policy decision."""

        context = {
            "detected": detected,
            "model": model,
            "entropy_score": entropy_score,
        }

        for policy in self.policies:
            if self._is_match(policy.when, context):
                return {
                    "name": policy.name,
                    "action": policy.action,
                    "notify": policy.notify,
                }
        return None
