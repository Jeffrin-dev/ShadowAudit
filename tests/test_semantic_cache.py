"""Semantic cache tests."""

from __future__ import annotations

from shadowaudit.core.cache import SemanticCache
from shadowaudit.core.models import ScanResult


class _ForbiddenClient:
    def get_or_create_collection(self, name: str):  # pragma: no cover - should not run
        raise AssertionError("cache backend should not be touched")


def test_semantic_cache_gate_blocks_get_and_set() -> None:
    cache = object.__new__(SemanticCache)
    cache._client = _ForbiddenClient()
    cache.similarity_threshold = 0.95

    blocked_scan = ScanResult(
        request_id="r1",
        detected_entities=["EMAIL"],
        secrets_found=[],
        action_taken="detected",
        tokens_before=1,
        tokens_after=1,
    )

    assert cache.get("hello", "session-1", scan_result=blocked_scan) is None
    assert cache.set("hello", "world", "session-1", scan_result=blocked_scan) is None
