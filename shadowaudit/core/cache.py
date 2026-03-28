"""Semantic cache backed by ChromaDB and sentence-transformers embeddings."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from shadowaudit.core.models import ScanResult

try:  # pragma: no cover - optional dependency guard.
    import chromadb
except Exception:  # pragma: no cover
    chromadb = None

try:  # pragma: no cover - optional dependency guard.
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover
    SentenceTransformer = None


@dataclass(frozen=True)
class CacheEntry:
    """Internal cache lookup result."""

    prompt: str
    response: str
    distance: float


class SemanticCache:
    """Semantic cache keyed by prompt similarity and session namespace."""

    def __init__(self, similarity_threshold: float = 0.95) -> None:
        if chromadb is None or SentenceTransformer is None:
            raise RuntimeError(
                "SemanticCache requires optional dependencies: chromadb and sentence-transformers"
            )

        self.similarity_threshold = similarity_threshold
        self._client = chromadb.Client()
        self._embedder = SentenceTransformer("all-MiniLM-L6-v2")

    def get(self, prompt: str, session_id: str, *, scan_result: ScanResult | None = None) -> str | None:
        """Return cached response when a close-enough prompt match exists."""

        if scan_result and (scan_result.detected_entities or scan_result.secrets_found):
            return None

        collection = self._client.get_or_create_collection(name=self._collection_name(session_id))
        embedding = self._embed(prompt)
        result = collection.query(query_embeddings=[embedding], n_results=1, include=["distances", "metadatas"])

        distances = result.get("distances") or []
        metadatas = result.get("metadatas") or []
        if not distances or not distances[0] or not metadatas or not metadatas[0]:
            return None

        distance = float(distances[0][0])
        similarity = 1.0 - distance
        if similarity < self.similarity_threshold:
            return None

        metadata: dict[str, Any] = metadatas[0][0]
        return metadata.get("response")

    def set(
        self,
        prompt: str,
        response: str,
        session_id: str,
        *,
        scan_result: ScanResult | None = None,
    ) -> None:
        """Store a prompt/response pair in the scoped semantic cache."""

        if scan_result and (scan_result.detected_entities or scan_result.secrets_found):
            return None

        collection = self._client.get_or_create_collection(name=self._collection_name(session_id))
        collection.add(
            ids=[self._entry_id(prompt)],
            embeddings=[self._embed(prompt)],
            metadatas=[{"prompt": prompt, "response": response}],
            documents=[prompt],
        )

    def _embed(self, text: str) -> list[float]:
        vector = self._embedder.encode(text)
        if hasattr(vector, "tolist"):
            return vector.tolist()
        return list(vector)

    @staticmethod
    def _collection_name(session_id: str) -> str:
        return f"session_{session_id}"

    @staticmethod
    def _entry_id(prompt: str) -> str:
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()
