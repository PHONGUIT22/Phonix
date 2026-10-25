"""KV Prefix Cache Manager for Phonix v2.0 Context MMU.

Maintains pinned and dynamic KV cache prefixes (system prompts, enterprise policies,
and common AST interfaces) to maximize prefix cache hits on llama.cpp / vLLM runtimes.
"""

from __future__ import annotations

import time
from typing import Any

try:
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__

    def Field(default: Any = ..., **kwargs: Any) -> Any:  # type: ignore
        return default


class PrefixEntry(BaseModel):
    """An indexed prefix entry in the KV prefix cache."""

    prefix_id: str = Field(description="Unique identifier for the prefix segment")
    text: str = Field(description="Exact prompt prefix text")
    token_count: int = Field(default=0, description="Estimated token length")
    is_pinned: bool = Field(default=False, description="Whether prefix is permanently pinned")
    hit_count: int = Field(default=0, description="Cumulative cache hit count")
    created_at: float = Field(default_factory=time.time)
    last_accessed: float = Field(default_factory=time.time)


class KVPrefixCache:
    """Manages prompt prefix cache states and pinned KV buffers.

    Ensures critical enterprise policies and system instructions are pinned in VRAM,
    maximizing prefix reuse and minimizing time-to-first-token (TTFT).
    """

    APPROX_CHARS_PER_TOKEN: int = 4

    def __init__(self, max_token_budget: int = 1024) -> None:
        self.max_token_budget: int = max_token_budget
        self._entries: dict[str, PrefixEntry] = {}

    def estimate_tokens(self, text: str) -> int:
        """Estimates token count from text length."""
        return max(1, len(text) // self.APPROX_CHARS_PER_TOKEN)

    def register_prefix(
        self, prefix_id: str, text: str, is_pinned: bool = False
    ) -> PrefixEntry:
        """Registers a prompt prefix in the cache.

        TODO (Phonix v2.0):
        - Sync prefix hash directly with llama.cpp `llama_kv_cache_seq_keep` or vLLM prefix cache slots.
        """
        token_count = self.estimate_tokens(text)
        entry = PrefixEntry(
            prefix_id=prefix_id,
            text=text,
            token_count=token_count,
            is_pinned=is_pinned,
            hit_count=0,
            created_at=time.time(),
            last_accessed=time.time(),
        )
        self._entries[prefix_id] = entry
        self._enforce_budget()
        return entry

    def get_prefix(self, prefix_id: str) -> PrefixEntry | None:
        """Retrieves a prefix by ID and updates its access telemetry."""
        entry = self._entries.get(prefix_id)
        if entry is not None:
            entry.hit_count += 1
            entry.last_accessed = time.time()
        return entry

    def match_longest_prefix(self, prompt: str) -> PrefixEntry | None:
        """Finds the longest registered prefix that matches the beginning of the prompt."""
        best_match: PrefixEntry | None = None
        best_length: int = 0

        for entry in self._entries.values():
            if prompt.startswith(entry.text) and len(entry.text) > best_length:
                best_match = entry
                best_length = len(entry.text)

        if best_match is not None:
            best_match.hit_count += 1
            best_match.last_accessed = time.time()

        return best_match

    def get_total_tokens(self) -> int:
        """Calculates total token volume currently cached."""
        return sum(e.token_count for e in self._entries.values())

    def _enforce_budget(self) -> None:
        """Evicts unpinned entries via LRU policy if total tokens exceed budget."""
        while self.get_total_tokens() > self.max_token_budget:
            unpinned = [e for e in self._entries.values() if not e.is_pinned]
            if not unpinned:
                break
            # Evict oldest accessed unpinned prefix
            unpinned.sort(key=lambda x: x.last_accessed)
            evicted = unpinned[0]
            del self._entries[evicted.prefix_id]
