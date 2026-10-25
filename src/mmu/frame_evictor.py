"""Deterministic AST Frame Evictor for Phonix v2.0 Context MMU.

Enforces strict context window budgets (< 4096 tokens total) by evicting AST frames
using LRU and priority-weighted heuristics when paging thresholds are reached.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from src.mmu.ast_slicer import ASTFrame

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


class FrameEvictionPolicy(str, Enum):
    """Supported eviction strategies for Context MMU."""

    LRU = "lru"
    PRIORITY = "priority"
    HYBRID = "hybrid"


class EvictionResult(BaseModel):
    """Summary of frame eviction operation."""

    retained_frames: list[ASTFrame] = Field(default_factory=list)
    evicted_frames: list[ASTFrame] = Field(default_factory=list)
    total_tokens_retained: int = Field(default=0)
    total_tokens_evicted: int = Field(default=0)


class FrameEvictor:
    """Deterministic frame evictor managing Context MMU working set size.

    Orders and prunes AST frames to fit into downstream LLM context windows
    while preserving the most structurally critical symbols.
    """

    def __init__(self, default_policy: FrameEvictionPolicy = FrameEvictionPolicy.HYBRID) -> None:
        self.default_policy: FrameEvictionPolicy = default_policy

    def evict(
        self,
        frames: list[ASTFrame],
        token_budget: int = 2048,
        policy: FrameEvictionPolicy | None = None,
    ) -> EvictionResult:
        """Prunes frames exceeding token_budget according to the specified policy.

        TODO (Phonix v2.0):
        - Integrate feedback from Micro-Router drop decisions to boost eviction accuracy.
        - Support caller/callee semantic pinning (never evict frames with entrypoint references).
        """
        active_policy = policy or self.default_policy
        total_tokens = sum(f.token_count for f in frames)

        if total_tokens <= token_budget:
            return EvictionResult(
                retained_frames=list(frames),
                evicted_frames=[],
                total_tokens_retained=total_tokens,
                total_tokens_evicted=0,
            )

        # Sort frames by preservation priority (descending: highest priority retained first)
        if active_policy == FrameEvictionPolicy.PRIORITY:
            sorted_candidates = sorted(frames, key=lambda f: f.relevance_score, reverse=True)
        elif active_policy == FrameEvictionPolicy.LRU:
            # Assumes input order reflects recency
            sorted_candidates = list(reversed(frames))
        else:  # HYBRID
            sorted_candidates = sorted(
                frames,
                key=lambda f: (f.relevance_score, -f.token_count),
                reverse=True,
            )

        retained: list[ASTFrame] = []
        evicted: list[ASTFrame] = []
        current_tokens = 0

        for frame in sorted_candidates:
            if current_tokens + frame.token_count <= token_budget:
                retained.append(frame)
                current_tokens += frame.token_count
            else:
                evicted.append(frame)

        return EvictionResult(
            retained_frames=retained,
            evicted_frames=evicted,
            total_tokens_retained=current_tokens,
            total_tokens_evicted=sum(f.token_count for f in evicted),
        )
