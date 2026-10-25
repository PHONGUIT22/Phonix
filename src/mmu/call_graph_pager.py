"""Static 1-Hop / 2-Hop Call Graph Pager for Phonix v2.0 Context MMU.

Pages AST frames into the context window via deterministic BFS expansion
over static caller/callee edges without full repository loading.
Explicitly avoids heavy Z3 solver logic for code transpilation; purely static graph traversal.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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


class CallGraphEdge(BaseModel):
    """A directed edge in the static call graph."""

    caller_symbol: str = Field(description="Name or ID of invoking symbol")
    callee_symbol: str = Field(description="Name or ID of referenced symbol")
    relation_type: str = Field(
        default="calls", description="Type of relationship: calls, imports, inherits"
    )
    hop_distance: int = Field(default=1, description="Topological distance from query seed")


class CallGraphPager:
    """Static Call Graph Pager for deterministic 1-hop and 2-hop context expansion.

    Traverses symbol dependencies using BFS to retrieve only relevant AST frames,
    enforcing frame token limits and strict hop constraints.
    """

    def __init__(self, default_max_hops: int = 2) -> None:
        self.default_max_hops: int = default_max_hops
        # symbol_name -> list of ASTFrames defining it
        self._symbol_to_frames: dict[str, list[ASTFrame]] = {}
        # symbol_name -> set of callee symbols
        self._adjacency_out: dict[str, set[str]] = {}
        # symbol_name -> set of caller symbols
        self._adjacency_in: dict[str, set[str]] = {}

    def register_frame(self, frame: ASTFrame) -> None:
        """Indexes an AST frame and its dependencies into the call graph."""
        sym = frame.symbol_name
        self._symbol_to_frames.setdefault(sym, []).append(frame)
        self._adjacency_out.setdefault(sym, set())
        self._adjacency_in.setdefault(sym, set())

        deps = frame.dependencies if isinstance(getattr(frame, "dependencies", None), (list, set, tuple)) else []
        for dep in deps:
            self._adjacency_out[sym].add(dep)
            self._adjacency_in.setdefault(dep, set()).add(sym)

    def register_frames(self, frames: list[ASTFrame]) -> None:
        """Batch indexes multiple AST frames."""
        for frame in frames:
            self.register_frame(frame)

    def get_symbol_frames(self, symbol: str) -> list[ASTFrame]:
        """Returns all AST frames defining a specific symbol (including partitioned parts)."""
        if symbol in self._symbol_to_frames:
            return self._symbol_to_frames[symbol]
        prefix = f"{symbol}#"
        matched: list[ASTFrame] = []
        for sym, frames in self._symbol_to_frames.items():
            if sym.startswith(prefix):
                matched.extend(frames)
        return matched

    def page_graph(
        self,
        seed_symbols: list[str],
        max_hops: int | None = None,
        max_token_budget: int = 3072,
    ) -> list[ASTFrame]:
        """Expands context deterministically up to max_hops (1-hop / 2-hop).

        Performs Breadth-First Search (BFS) starting from seed_symbols.
        Returns a curated list of AST frames whose cumulative token count <= max_token_budget.

        TODO (Phonix v2.0):
        - Incorporate symbol usage frequency weights to break ties during budget contention.
        - Add reverse-call (callee -> caller) expansion for context-aware bug localization.
        """
        hops_limit = self.default_max_hops if max_hops is None else max_hops
        visited_symbols: set[str] = set()
        selected_frames: list[ASTFrame] = []
        selected_frame_ids: set[str] = set()
        current_tokens: int = 0

        # Queue items: (symbol_name, current_hop)
        queue: deque[tuple[str, int]] = deque((sym, 0) for sym in seed_symbols)

        while queue:
            symbol, hop = queue.popleft()
            if symbol in visited_symbols:
                continue
            visited_symbols.add(symbol)

            # Retrieve frames associated with this symbol
            frames = self._symbol_to_frames.get(symbol, [])
            for frame in frames:
                if frame.frame_id not in selected_frame_ids:
                    if current_tokens + frame.token_count <= max_token_budget:
                        selected_frames.append(frame)
                        selected_frame_ids.add(frame.frame_id)
                        current_tokens += frame.token_count
                    else:
                        # Budget exceeded, stop including further frames
                        break

            # If within hop limit, discover neighbors (1-hop, 2-hop)
            if hop < hops_limit:
                neighbors = self._adjacency_out.get(symbol, set())
                for neighbor in sorted(neighbors):
                    if neighbor not in visited_symbols:
                        queue.append((neighbor, hop + 1))

        return selected_frames
