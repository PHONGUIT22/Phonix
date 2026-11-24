"""Static 1-Hop / 2-Hop Call Graph Pager for Phonix v2.0 Context MMU.

Pages AST frames into the context window via deterministic BFS expansion
over static caller/callee edges without full repository loading.
Explicitly avoids heavy Z3 solver logic for code transpilation; purely static graph traversal.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any, Literal

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
        """Returns all AST frames defining a specific symbol (including partitioned parts and class methods)."""
        if symbol in self._symbol_to_frames:
            return self._symbol_to_frames[symbol]
        part_prefix = f"{symbol}#"
        method_prefix = f"{symbol}."
        matched: list[ASTFrame] = []
        for sym, frames in self._symbol_to_frames.items():
            if sym.startswith(part_prefix) or sym.startswith(method_prefix):
                matched.extend(frames)
        return matched

    def get_callers(self, symbol: str) -> set[str]:
        """Returns direct caller symbols for a given symbol (including Class.method forms)."""
        callers: set[str] = set(self._adjacency_in.get(symbol, set()))
        suffix = f".{symbol}"
        for dep_sym, caller_set in self._adjacency_in.items():
            if dep_sym.endswith(suffix) or dep_sym.startswith(f"{symbol}."):
                callers.update(caller_set)
        return callers

    def get_callees(self, symbol: str) -> set[str]:
        """Returns direct callee symbols for a given symbol."""
        callees: set[str] = set(self._adjacency_out.get(symbol, set()))
        for sym, deps in self._adjacency_out.items():
            if sym.startswith(f"{symbol}.") or sym.startswith(f"{symbol}#"):
                callees.update(deps)
        return callees

    def page_graph(
        self,
        seed_symbols: list[str],
        max_hops: int | None = None,
        max_token_budget: int = 3072,
        direction: Literal["callees", "callers", "both"] = "callees",
    ) -> list[ASTFrame]:
        """Expands context deterministically up to max_hops (1-hop / 2-hop).

        Performs Breadth-First Search (BFS) starting from seed_symbols along:
        - direction="callees": outgoing dependency edges (_adjacency_out)
        - direction="callers": incoming caller edges (_adjacency_in)
        - direction="both": bidirectional (callers + callees)
        Returns a curated list of AST frames whose cumulative token count <= max_token_budget.
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
            frames = self.get_symbol_frames(symbol)
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
                neighbors: set[str] = set()
                if direction in ("callees", "both"):
                    neighbors.update(self._adjacency_out.get(symbol, set()))
                if direction in ("callers", "both"):
                    neighbors.update(self._adjacency_in.get(symbol, set()))
                for neighbor in sorted(neighbors):
                    if neighbor not in visited_symbols:
                        queue.append((neighbor, hop + 1))

        return selected_frames
