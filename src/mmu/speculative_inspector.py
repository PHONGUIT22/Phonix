"""Speculative Inspector for 0ms Speculative I/O in Phonix v2.0 Context MMU.

Inspects streaming JSON request chunks in real-time as they arrive over HTTP,
matching file paths against FileTrie and triggering speculative AST frame pre-fetching.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.mmu.file_trie import FileTrie

if TYPE_CHECKING:
    from src.mmu.ast_slicer import ASTFrame, ASTSlicer
    from src.mmu.call_graph_pager import CallGraphPager

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

logger = logging.getLogger(__name__)


class InspectionResult(BaseModel):
    """Result of real-time speculative chunk inspection."""

    candidate_files: list[str] = Field(
        default_factory=list, description="Candidate file paths matched from stream"
    )
    prefetched_frame_ids: list[str] = Field(
        default_factory=list, description="IDs of AST frames pre-staged in memory"
    )
    buffer_length_bytes: int = Field(default=0, description="Total stream buffer length in bytes")
    is_speculation_active: bool = Field(
        default=True, description="Whether speculative worker is active"
    )


class SpeculativeInspector:
    """Real-time streaming chunk inspector for the Context MMU.

    Monitors incoming byte/character streams from HTTP POST bodies, extracts
    speculative file path references, and requests early AST frame paging.
    """

    def __init__(
        self,
        file_trie: FileTrie,
        ast_slicer: ASTSlicer | None = None,
        call_graph_pager: CallGraphPager | None = None,
    ) -> None:
        self.file_trie: FileTrie = file_trie
        self.ast_slicer: ASTSlicer | None = ast_slicer
        self.call_graph_pager: CallGraphPager | None = call_graph_pager
        self._streaming_buffer: str = ""
        self._staged_frame_cache: dict[str, list[ASTFrame]] = {}
        self._detected_files: set[str] = set()

    def reset_stream(self) -> None:
        """Resets the streaming buffer and per-request speculation state."""
        self._streaming_buffer = ""
        self._staged_frame_cache.clear()
        self._detected_files.clear()

    def process_chunk(self, chunk: str | bytes) -> InspectionResult:
        """Processes an incoming streaming chunk from an HTTP request.

        Matches candidate file paths against the FileTrie and initiates
        speculative pre-fetching of AST frames.

        TODO (Phonix v2.0):
        - Integrate with async thread pool / worker queue to avoid blocking ASGI event loop.
        - Add SIMD-accelerated string scanning for high-throughput enterprise gateways.
        """
        text_chunk = chunk.decode("utf-8", errors="ignore") if isinstance(chunk, bytes) else chunk
        self._streaming_buffer += text_chunk

        matches = self.file_trie.speculative_match_streaming_tokens(self._streaming_buffer)
        new_files = [m for m in matches if m not in self._detected_files]

        prefetched_ids: list[str] = []
        for file_path in new_files:
            self._detected_files.add(file_path)
            prefetched = self._speculatively_load_file_frames(file_path)
            prefetched_ids.extend([f.frame_id for f in prefetched])

        return InspectionResult(
            candidate_files=sorted(self._detected_files),
            prefetched_frame_ids=prefetched_ids,
            buffer_length_bytes=len(self._streaming_buffer.encode("utf-8")),
            is_speculation_active=True,
        )

    def _speculatively_load_file_frames(self, file_path: str) -> list[ASTFrame]:
        """Internal worker to slice and pre-fetch AST frames for a detected file."""
        if file_path in self._staged_frame_cache:
            return self._staged_frame_cache[file_path]

        frames: list[ASTFrame] = []
        if self.ast_slicer is not None:
            try:
                frames = self.ast_slicer.slice_file(file_path)
                self._staged_frame_cache[file_path] = frames
                logger.debug(
                    "Speculatively staged %d AST frames for %s", len(frames), file_path
                )
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to speculatively slice file %s: %s", file_path, exc)

        return frames

    def get_staged_frames(self, file_path: str) -> list[ASTFrame]:
        """Retrieves speculatively staged frames for a file if available."""
        return self._staged_frame_cache.get(file_path, [])
