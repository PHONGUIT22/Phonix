"""In-Memory File Trie for 0ms Speculative I/O in Phonix v2.0 Context MMU.

Matches file path prefixes directly from streaming JSON tokens and maintains
a fast prefix index of all repository files to trigger speculative AST paging.
"""

from __future__ import annotations

import re
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


class FileMetadata(BaseModel):
    """Metadata associated with an indexed file in the Context MMU Trie."""

    file_path: str = Field(description="Normalized relative repository path")
    language: str = Field(default="python", description="Programming language identifier")
    size_bytes: int = Field(default=0, description="Size in bytes on disk")
    ast_frame_ids: list[str] = Field(
        default_factory=list, description="IDs of sliced AST frames for this file"
    )
    last_modified: float = Field(default=0.0, description="POSIX timestamp of last modification")


class TrieNode:
    """A single character node in the File Trie."""

    __slots__ = ("char", "children", "is_leaf", "metadata")

    def __init__(self, char: str = "") -> None:
        self.char: str = char
        self.children: dict[str, TrieNode] = {}
        self.is_leaf: bool = False
        self.metadata: FileMetadata | None = None


class FileTrie:
    """In-memory File Trie indexing repository file paths.

    Provides O(K) lookup where K is path length, and speculative extraction of
    candidate paths from streaming JSON token buffers to achieve 0ms speculative I/O.
    """

    def __init__(self) -> None:
        self.root: TrieNode = TrieNode()
        self._total_files: int = 0
        # Matches quoted OR unquoted file path candidates with extensions
        self._path_pattern: re.Pattern[str] = re.compile(
            r'(?:["\']|\b)([a-zA-Z0-9_\-]+(?:[\\/][a-zA-Z0-9_\-\.]+)*\.[a-zA-Z0-9]{1,10})(?:["\']|\b)'
        )
        # Matches partial streaming prefixes containing at least one path separator
        self._prefix_pattern: re.Pattern[str] = re.compile(
            r'(?:["\']|\b)([a-zA-Z0-9_\-]+(?:[\\/][a-zA-Z0-9_\-\.]+)+[\\/]?)(?:["\']|\b)'
        )

    @property
    def total_files(self) -> int:
        """Returns the total number of indexed files."""
        return self._total_files

    def normalize_path(self, path: str) -> str:
        """Normalizes path separators to forward slashes and removes leading dot-slashes."""
        clean = path.replace("\\", "/").strip()
        if clean.startswith("./"):
            clean = clean[2:]
        return clean

    def insert(self, path: str, metadata: FileMetadata | None = None) -> None:
        """Inserts a file path and its metadata into the trie.

        TODO (Phonix v2.0):
        - Integrate filesystem watcher to atomically update metadata on file changes.
        - Track file hash to trigger AST re-slicing only when dirty.
        """
        normalized = self.normalize_path(path)
        if not normalized:
            return

        curr = self.root
        for char in normalized:
            if char not in curr.children:
                curr.children[char] = TrieNode(char)
            curr = curr.children[char]

        if not curr.is_leaf:
            self._total_files += 1
        curr.is_leaf = True
        curr.metadata = metadata or FileMetadata(file_path=normalized)

    def find_exact(self, path: str) -> FileMetadata | None:
        """Performs exact match lookup for a given file path.

        Returns:
            FileMetadata if found, None otherwise.
        """
        normalized = self.normalize_path(path)
        curr = self.root
        for char in normalized:
            if char not in curr.children:
                return None
            curr = curr.children[char]

        return curr.metadata if curr.is_leaf else None

    def search_prefix(self, prefix: str, max_results: int = 10) -> list[str]:
        """Finds all indexed paths sharing the given prefix.

        Returns:
            List of matching file paths up to max_results.
        """
        normalized = self.normalize_path(prefix)
        curr = self.root
        for char in normalized:
            if char not in curr.children:
                return []
            curr = curr.children[char]

        results: list[str] = []
        self._collect_paths(curr, normalized, results, max_results)
        return results

    def _collect_paths(
        self, node: TrieNode, current_path: str, results: list[str], max_results: int
    ) -> None:
        """Depth-first search traversal to collect file paths."""
        if len(results) >= max_results:
            return
        if node.is_leaf:
            results.append(current_path)

        for char, child_node in sorted(node.children.items()):
            if len(results) >= max_results:
                break
            self._collect_paths(child_node, current_path + char, results, max_results)

    def speculative_match_streaming_tokens(self, token_buffer: str) -> list[str]:
        """Scans raw streaming JSON token buffer to identify referenced files before parsing ends.

        Enables 0ms Speculative I/O by triggering AST frame pre-fetching
        while HTTP streaming chunks are still being received. Supports both quoted
        and unquoted file paths as well as partial streaming path prefixes (e.g. 'src/gateway/pol').

        TODO (Phonix v2.0):
        - Implement streaming Aho-Corasick or direct byte-level automaton for sub-millisecond scans.
        - Cache partial match states across chunk boundaries.
        """
        matches: set[str] = set()

        # 1. Match full path candidates with extensions (quoted or unquoted)
        for raw_candidate in self._path_pattern.findall(token_buffer):
            candidate = self.normalize_path(raw_candidate)
            if self.find_exact(candidate) is not None:
                matches.add(candidate)
            else:
                prefixes = self.search_prefix(candidate, max_results=3)
                matches.update(prefixes)

        # 2. Match partial streaming path prefixes containing at least one path separator
        for raw_prefix in self._prefix_pattern.findall(token_buffer):
            prefix_candidate = self.normalize_path(raw_prefix)
            if "/" in prefix_candidate:
                prefixes = self.search_prefix(prefix_candidate, max_results=5)
                matches.update(prefixes)

        return sorted(matches)
