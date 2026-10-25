"""Context MMU (Memory Management Unit) for Phonix v2.0.

Provides deterministic Tree-sitter AST slicing, 1-hop/2-hop static call graph paging,
in-memory File Trie for 0ms speculative I/O, pinned KV prefix caching, and LRU frame eviction.
"""

from __future__ import annotations

from src.mmu.ast_slicer import ASTFrame, ASTSlicer
from src.mmu.call_graph_pager import CallGraphEdge, CallGraphPager
from src.mmu.file_trie import FileMetadata, FileTrie, TrieNode
from src.mmu.frame_evictor import FrameEvictionPolicy, FrameEvictor
from src.mmu.kv_prefix_cache import KVPrefixCache, PrefixEntry
from src.mmu.speculative_inspector import SpeculativeInspector

__all__ = [
    "ASTFrame",
    "ASTSlicer",
    "CallGraphEdge",
    "CallGraphPager",
    "FileMetadata",
    "FileTrie",
    "FrameEvictionPolicy",
    "FrameEvictor",
    "KVPrefixCache",
    "PrefixEntry",
    "SpeculativeInspector",
    "TrieNode",
]
