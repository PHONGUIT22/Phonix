"""Unit tests for FileTrie and Speculative 0ms I/O matching."""

from __future__ import annotations

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.mmu.file_trie import FileMetadata, FileTrie


def test_insert_and_find_exact() -> None:
    """Verifies inserting paths and retrieving exact metadata."""
    trie = FileTrie()
    trie.insert("src/gateway/proxy_server.py", FileMetadata(file_path="src/gateway/proxy_server.py"))
    trie.insert("src/mmu/file_trie.py")

    assert trie.total_files == 2

    # Exact match hit
    meta = trie.find_exact("src/gateway/proxy_server.py")
    assert meta is not None
    assert meta.file_path == "src/gateway/proxy_server.py"

    # Exact match miss
    assert trie.find_exact("non_existent_file.py") is None


def test_search_prefix() -> None:
    """Verifies prefix searching across repository file paths."""
    trie = FileTrie()
    trie.insert("src/mmu/file_trie.py")
    trie.insert("src/mmu/ast_slicer.py")
    trie.insert("src/mmu/call_graph_pager.py")
    trie.insert("src/gateway/proxy_server.py")

    matches = trie.search_prefix("src/mmu/")
    assert len(matches) == 3
    assert "src/mmu/file_trie.py" in matches
    assert "src/mmu/ast_slicer.py" in matches
    assert "src/mmu/call_graph_pager.py" in matches


def test_speculative_match_streaming_tokens() -> None:
    """Verifies extracting file paths from streaming JSON tokens for 0ms speculative I/O."""
    trie = FileTrie()
    trie.insert("src/gateway/proxy_server.py")
    trie.insert("src/mmu/ast_slicer.py")

    # Simulated incoming partial JSON stream chunk
    streaming_chunk = '{"action": "inspect", "file": "src/gateway/proxy_server.py", "extra": 42}'
    matches = trie.speculative_match_streaming_tokens(streaming_chunk)

    assert "src/gateway/proxy_server.py" in matches


def test_speculative_match_unquoted_and_partial_prefixes() -> None:
    """Verifies matching unquoted paths and streaming partial prefixes."""
    trie = FileTrie()
    trie.insert("src/gateway/proxy_server.py")
    trie.insert("src/gateway/policy_engine.py")
    trie.insert("src/mmu/ast_slicer.py")

    # Unquoted path in natural language prompt
    nl_prompt = "Please inspect src/gateway/proxy_server.py and optimize its routing."
    matches = trie.speculative_match_streaming_tokens(nl_prompt)
    assert "src/gateway/proxy_server.py" in matches

    # Partial streaming prefix without extension
    partial_stream = "Investigate error in src/gateway/pol before next chunk"
    partial_matches = trie.speculative_match_streaming_tokens(partial_stream)
    assert "src/gateway/policy_engine.py" in partial_matches


if __name__ == "__main__":
    test_insert_and_find_exact()
    test_search_prefix()
    test_speculative_match_streaming_tokens()
    test_speculative_match_unquoted_and_partial_prefixes()
    print("All FileTrie tests passed successfully!")
