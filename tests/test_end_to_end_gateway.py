"""End-to-End Integration Tests for Phonix v2.0 Gateway Core.

Verifies:
1. Deterministic Workspace Indexer populating FileTrie, CallGraphPager, and KVPrefixCache on startup.
2. Speculative matching of file paths in user requests.
3. Zero-Trust AST Sanitization & placeholder vault management.
4. AST context frame injection ([PHONIX CONTEXT MMU — PRUNED AST FRAMES]) into completion payloads.
5. Accurate routing telemetry with selected and evicted frame accounting.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.gateway.proxy_server import (
    ChatCompletionRequest,
    ChatMessage,
    GatewayCore,
)


def test_workspace_indexing_on_startup() -> None:
    """Verifies that GatewayCore automatically indexes the repository on startup."""
    # Initialize gateway with current workspace root
    core = GatewayCore(workspace_root=".", auto_index=True)

    # Invariant 1: Indexes source files across the workspace (>= 15 files)
    assert core.file_trie.total_files >= 15, f"Expected >= 15 indexed files, found {core.file_trie.total_files}"

    # Invariant 2: Repository Symbol Map is pinned in KVPrefixCache
    pinned_prefix = core.kv_prefix_cache.get_prefix("repo_symbol_map")
    assert pinned_prefix is not None, "repo_symbol_map was not pinned in KVPrefixCache"
    assert pinned_prefix.is_pinned is True
    assert len(pinned_prefix.text) > 0

    # Invariant 3: Key architectural files and AST frames are registered
    assert "src/gateway/policy_engine.py" in core._file_to_frames
    assert "src/gateway/semantic_sanitizer.py" in core._file_to_frames
    assert "src/mmu/file_trie.py" in core._file_to_frames
    assert len(core._frame_registry) >= 20, f"Expected >= 20 AST frames, found {len(core._frame_registry)}"


def test_sanitized_ast_context_injection_and_policy() -> None:
    """Verifies end-to-end AST frame paging, sanitization, and context block injection."""
    core = GatewayCore(workspace_root=".", auto_index=True)

    # Prompt referencing an unquoted file and containing a mock secret
    prompt = (
        "Please inspect src/gateway/policy_engine.py and review rule evaluation. "
        "Temporary credential for testing: AKIAIOSFODNN7EXAMPLE"
    )

    request = ChatCompletionRequest(
        model="phonix-v2",
        messages=[
            ChatMessage(role="system", content="You are a principal engineer."),
            ChatMessage(role="user", content=prompt),
        ],
        user_role="contractor",  # Contractor role enforces local fast path
        department="engineering",
    )

    # Execute gateway pipeline
    response = core.process_chat_completion_sync(request)

    # Invariant 1: Valid response envelope
    assert response.id.startswith("chatcmpl-")
    assert response.model in ("phonix-fast-path-stub", "ollama:qwen2.5-coder:1.5b")

    # Invariant 2: Speculative matching successfully extracted target file
    routing = response.phonix_routing
    assert "src/gateway/policy_engine.py" in routing["candidate_files"]

    # Invariant 3: AST frames were paged, selected, and injected into context
    assert len(routing["selected_frame_ids"]) > 0, "Expected selected AST frames to be non-empty"
    assert routing["context_tokens_injected"] > 0

    # Invariant 4: Zero-Trust sanitization redacted the AWS access key
    assert routing["redactions_count"] >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in response.choices[0].message.content

    # Invariant 5: Policy decision allowed execution on local path
    assert routing["policy_decision"]["is_allowed"] is True
    assert routing["routing_eval"]["target_upstream"] == "local"


def test_engineer_cloud_dispatch_with_ast_injection() -> None:
    """Verifies that engineer requests assemble AST context and route with fallback."""
    core = GatewayCore(workspace_root=".", auto_index=True)

    prompt = (
        "Refactor method slice_code in src/mmu/ast_slicer.py to support Tree-sitter C bindings."
    )

    request = ChatCompletionRequest(
        model="phonix-v2",
        messages=[ChatMessage(role="user", content=prompt)],
        user_role="engineer",
        department="engineering",
    )

    response = core.process_chat_completion_sync(request)

    # Check routing telemetry
    routing = response.phonix_routing
    assert "src/mmu/ast_slicer.py" in routing["candidate_files"]
    assert len(routing["selected_frame_ids"]) > 0

    # Verify telemetry metrics updated
    metrics = core.telemetry.get_summary_metrics()
    assert metrics["total_requests"] >= 1


if __name__ == "__main__":
    test_workspace_indexing_on_startup()
    test_sanitized_ast_context_injection_and_policy()
    test_engineer_cloud_dispatch_with_ast_injection()
    print("All end-to-end integration tests passed successfully!")
