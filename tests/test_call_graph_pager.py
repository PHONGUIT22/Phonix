"""Unit tests for CallGraphPager static 1-hop and 2-hop context expansion."""

from __future__ import annotations

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.mmu.ast_slicer import ASTFrame
from src.mmu.call_graph_pager import CallGraphPager


def create_sample_frame(name: str, deps: list[str], tokens: int = 100) -> ASTFrame:
    """Helper to construct dummy ASTFrame instances for testing."""
    return ASTFrame(
        frame_id=f"src/demo.py::{name}::hash123",
        file_path="src/demo.py",
        symbol_name=name,
        symbol_type="function",
        token_count=tokens,
        raw_code=f"def {name}(): pass",
        dependencies=deps,
    )


def test_register_frame_and_symbol_lookup() -> None:
    """Verifies indexing AST frames into the pager."""
    pager = CallGraphPager()
    frame = create_sample_frame("func_a", ["func_b"])
    pager.register_frame(frame)

    frames = pager.get_symbol_frames("func_a")
    assert len(frames) == 1
    assert frames[0].symbol_name == "func_a"


def test_page_graph_1_hop_and_2_hop() -> None:
    """Verifies deterministic BFS expansion up to 1-hop and 2-hops."""
    pager = CallGraphPager()
    # Graph: A -> B -> C -> D
    frame_a = create_sample_frame("func_a", ["func_b"])
    frame_b = create_sample_frame("func_b", ["func_c"])
    frame_c = create_sample_frame("func_c", ["func_d"])
    frame_d = create_sample_frame("func_d", [])

    pager.register_frames([frame_a, frame_b, frame_c, frame_d])

    # 1-hop expansion from func_a should include func_a (seed) and func_b (1-hop)
    paged_1hop = pager.page_graph(seed_symbols=["func_a"], max_hops=1, max_token_budget=5000)
    paged_1hop_symbols = {f.symbol_name for f in paged_1hop}
    assert paged_1hop_symbols == {"func_a", "func_b"}

    # 2-hop expansion from func_a should include func_a, func_b, and func_c
    paged_2hop = pager.page_graph(seed_symbols=["func_a"], max_hops=2, max_token_budget=5000)
    paged_2hop_symbols = {f.symbol_name for f in paged_2hop}
    assert paged_2hop_symbols == {"func_a", "func_b", "func_c"}
    assert "func_d" not in paged_2hop_symbols


def test_token_budget_enforcement() -> None:
    """Verifies that frame paging strictly respects token budget constraints."""
    pager = CallGraphPager()
    # Frame size 200 tokens each
    frame_a = create_sample_frame("func_a", ["func_b"], tokens=200)
    frame_b = create_sample_frame("func_b", ["func_c"], tokens=200)
    pager.register_frames([frame_a, frame_b])

    # Budget is 250 tokens: can only fit func_a (200), cannot fit func_b (total 400 > 250)
    paged = pager.page_graph(seed_symbols=["func_a"], max_hops=2, max_token_budget=250)
    assert len(paged) == 1
    assert paged[0].symbol_name == "func_a"


if __name__ == "__main__":
    test_register_frame_and_symbol_lookup()
    test_page_graph_1_hop_and_2_hop()
    test_token_budget_enforcement()
    print("All CallGraphPager tests passed successfully!")
