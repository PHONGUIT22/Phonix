"""Unit tests for public AST-based G-MMU Context Rendering Engine (src/mmu/gmmu.py).

Verifies:
1. Python AST extraction with class methods (Class.method(args)), docstrings, and constructor in L2.
2. JS/TS regex-based extraction of interfaces, types, classes, and methods.
3. Symbol outline capping at 40 entries with a notice.
4. Scope isolation for module level and top-level function windows.
"""

from __future__ import annotations

import pytest
from src.mmu.gmmu import render_gmmu_bundle, detect_language


def test_detect_language():
    assert detect_language("app/main.py") == "Python"
    assert detect_language("frontend/src/App.tsx") == "TypeScript"
    assert detect_language("lib/utils.ts") == "TypeScript"
    assert detect_language("server/index.js") == "JavaScript"
    assert detect_language("service/main.rs") == "Rust"
    assert detect_language("cmd/app.go") == "Go"
    assert detect_language("config.json") == "JSON"
    assert detect_language("unknown.xyz") == "Unknown"


def test_gmmu_python_class_with_methods_and_docstrings():
    """Verify that fetching only the target method includes L0, L1 (listing both methods with docstrings),

    L2 (showing class header and __init__), and L3 (the target method).
    """
    code = (
        "import os\n"
        "import sys\n\n"
        "class DataPipeline:\n"
        '    """High-throughput streaming ETL pipeline."""\n\n'
        "    def __init__(self, batch_size: int = 100, retries: int = 3):\n"
        '        """Initializes pipeline with given batch size."""\n'
        "        self.batch_size = batch_size\n"
        "        self.retries = retries\n\n"
        "    def format_item(self, item: dict) -> str:\n"
        '        """Formats a single item into JSON line."""\n'
        "        return str(item)\n\n"
        "    def run_pipeline(self, items: list[dict]) -> list[str]:\n"
        '        """Executes processing across all items."""\n'
        "        processed = [self.format_item(i) for i in items]\n"
        "        return processed\n\n"
        "def standalone_utility(x: int) -> int:\n"
        '    """Helper utility function."""\n'
        "    return x * 2\n"
    )

    lines = code.splitlines()
    # Find start and end line of run_pipeline
    start_l = None
    end_l = None
    for i, line in enumerate(lines, 1):
        if "def run_pipeline" in line:
            start_l = i
        if start_l and "return processed" in line:
            end_l = i
            break

    assert start_l is not None and end_l is not None

    bundle = render_gmmu_bundle(
        file_path="src/etl/pipeline.py",
        all_content=code,
        start_line=start_l,
        end_line=end_l,
    )

    # 1. L0 Ghost Scope Overview
    assert "=== [G-MMU L0: Ghost Scope Overview] ===" in bundle
    assert "src/etl/pipeline.py" in bundle
    assert "Language: Python" in bundle
    assert "os" in bundle or "sys" in bundle

    # 2. L1 Structural Outline
    assert "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===" in bundle
    assert "class DataPipeline" in bundle
    assert "High-throughput streaming ETL pipeline." in bundle
    assert "DataPipeline.__init__(self, batch_size, retries)" in bundle
    assert "Initializes pipeline with given batch size." in bundle
    assert "DataPipeline.format_item(self, item)" in bundle
    assert "Formats a single item into JSON line." in bundle
    assert "DataPipeline.run_pipeline(self, items)" in bundle
    assert "Executes processing across all items." in bundle
    assert "def standalone_utility(x)" in bundle

    # 3. L2 Enclosing Context & Scope Isolation
    assert "=== [G-MMU L2: Enclosing Context & Scope Isolation] === " in bundle or "=== [G-MMU L2: Enclosing Context & Scope Isolation] ===" in bundle
    assert "Enclosing Class: class DataPipeline:" in bundle
    assert "Constructor:" in bundle
    assert "def __init__(self, batch_size: int = 100, retries: int = 3):" in bundle
    assert "self.batch_size = batch_size" in bundle

    # 4. L3 Verbatim Edit Window
    assert "=== [G-MMU L3: Verbatim Edit Window: src/etl/pipeline.py" in bundle
    assert "=== Verbatim Edit Window: src/etl/pipeline.py" in bundle
    assert "def run_pipeline(self, items: list[dict]) -> list[str]:" in bundle
    assert "return processed" in bundle


def test_gmmu_jsts_extraction():
    """Verify regex-extracted interfaces, types, classes, and methods appear in L1."""
    ts_code = (
        "import { EventEmitter } from 'events';\n\n"
        "export interface WorkerConfig {\n"
        "    id: string;\n"
        "    concurrency: number;\n"
        "}\n\n"
        "export type WorkerStatus = 'idle' | 'busy' | 'stopped';\n\n"
        "export class AgentCluster extends EventEmitter {\n"
        "    private config: WorkerConfig;\n\n"
        "    constructor(config: WorkerConfig) {\n"
        "        super();\n"
        "        this.config = config;\n"
        "    }\n\n"
        "    public async startCluster(): Promise<void> {\n"
        "        this.emit('start');\n"
        "    }\n\n"
        "    stopCluster(): void {\n"
        "        this.emit('stop');\n"
        "    }\n"
        "}\n\n"
        "export function createDefaultCluster(): AgentCluster {\n"
        "    return new AgentCluster({ id: 'worker-1', concurrency: 4 });\n"
        "}\n"
    )

    bundle = render_gmmu_bundle(
        file_path="src/cluster.ts",
        all_content=ts_code,
        start_line=18,
        end_line=21,
    )

    assert "=== [G-MMU L0: Ghost Scope Overview] ===" in bundle
    assert "Language: TypeScript" in bundle

    assert "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===" in bundle
    assert "interface WorkerConfig" in bundle
    assert "type WorkerStatus" in bundle
    assert "class AgentCluster" in bundle
    assert "AgentCluster.constructor(config: WorkerConfig)" in bundle
    assert "AgentCluster.startCluster()" in bundle
    assert "AgentCluster.stopCluster()" in bundle
    assert "function createDefaultCluster()" in bundle

    assert "=== [G-MMU L2: Enclosing Context & Scope Isolation] ===" in bundle
    assert "Enclosing Class: export class AgentCluster extends EventEmitter" in bundle
    assert "constructor(config: WorkerConfig)" in bundle


def test_gmmu_outline_capped_at_40():
    """Verify that a file with >50 symbols has L1 capped at 40 with a notice."""
    fn_defs = [f"def worker_task_{i:02d}(arg: int) -> int:\n    return arg * {i}\n" for i in range(55)]
    code = "\n".join(fn_defs)

    bundle = render_gmmu_bundle(
        file_path="src/many_functions.py",
        all_content=code,
        start_line=1,
        end_line=3,
    )

    assert "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===" in bundle
    assert "... and 15 more symbols" in bundle
    # Verify that worker_task_00 through worker_task_39 appear, but worker_task_40 does not
    assert "def worker_task_00(arg)" in bundle
    assert "def worker_task_39(arg)" in bundle
    assert "def worker_task_40(arg)" not in bundle


def test_gmmu_module_and_function_level_isolation():
    """Verify L2 scope detection for module level and top-level function."""
    code = (
        "CONSTANT_A = 100\n"
        "CONSTANT_B = 200\n\n"
        "def top_func(x: int) -> int:\n"
        "    y = x + 1\n"
        "    return y * 2\n"
    )

    # 1. Module-level window (lines 1-2)
    bundle_mod = render_gmmu_bundle(
        file_path="src/constants.py",
        all_content=code,
        start_line=1,
        end_line=2,
    )
    assert "Module level scope (no enclosing class or function)" in bundle_mod

    # 2. Top-level function window (lines 5-6)
    bundle_fn = render_gmmu_bundle(
        file_path="src/constants.py",
        all_content=code,
        start_line=5,
        end_line=6,
    )
    assert "Enclosing Function: def top_func(x: int) -> int:" in bundle_fn


def test_mcp_format_window_with_gmmu_fallback(monkeypatch, tmp_path):
    """Verify PhonixMCPServer._format_window_with_gmmu falls back to render_gmmu_bundle when private_moat is absent."""
    import sys
    from unittest.mock import patch
    from src.mcp_server import PhonixMCPServer

    server = PhonixMCPServer(workspace_root=str(tmp_path))
    code = (
        "class ConfigService:\n"
        "    def __init__(self, key: str):\n"
        "        self.key = key\n\n"
        "    def get_key(self) -> str:\n"
        "        return self.key\n"
    )

    with patch.dict(sys.modules, {"private_moat": None, "private_moat.foveated_ast_compactor": None}):
        res = server._format_window_with_gmmu(
            rel_path="src/config.py",
            snippet="        return self.key",
            all_content=code,
            line_range=(5, 5),
        )

    assert "=== [G-MMU L0: Ghost Scope Overview] ===" in res
    assert "src/config.py" in res
    assert "=== [G-MMU L1: Structural Outline (Symbols & Dependencies)] ===" in res
    assert "ConfigService.get_key(self)" in res
    assert "=== [G-MMU L2: Enclosing Context & Scope Isolation] ===" in res
    assert "Enclosing Class: class ConfigService:" in res
    assert "Constructor:" in res
    assert "=== [G-MMU L3: Verbatim Edit Window" in res
    assert "return self.key" in res

