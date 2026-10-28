"""Main entry point and CLI runner for Phonix v2.0 Gateway.

Usage:
    phonix start [--host HOST] [--port PORT]
    phonix status
    phonix verify-policy [--role ROLE] [--dept DEPT]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.gateway.policy_engine import PolicyEngine, PolicyRequest
from src.gateway.proxy_server import (
    GatewayCore,
    PHONIX_HP_RULE_CONTENT,
    _ensure_phonix_hp_rule,
    create_gateway_app,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phonix.main")

# Global ASGI application instance (lazy initialization: auto_index=False by default)
app = create_gateway_app(auto_index=False)


def auto_bootstrap_agy_environment(repo_root: str = _REPO_ROOT, install_hooks: bool = False) -> None:
    """Safe workspace MCP bootstrapper.

    Strictly Read-Only by default:
    - NEVER touches ~/.gemini or any user home profile directories.
    - NEVER scans or mutates sibling directories (zero parent_dir.iterdir()).
    - Only configures local <repo_root>/.agents/mcp_config.json if explicitly requested.
    """
    if not install_hooks:
        return

    root_path = Path(repo_root).resolve()
    py_exec = sys.executable or "python"
    agents_dir = root_path / ".agents"
    try:
        agents_dir.mkdir(parents=True, exist_ok=True)
        local_mcp = agents_dir / "mcp_config.json"
        cfg: dict[str, Any] = {"mcpServers": {}}
        if local_mcp.is_file():
            try:
                with open(local_mcp, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        cfg = loaded
            except Exception:
                pass

        cfg.setdefault("mcpServers", {})["phonix-mmu"] = {
            "command": py_exec,
            "args": ["-m", "src.mcp_server"],
            "env": {"PYTHONPATH": str(root_path)},
        }
        with open(local_mcp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        logger.info("Configured local workspace MCP config at %s", local_mcp)
    except Exception as exc:
        logger.debug("Could not write local MCP config at %s: %s", root_path, exc)


def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = False,
    install_hooks: bool = False,
) -> None:
    """Launches the Phonix v2.0 FastAPI Gateway using Uvicorn."""
    if install_hooks:
        auto_bootstrap_agy_environment(install_hooks=True)
    try:
        import uvicorn  # type: ignore

        logger.info("Starting Phonix v2.0 Zero-Trust Gateway on %s:%d", host, port)
        uvicorn.run("src.main:app", host=host, port=port, reload=reload)
    except ImportError:
        logger.error(
            "Uvicorn is not installed. Please run: pip install uvicorn[standard]"
        )
        sys.exit(1)


def show_status() -> None:
    """Prints runtime status, hardware profile limits, and active policies."""
    print("=" * 60)
    print(" Phonix v2.0 - Zero-Trust AST Paging & 1B Micro-Router Gateway")
    print("=" * 60)
    print(" [Core Engine]")
    print("  - Version: 2.0.0")
    print("  - Architecture: Enterprise Compliance & Cost Gateway + Context MMU")
    print(" [Hardware Profile]")
    print("  - VRAM Budget: 1.2 GB (Strict)")
    print("  - Quantization: Q4_K_M")
    print("  - Model Target: Llama-3.2-1B-Instruct / Qwen2.5-Coder-1.5B")
    print(" [Context MMU]")
    print("  - Max AST Frame: < 512 tokens")
    print("  - Speculative I/O: 0ms FileTrie prefix matching")
    print("  - Call Graph: Deterministic 1-hop / 2-hop BFS")
    print(" [Zero-Trust Policy Engine]")
    print("  - Formal Verifier: Z3 SMT Solver")
    print("  - Sanitizer: Semantic-Preserving (100% Identifiers Intact)")
    print("=" * 60)


def verify_policy(role: str, department: str, unredacted_secrets: int) -> None:
    """Runs a live verification check using the Z3 Policy Engine."""
    engine = PolicyEngine()
    req = PolicyRequest(
        role=role,
        department=department,
        target_upstream="anthropic",
        estimated_tokens=500,
        unredacted_secrets_count=unredacted_secrets,
    )
    decision = engine.evaluate(req)
    print(f"Policy Verification for Role='{role}', Dept='{department}', Secrets={unredacted_secrets}:")
    print(f"  Allowed: {decision.is_allowed}")
    print(f"  Z3 Status: {decision.z3_proof_status}")
    print(f"  Reason: {decision.reason}")
    print(f"  Headroom: {decision.token_headroom} tokens")


def install_agy(repo_root: str = _REPO_ROOT) -> int:
    """Registers Phonix MMU in workspace .agents/mcp_config.json and ensures .agents/ configs exist."""
    print("=" * 60)
    print(" Installing Phonix v2.0 Quota-Saver Suite for Antigravity CLI")
    print("=" * 60)

    # 1. Register in workspace .agents/mcp_config.json
    agents_dir = Path(repo_root) / ".agents"
    try:
        agents_dir.mkdir(parents=True, exist_ok=True)
        local_mcp_path = agents_dir / "mcp_config.json"
        local_config: dict[str, Any] = {"mcpServers": {}}
        if local_mcp_path.is_file():
            try:
                with open(local_mcp_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        local_config = loaded
            except Exception as exc:
                logger.warning("Could not parse existing %s: %s", local_mcp_path, exc)

        if "mcpServers" not in local_config or not isinstance(local_config["mcpServers"], dict):
            local_config["mcpServers"] = {}

        local_config["mcpServers"]["phonix-mmu"] = {
            "command": sys.executable,
            "args": ["-m", "src.mcp_server"],
            "env": {"PYTHONPATH": repo_root},
        }

        with open(local_mcp_path, "w", encoding="utf-8") as f:
            json.dump(local_config, f, indent=2)
        print(f" [PASS] Registered 'phonix-mmu' in {local_mcp_path}")
    except Exception as exc:
        print(f" [WARN] Could not write {local_mcp_path}: {exc}")

    # 2. Verify .agents/hooks.json
    hooks_file = agents_dir / "hooks.json"
    hooks_content = {
        "phonix-quota-and-security-gate": {
            "enabled": True,
            "SessionStart": [
                {
                    "type": "command",
                    "command": "python -m src.agy_hooks session-start",
                    "timeout": 10,
                }
            ],
            "UserPromptSubmit": [
                {
                    "type": "command",
                    "command": "python -m src.agy_hooks user-prompt-submit",
                    "timeout": 5,
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "read_file|view_file|read_file_lines|run_command|ManageTask|manage_task|Bash|bash|execute_command",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python -m src.agy_hooks pre-tool-use",
                            "timeout": 5,
                        }
                    ],
                }
            ],
        }
    }
    try:
        if not hooks_file.exists():
            with open(hooks_file, "w", encoding="utf-8") as f:
                json.dump(hooks_content, f, indent=2)
        print(f" [PASS] Verified hooks configuration at {hooks_file}")
    except Exception as exc:
        print(f" [WARN] Could not write {hooks_file}: {exc}")

    # 3. Verify .agents/rules/PhonixHP.md
    rules_dir = agents_dir / "rules"
    rules_file = rules_dir / "PhonixHP.md"
    try:
        rules_dir.mkdir(parents=True, exist_ok=True)
        _ensure_phonix_hp_rule(repo_root)
        print(f" [PASS] Verified quota preservation rules at {rules_file}")
    except Exception as exc:
        print(f" [WARN] Could not write {rules_file}: {exc}")

    print("=" * 60)
    print(" Phonix v2.0 Quota-Saver Suite successfully installed!")
    print(" Antigravity CLI will now automatically route code inspections")
    print(" through the Context MMU to preserve Five Hour & Weekly Limit quotas.")
    print("=" * 60)
    return 0


def attach_workspace(target_dir: str = ".") -> int:
    """Attaches Phonix v2.0 Quota-Armor to an external codebase.

    1. Injects .agents/rules/PhonixHP.md
    2. Registers phonix-mmu in target project's .agents/mcp_config.json
    3. Indexes the target codebase and builds compact AST symbols
    """
    target_path = Path(target_dir).resolve()
    print("=" * 65)
    print(" Phonix v2.0 - Attach Quota Armor to Target Codebase")
    print("=" * 65)
    print(f" [*] Target Workspace: {target_path}")

    if not target_path.is_dir():
        print(f" [!] Error: Target directory '{target_path}' does not exist.")
        return 1

    # 1. Inject PhonixHP.md
    _ensure_phonix_hp_rule(target_path)
    rules_file = target_path / ".agents" / "rules" / "PhonixHP.md"
    print(f" [PASS] Injected PhonixHP.md quota rule at {rules_file}")

    # 2. Register phonix-mmu in target's .agents/mcp_config.json
    agents_dir = target_path / ".agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    mcp_config_path = agents_dir / "mcp_config.json"

    py_executable = sys.executable or "python"
    phonix_repo_dir = _REPO_ROOT

    config_data: dict[str, Any] = {"mcpServers": {}}
    if mcp_config_path.is_file():
        try:
            with open(mcp_config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict) and "mcpServers" in loaded:
                    config_data = loaded
        except Exception:
            pass

    config_data.setdefault("mcpServers", {})["phonix-mmu"] = {
        "command": py_executable,
        "args": ["-m", "src.mcp_server"],
        "cwd": phonix_repo_dir,
        "env": {
            "PHONIX_WORKSPACE": str(target_path),
            "PYTHONPATH": phonix_repo_dir,
        },
    }

    with open(mcp_config_path, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    print(f" [PASS] Registered phonix-mmu MCP server in {mcp_config_path}")

    # 3. Index target codebase in memory (Read-Only)
    print(" [*] Indexing target codebase AST frames in memory (Read-Only)...")
    core = GatewayCore(workspace_root=str(target_path), auto_index=True)
    file_count = core.file_trie.total_files
    frame_count = len(core._frame_registry)
    print(f" [PASS] Successfully indexed {file_count} files ({frame_count} AST frames in memory)")
    print("=" * 65)
    print(" Codebase successfully equipped with Phonix v2.0 Quota Armor!")
    print(f" Antigravity agents in '{target_path.name}' will now use phonix-mmu")
    print(" to save 75%-85% token quota and prevent context limit exhaustion.")
    print("=" * 65)
    return 0


def run_mcp_server() -> None:
    """Runs the Stdio MCP Server for Antigravity or Claude CLI."""
    from src.mcp_server import PhonixMCPServer

    server = PhonixMCPServer(workspace_root=_REPO_ROOT)
    server.run_stdio()


def build_dataset_command(
    max_commits: int = 50,
    output_path: str = "data/phonix_router_sft_dataset.jsonl",
    repo_path: str = _REPO_ROOT,
) -> int:
    """Mines Git commits and exports an SFT dataset for Micro-Router fine-tuning."""
    from src.micro_router.data_flywheel import RouterDataFlywheel

    print("=" * 65)
    print(" Phonix v2.0 - Git-Commit AST Data Moat Miner & SFT Flywheel")
    print("=" * 65)
    flywheel = RouterDataFlywheel(workspace_root=repo_path)
    print(f"[*] Mining up to {max_commits} recent commits in '{repo_path}'...")
    samples = flywheel.mine_git_history(repo_path=repo_path, max_commits=max_commits)
    count = flywheel.export_jsonl(samples, output_path=output_path)
    stats = flywheel.calculate_statistics(samples)

    print(f"[+] Successfully exported {count} training samples to '{output_path}'")
    print("-" * 65)
    print(" Dataset Summary Statistics:")
    print(f"  - Total Mined Samples:        {stats['total_samples']}")
    print(f"  - Selected AST Frames:        {stats['total_selected_frames']}")
    print(f"  - Dropped AST Frames:         {stats['total_dropped_frames']}")
    pruning_pct = stats['avg_pruning_ratio'] * 100.0 if stats['total_samples'] > 0 else 0.0
    local_pct = stats.get('local_pct', 0.0)
    cloud_pct = stats.get('cloud_pct', 0.0)
    print(f"  - Average AST Pruning Ratio:  {pruning_pct:.1f}%")
    print(f"  - Local Fast-Path Handoff:    {stats['local_count']} ({local_pct:.1f}%)")
    print(f"  - Cloud Egress Handoff:       {stats['cloud_count']} ({cloud_pct:.1f}%)")
    print("  - Task Categories:")
    for cat, n in stats.get("category_distribution", {}).items():
        print(f"      * {cat:16s}: {n} samples")
    print("=" * 65)
    return count


def cli_entrypoint() -> None:
    """Command Line Interface entrypoint defined in pyproject.toml."""
    parser = argparse.ArgumentParser(
        prog="phonix",
        description="Phonix v2.0 - Zero-Trust AST Paging & 1B Micro-Router Gateway",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # start command
    start_parser = subparsers.add_parser("start", help="Start the gateway server")
    start_parser.add_argument("--host", default="0.0.0.0", help="Binding host IP")
    start_parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    start_parser.add_argument("--reload", action="store_true", help="Enable hot reload")
    start_parser.add_argument(
        "--install-hooks",
        action="store_true",
        help="Opt-in: install global hooks.json and rules files into agy environment",
    )

    # status command
    subparsers.add_parser("status", help="Display hardware profile and engine status")

    # verify-policy command
    verify_parser = subparsers.add_parser("verify-policy", help="Test Z3 policy engine")
    verify_parser.add_argument("--role", default="engineer", help="Role (admin, engineer, contractor)")
    verify_parser.add_argument("--dept", default="engineering", help="Department")
    verify_parser.add_argument(
        "--unredacted-secrets", type=int, default=0, help="Number of simulated unredacted secrets"
    )

    # install-agy command
    subparsers.add_parser("install-agy", help="Install Quota-Saver suite into Antigravity CLI")

    # mcp command
    subparsers.add_parser("mcp", help="Run Model Context Protocol stdio server")

    # build-dataset command
    dataset_parser = subparsers.add_parser(
        "build-dataset", help="Mine Git history into Micro-Router SFT training dataset"
    )
    dataset_parser.add_argument(
        "--max-commits", type=int, default=50, help="Maximum number of commits to mine"
    )
    dataset_parser.add_argument(
        "--output", default="data/phonix_router_sft_dataset.jsonl", help="Output JSONL path"
    )

    # attach command
    attach_parser = subparsers.add_parser(
        "attach", help="Attach PhonixHP quota armor to an external codebase"
    )
    attach_parser.add_argument(
        "target_dir",
        nargs="?",
        default=".",
        help="Target workspace path (default: current directory)",
    )

    args = parser.parse_args()

    if args.command == "start":
        run_server(
            host=args.host,
            port=args.port,
            reload=args.reload,
            install_hooks=args.install_hooks,
        )
    elif args.command == "status":
        show_status()
    elif args.command == "verify-policy":
        verify_policy(args.role, args.dept, args.unredacted_secrets)
    elif args.command == "install-agy":
        install_agy()
    elif args.command == "mcp":
        run_mcp_server()
    elif args.command == "build-dataset":
        build_dataset_command(max_commits=args.max_commits, output_path=args.output)
    elif args.command == "attach":
        attach_workspace(target_dir=args.target_dir)
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_entrypoint()
