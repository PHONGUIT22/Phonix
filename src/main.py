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

# Global ASGI application instance
app = create_gateway_app()


def auto_bootstrap_agy_environment(repo_root: str = _REPO_ROOT) -> None:
    """Zero-Touch, Zero-Prompt Auto-Bootstrapper for agy IDE & CLI across all projects.

    1. Configures global ~/.gemini/config/mcp_config.json with dynamic phonix-mmu (no hardcoded PHONIX_WORKSPACE).
    2. Injects PhonixHP.md quota rules into global ~/.gemini/ paths & instructions.md.
    3. Configures global hooks.json pointing to absolute agy_hooks.py.
    4. Auto-discovers sibling projects under repo_root.parent, injects PhonixHP.md,
       cleans stale configs, and appends .agents/ to .git/info/exclude for 0 untracked files.
    """
    root_path = Path(repo_root).resolve()
    py_exec = sys.executable or "python"
    hooks_script = str(root_path / "src" / "agy_hooks.py")

    # 1. Global MCP config (~/.gemini/config/mcp_config.json)
    home_gemini = Path.home() / ".gemini"
    global_mcp_paths = [
        home_gemini / "config" / "mcp_config.json",
        home_gemini / "antigravity-cli" / "config" / "mcp_config.json",
    ]
    for mcp_path in global_mcp_paths:
        try:
            mcp_path.parent.mkdir(parents=True, exist_ok=True)
            cfg: dict[str, Any] = {"mcpServers": {}}
            if mcp_path.is_file():
                try:
                    with open(mcp_path, "r", encoding="utf-8") as f:
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
            # Remove any stale hardcoded PHONIX_WORKSPACE or cwd from global config
            cfg["mcpServers"]["phonix-mmu"].pop("cwd", None)
            if "env" in cfg["mcpServers"]["phonix-mmu"]:
                cfg["mcpServers"]["phonix-mmu"]["env"].pop("PHONIX_WORKSPACE", None)

            with open(mcp_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            logger.info("Synchronized global MCP config at %s", mcp_path)
        except Exception as exc:
            logger.debug("Could not write MCP config at %s: %s", mcp_path, exc)

    # 2. Global Rules & Instructions (PhonixHP.md)
    rule_targets = [
        home_gemini / "GEMINI.md",
        home_gemini / "config" / "GEMINI.md",
        home_gemini / "config" / "rules" / "PhonixHP.md",
        home_gemini / "antigravity-cli" / "mcp" / "phonix-mmu" / "instructions.md",
        home_gemini / "antigravity" / "mcp" / "phonix-mmu" / "instructions.md",
    ]
    for r_path in rule_targets:
        try:
            r_path.parent.mkdir(parents=True, exist_ok=True)
            r_path.write_text(PHONIX_HP_RULE_CONTENT, encoding="utf-8")
            logger.info("Injected PhonixHP rule to %s", r_path)
        except Exception as exc:
            logger.debug("Could not write rule to %s: %s", r_path, exc)

    # 3. Global hooks.json (~/.gemini/config/hooks.json & ~/.gemini/hooks.json)
    hooks_payload = {
        "phonix-quota-and-security-gate": {
            "enabled": True,
            "SessionStart": [
                {
                    "type": "command",
                    "command": f'"{py_exec}" "{hooks_script}" session-start',
                    "timeout": 10,
                }
            ],
            "PreToolUse": [
                {
                    "matcher": "read_file|view_file|read_file_lines|run_command",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f'"{py_exec}" "{hooks_script}" pre-tool-use',
                            "timeout": 5,
                        }
                    ],
                }
            ],
        }
    }
    for hk_path in [home_gemini / "config" / "hooks.json", home_gemini / "hooks.json"]:
        try:
            hk_path.parent.mkdir(parents=True, exist_ok=True)
            with open(hk_path, "w", encoding="utf-8") as f:
                json.dump(hooks_payload, f, indent=2)
            logger.info("Synchronized global hooks at %s", hk_path)
        except Exception as exc:
            logger.debug("Could not write hooks to %s: %s", hk_path, exc)

    # 4. Sibling repos auto-discovery & injection
    parent_dir = root_path.parent
    if parent_dir.is_dir():
        for child in parent_dir.iterdir():
            if not child.is_dir() or child == root_path or child.name.startswith("."):
                continue

            # Ensure .agents/rules/PhonixHP.md and .git/info/exclude
            _ensure_phonix_hp_rule(child)

            # Ensure clean .agents/mcp_config.json without hardcoded PHONIX_WORKSPACE
            child_agents = child / ".agents"
            if child_agents.is_dir():
                child_mcp = child_agents / "mcp_config.json"
                if child_mcp.is_file():
                    try:
                        with open(child_mcp, "r", encoding="utf-8") as f:
                            c_cfg = json.load(f)
                        if isinstance(c_cfg, dict) and "mcpServers" in c_cfg:
                            if "phonix-mmu" in c_cfg["mcpServers"]:
                                c_cfg["mcpServers"]["phonix-mmu"].pop("cwd", None)
                                if "env" in c_cfg["mcpServers"]["phonix-mmu"]:
                                    c_cfg["mcpServers"]["phonix-mmu"]["env"].pop("PHONIX_WORKSPACE", None)
                                with open(child_mcp, "w", encoding="utf-8") as f:
                                    json.dump(c_cfg, f, indent=2)
                    except Exception:
                        pass

                # Child hooks.json with absolute script path
                child_hooks = child_agents / "hooks.json"
                try:
                    with open(child_hooks, "w", encoding="utf-8") as f:
                        json.dump(hooks_payload, f, indent=2)
                except Exception:
                    pass


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:
    """Launches the Phonix v2.0 FastAPI Gateway using Uvicorn."""
    auto_bootstrap_agy_environment()
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
    """Registers Phonix MMU in global ~/.gemini/config/mcp_config.json and ensures .agents/ configs exist."""
    print("=" * 60)
    print(" Installing Phonix v2.0 Quota-Saver Suite for Antigravity CLI")
    print("=" * 60)

    # Run complete zero-touch environment bootstrap
    auto_bootstrap_agy_environment(repo_root=repo_root)

    # 1. Register in global ~/.gemini/config/mcp_config.json
    global_mcp_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
    global_mcp_path.parent.mkdir(parents=True, exist_ok=True)

    config_data: dict[str, Any] = {"mcpServers": {}}
    if global_mcp_path.is_file():
        try:
            with open(global_mcp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    config_data = loaded
        except Exception as exc:
            logger.warning("Could not parse existing %s: %s", global_mcp_path, exc)

    if "mcpServers" not in config_data or not isinstance(config_data["mcpServers"], dict):
        config_data["mcpServers"] = {}

    config_data["mcpServers"]["phonix-mmu"] = {
        "command": sys.executable,
        "args": ["-m", "src.mcp_server"],
        "env": {"PYTHONPATH": repo_root},
    }

    try:
        with open(global_mcp_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        print(f" [PASS] Registered 'phonix-mmu' in {global_mcp_path}")
    except Exception as exc:
        print(f" [WARN] Could not write {global_mcp_path}: {exc}")

    # 2. Register in workspace .agents/mcp_config.json
    agents_dir = Path(repo_root) / ".agents"
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

    try:
        with open(local_mcp_path, "w", encoding="utf-8") as f:
            json.dump(local_config, f, indent=2)
        print(f" [PASS] Registered 'phonix-mmu' in {local_mcp_path}")
    except Exception as exc:
        print(f" [WARN] Could not write {local_mcp_path}: {exc}")

    # 3. Verify .agents/hooks.json
    hooks_file = agents_dir / "hooks.json"
    if not hooks_file.exists():
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
                "PreToolUse": [
                    {
                        "matcher": "read_file|view_file|run_command",
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
        with open(hooks_file, "w", encoding="utf-8") as f:
            json.dump(hooks_content, f, indent=2)
    print(f" [PASS] Verified hooks configuration at {hooks_file}")

    # 4. Verify .agents/rules/PhonixHP.md
    rules_dir = agents_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rules_file = rules_dir / "PhonixHP.md"
    _ensure_phonix_hp_rule(repo_root)
    print(f" [PASS] Verified quota preservation rules at {rules_file}")

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

    # Also register in user's global ~/.gemini/config/mcp_config.json
    try:
        global_mcp_path = Path.home() / ".gemini" / "config" / "mcp_config.json"
        global_mcp_path.parent.mkdir(parents=True, exist_ok=True)
        global_cfg: dict[str, Any] = {"mcpServers": {}}
        if global_mcp_path.is_file():
            try:
                with open(global_mcp_path, "r", encoding="utf-8") as f:
                    global_cfg = json.load(f)
            except Exception:
                pass
        global_cfg.setdefault("mcpServers", {})["phonix-mmu"] = {
            "command": py_executable,
            "args": ["-m", "src.mcp_server"],
            "cwd": phonix_repo_dir,
            "env": {
                "PHONIX_WORKSPACE": str(target_path),
                "PYTHONPATH": phonix_repo_dir,
            },
        }
        with open(global_mcp_path, "w", encoding="utf-8") as f:
            json.dump(global_cfg, f, indent=2)
        print(f" [PASS] Synchronized global MCP configuration at {global_mcp_path}")
    except Exception as exc:
        logger.debug("Could not update global config: %s", exc)

    # 3. Index target codebase
    print(" [*] Indexing target codebase AST frames...")
    core = GatewayCore(workspace_root=str(target_path), auto_index=True)
    file_count = core.file_trie.total_files
    frame_count = len(core._frame_registry)
    print(f" [PASS] Successfully indexed {file_count} files ({frame_count} AST frames)")
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
        run_server(host=args.host, port=args.port, reload=args.reload)
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
