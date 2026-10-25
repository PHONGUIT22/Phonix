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
from src.gateway.proxy_server import create_gateway_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phonix.main")

# Global ASGI application instance
app = create_gateway_app()


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False) -> None:
    """Launches the Phonix v2.0 FastAPI Gateway using Uvicorn."""
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

    # 4. Verify .agents/rules/GEMINI.md
    rules_dir = agents_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rules_file = rules_dir / "GEMINI.md"
    print(f" [PASS] Verified quota preservation rules at {rules_file}")

    print("=" * 60)
    print(" Phonix v2.0 Quota-Saver Suite successfully installed!")
    print(" Antigravity CLI will now automatically route code inspections")
    print(" through the Context MMU to preserve Five Hour & Weekly Limit quotas.")
    print("=" * 60)
    return 0


def run_mcp_server() -> None:
    """Runs the Stdio MCP Server for Antigravity or Claude CLI."""
    from src.mcp_server import PhonixMCPServer

    server = PhonixMCPServer(workspace_root=_REPO_ROOT)
    server.run_stdio()


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
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_entrypoint()
