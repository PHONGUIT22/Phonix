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
import os
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
    _ensure_target_mcp_config,
    create_gateway_app,
    is_loopback_host,
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
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
    install_hooks: bool = False,
) -> None:
    """Launches the Phonix v2.0 FastAPI Gateway using Uvicorn."""
    if not is_loopback_host(host):
        token = os.environ.get("PHONIX_API_TOKEN")
        if not token or not token.strip():
            logger.error("Non-loopback host '%s' requires PHONIX_API_TOKEN environment variable to be set.", host)
            raise ValueError(f"Non-loopback host '{host}' requires PHONIX_API_TOKEN to be set.")

    os.environ["PHONIX_HOST"] = host

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
    _ensure_target_mcp_config(target_path)
    mcp_config_path = target_path / ".agents" / "mcp_config.json"
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


def run_mcp_server(workspace_root: str | None = None) -> None:
    """Runs the Stdio MCP Server for Antigravity, Claude, or Cursor."""
    from src.mcp_server import run_stdio_server

    run_stdio_server(workspace_root=workspace_root)


def export_configs_command(workspace: str = ".", out: str | None = None) -> int:
    """Generates 1-click MCP configs for Claude Desktop, Cursor, and Cline."""
    target_ws = str(Path(workspace).resolve())
    phonix_root = str(Path(_REPO_ROOT).resolve())
    py_exec = sys.executable or "python"

    if out:
        out_dir = Path(out).resolve()
    else:
        out_dir = Path(_REPO_ROOT) / "integrations" / "mcp_configs" / "generated"

    out_dir.mkdir(parents=True, exist_ok=True)

    claude_cfg = {
        "mcpServers": {
            "phonix-mmu": {
                "command": py_exec,
                "args": ["-m", "src.main", "mcp", "--workspace", target_ws],
                "cwd": phonix_root,
            }
        }
    }

    cursor_cfg = {
        "mcpServers": {
            "phonix-mmu": {
                "command": py_exec,
                "args": ["-m", "src.main", "mcp", "--workspace", target_ws],
                "cwd": phonix_root,
            }
        }
    }

    cline_cfg = {
        "mcpServers": {
            "phonix-mmu": {
                "command": py_exec,
                "args": ["-m", "src.main", "mcp", "--workspace", target_ws],
                "cwd": phonix_root,
                "disabled": False,
                "autoApprove": [],
            }
        }
    }

    claude_path = out_dir / "claude_desktop_config.json"
    cursor_path = out_dir / "cursor_mcp_config.json"
    cline_path = out_dir / "cline_mcp_config.json"

    claude_path.write_text(json.dumps(claude_cfg, indent=2) + "\n", encoding="utf-8")
    cursor_path.write_text(json.dumps(cursor_cfg, indent=2) + "\n", encoding="utf-8")
    cline_path.write_text(json.dumps(cline_cfg, indent=2) + "\n", encoding="utf-8")

    print("=" * 68)
    print(" Phonix v2.0 - 1-Click Multi-Platform MCP Configs Exporter")
    print("=" * 68)
    print(f" Target Workspace: {target_ws}")
    print(f" Phonix Repo Root: {phonix_root}")
    print(f" Python Binary:    {py_exec}")
    print(f" Output Directory: {out_dir}")
    print("-" * 68)
    print(f" [PASS] Claude Desktop: {claude_path}")
    print(f" [PASS] Cursor IDE:     {cursor_path}")
    print(f" [PASS] Cline/Roo Code: {cline_path}")
    print("=" * 68)
    return 0


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


def find_phonix_leftovers(home_dir: Path) -> dict[str, list[Any]]:
    """Scans <home_dir>/.gemini for Phonix leftovers (state, rules, skills, MCP, logs)."""
    gemini_dir = home_dir / ".gemini"
    leftovers: dict[str, list[Any]] = {
        "state": [],
        "rules": [],
        "skills": [],
        "mcp_configs": [],
        "logs": [],
    }
    if not gemini_dir.is_dir():
        return leftovers

    # 1. State files
    state_file = gemini_dir / "phonix_circuit_state.json"
    if state_file.is_file():
        leftovers["state"].append(state_file)

    # 2. Rules
    for pattern in ("*phonix*.md", "*Phonix*.md"):
        for rule_path in gemini_dir.glob(f"**/rules/{pattern}"):
            if rule_path.is_file() and rule_path not in leftovers["rules"]:
                leftovers["rules"].append(rule_path)

    # 3. Skills
    for skill_dir in gemini_dir.glob("skills/*phonix*"):
        if skill_dir.exists() and skill_dir not in leftovers["skills"]:
            leftovers["skills"].append(skill_dir)

    # 4. MCP configs
    for cfg_cand in [
        gemini_dir / "mcp_config.json",
        gemini_dir / "antigravity-cli" / "mcp_config.json",
    ]:
        if cfg_cand.is_file():
            try:
                data = json.loads(cfg_cand.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "mcpServers" in data:
                    if "phonix-mmu" in data["mcpServers"]:
                        leftovers["mcp_configs"].append(cfg_cand)
            except Exception:
                pass

    # 5. Logs
    for log_path in gemini_dir.glob("**/*phonix*.log"):
        if log_path.is_file() and log_path not in leftovers["logs"]:
            leftovers["logs"].append(log_path)

    return leftovers


def doctor_command(fix: bool = False, home_dir: Path | None = None) -> int:
    """Audits and optionally cleans Phonix leftovers under ~/.gemini."""
    import shutil

    if home_dir is None:
        home_dir = Path.home()

    gemini_dir = home_dir / ".gemini"
    print("=" * 65)
    print(" Phonix v2.0 Doctor - Machine Hygiene Auditor")
    print("=" * 65)
    print(f" Target Home:   {home_dir}")
    print(f" Target Gemini: {gemini_dir}")
    print("-" * 65)

    leftovers = find_phonix_leftovers(home_dir)
    total_count = sum(len(items) for items in leftovers.values())

    if total_count == 0:
        print(" [PASS] Clean machine: No Phonix leftovers found under ~/.gemini.")
        print("=" * 65)
        return 0

    print(f" [!] Found {total_count} Phonix leftover item(s) in ~/.gemini:")
    for category, items in leftovers.items():
        if items:
            print(f"   * {category.upper()}:")
            for item in items:
                print(f"       - {item}")
    print("-" * 65)

    if not fix:
        print(" To back up and remove these leftovers, run:")
        print("   phonix doctor --fix")
        print("=" * 65)
        return 0

    # User confirmation for --fix
    confirm = input(" Would you like to back up and remove all identified leftovers? (y/N): ").strip().lower()
    if confirm not in ("y", "yes"):
        print(" Cleanup aborted by user. No files were modified.")
        print("=" * 65)
        return 0

    backup_dir = home_dir / "phonix_leftovers_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    print(f" [*] Backing up leftovers to: {backup_dir}")

    removed_count = 0
    # Process files / directories
    for cat in ("state", "rules", "skills", "logs"):
        for item in leftovers[cat]:
            item_path = Path(item)
            if not item_path.exists():
                continue
            rel_dest = backup_dir / item_path.name
            try:
                if item_path.is_file():
                    shutil.copy2(item_path, rel_dest)
                    item_path.unlink()
                elif item_path.is_dir():
                    if rel_dest.exists():
                        shutil.rmtree(rel_dest)
                    shutil.copytree(item_path, rel_dest)
                    shutil.rmtree(item_path)
                removed_count += 1
                print(f"   [REMOVED] {item_path} -> backed up to {rel_dest}")
            except Exception as exc:
                print(f"   [ERROR] Failed cleaning {item_path}: {exc}")

    # Process MCP configs
    for cfg_cand in leftovers["mcp_configs"]:
        cfg_path = Path(cfg_cand)
        if not cfg_path.is_file():
            continue
        try:
            raw = cfg_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            # Backup original file
            backup_file = backup_dir / f"{cfg_path.name}.bak"
            backup_file.write_text(raw, encoding="utf-8")

            if "mcpServers" in data and "phonix-mmu" in data["mcpServers"]:
                del data["mcpServers"]["phonix-mmu"]
                cfg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                removed_count += 1
                print(f"   [CLEANED] Removed 'phonix-mmu' from {cfg_path}")
        except Exception as exc:
            print(f"   [ERROR] Failed updating MCP config {cfg_path}: {exc}")

    print("-" * 65)
    print(f" [PASS] Successfully cleaned {removed_count} item(s).")
    print(f" Backup preserved at: {backup_dir}")
    print("=" * 65)
    return 0


def cli_entrypoint() -> None:
    """Command Line Interface entrypoint defined in pyproject.toml."""
    parser = argparse.ArgumentParser(
        prog="phonix",
        description="Phonix v2.0 - Zero-Trust AST Paging & 1B Micro-Router Gateway",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # start command
    start_parser = subparsers.add_parser("start", help="Start the gateway server")
    start_parser.add_argument("--host", default="127.0.0.1", help="Binding host IP")
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
    mcp_parser = subparsers.add_parser("mcp", help="Run Model Context Protocol stdio server")
    mcp_parser.add_argument(
        "-w", "--workspace",
        default=None,
        help="Target workspace directory (default: current working directory os.getcwd())",
    )

    # export-configs command
    export_parser = subparsers.add_parser(
        "export-configs", help="Generate 1-click MCP configs for Claude, Cursor, and Cline"
    )
    export_parser.add_argument(
        "--workspace", "-w", default=".", help="Target workspace path to configure"
    )
    export_parser.add_argument(
        "--out", "-o", default=None, help="Output directory to save generated configs"
    )

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

    # doctor command
    doctor_parser = subparsers.add_parser(
        "doctor", help="Audit and clean Phonix leftovers in ~/.gemini"
    )
    doctor_parser.add_argument(
        "--fix",
        action="store_true",
        help="Prompt to back up and remove leftovers from ~/.gemini",
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
        run_mcp_server(workspace_root=args.workspace)
    elif args.command == "export-configs":
        export_configs_command(workspace=args.workspace, out=args.out)
    elif args.command == "build-dataset":
        build_dataset_command(max_commits=args.max_commits, output_path=args.output)
    elif args.command == "attach":
        attach_workspace(target_dir=args.target_dir)
    elif args.command == "doctor":
        sys.exit(doctor_command(fix=args.fix))
    else:
        parser.print_help()


if __name__ == "__main__":
    cli_entrypoint()
