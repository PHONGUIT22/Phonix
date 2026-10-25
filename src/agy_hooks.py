"""Antigravity CLI (`agy`) Lifecycle Hooks for Phonix v2.0.

Provides deterministic runtime guardrails for coding agents:
1. SessionStart hook: Injects Context MMU symbol map into agent context via injectSteps.
2. PreToolUse hook: Intercepts `read_file`, `view_file`, and `run_command` tool calls,
   blocking reads to sensitive files (.env, *.pem, credentials) and exfiltration commands.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any

# Sensitive file patterns for read_file / view_file
SENSITIVE_FILE_PATTERNS = [
    r"(?i)(?:^|[\\/])\.env(?:\..*)?$",
    r"(?i)(?:^|[\\/])\.env\.(?:local|production|staging|test|development)$",
    r"(?i)(?:^|[\\/]).*\.(?:pem|key|pfx|p12|keystore)$",
    r"(?i)(?:^|[\\/])id_(?:rsa|ed25519|dsa|ecdsa)(?:\..*)?$",
    r"(?i)(?:^|[\\/]).*(?:credentials|secrets|password).*\.(?:json|yaml|yml|txt|conf)$",
    r"(?i)(?:^|[\\/])credentials\.json$",
]

# Exfiltration and dangerous command patterns for run_command
MALICIOUS_COMMAND_PATTERNS = [
    r"(?i)\bcurl\b.*(?:pastebin|webhook\.site|ngrok|transfer\.sh|requestbin)",
    r"(?i)\bcurl\b.*-[dF]\s*@.*(?:\.env|id_rsa|\.key|\.pem)",
    r"(?i)\bwget\b.*--post-file.*(?:\.env|id_rsa|\.key|\.pem)",
    r"(?i)\bgcloud\s+projects\s+delete\b",
    r"(?i)\brm\s+-(?:rf|fr)\s+(?:/|\*|c:[\\/])",
    r"(?i)\bcat\s+~[\\/]\.ssh[\\/]",
    r"(?i)\b(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    r"\bsk_live_[a-zA-Z0-9_\-]{16,64}\b",
]


def handle_session_start(workspace_root: str = ".") -> int:
    """Executes SessionStart lifecycle hook.

    Reads JSON on stdin if available, indexes the workspace using GatewayCore,
    and outputs the exact Antigravity injectSteps contract:
    {
      "injectSteps": [
        {
          "systemMessage": {
            "systemMessage": "[Phonix v2.0 Context MMU Active] To save token quota, prefer MCP tool `phonix_get_pruned_context` over reading full files. Indexed Repository Symbol Map:\n<compact_repo_map>"
          }
        }
      ]
    }
    """
    try:
        from src.gateway.proxy_server import GatewayCore

        if workspace_root == "." and os.path.basename(os.getcwd()) in (".agents", ".agent"):
            workspace_root = str(Path(os.getcwd()).parent)

        core = GatewayCore(workspace_root=workspace_root, auto_index=True)
        cached_map = core.kv_prefix_cache.get_prefix("repo_symbol_map")
        map_text = cached_map.text if cached_map else "No symbol map available."

        system_message_text = (
            "[Phonix v2.0 Context MMU Active] To save token quota, prefer MCP tool "
            "`phonix_get_pruned_context` over reading full files. Indexed Repository Symbol Map:\n"
            f"{map_text}"
        )

        output = {
            "injectSteps": [
                {
                    "systemMessage": {
                        "systemMessage": system_message_text
                    }
                }
            ]
        }
        sys.stdout.write(json.dumps(output) + "\n")
        sys.stdout.flush()
        return 0
    except Exception as exc:
        fallback_output = {
            "injectSteps": [
                {
                    "systemMessage": {
                        "systemMessage": (
                            "[Phonix v2.0 Context MMU Active] Prefer MCP tool `phonix_get_pruned_context` "
                            f"over reading full files. (MMU offline fallback: {exc})"
                        )
                    }
                }
            ]
        }
        sys.stdout.write(json.dumps(fallback_output) + "\n")
        sys.stdout.flush()
        return 0


def handle_pre_tool_use() -> int:
    """Evaluates tool invocation against Zero-Trust policies.

    Reads JSON on stdin:
    {
        "toolCall": {
            "name": "read_file",
            "args": {"Path": "..."}
        }
    }
    Outputs JSON on stdout:
    {
        "decision": "allow" | "deny",
        "reason": "..."
    }
    """
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        sys.stdout.flush()
        return 0

    try:
        data = json.loads(raw_input)
    except Exception:
        sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        sys.stdout.flush()
        return 0

    tool_call = data.get("toolCall", {})
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {})

    # Rule 1: Guard sensitive credential files against read_file / view_file
    if tool_name in ("read_file", "view_file", "read_file_lines"):
        target_path = args.get("Path") or args.get("path") or args.get("file_path") or ""
        norm_path = target_path.replace("\\", "/")

        for pat in SENSITIVE_FILE_PATTERNS:
            if re.search(pat, norm_path):
                response = {
                    "decision": "deny",
                    "reason": "[Phonix Zero-Trust Gate] Direct access to sensitive credential file is blocked by policy.",
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                return 0

    # Rule 2: Guard dangerous exfiltration and destructive commands against run_command
    if tool_name in ("run_command", "bash", "execute_command"):
        cmd = args.get("CommandLine") or args.get("command") or args.get("cmd") or ""

        for pat in MALICIOUS_COMMAND_PATTERNS:
            if re.search(pat, cmd):
                response = {
                    "decision": "deny",
                    "reason": "[Phonix Zero-Trust Gate] Command blocked: detected potential secret exposure or unsafe command.",
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                return 0

    # Allow benign or verified operations
    sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
    sys.stdout.flush()
    return 0


def main() -> int:
    """CLI dispatcher for Antigravity hooks."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.agy_hooks [session-start|pre-tool-use]")
        return 1

    action = sys.argv[1].lower()
    if action in ("session-start", "session_start"):
        ws = sys.argv[2] if len(sys.argv) > 2 else "."
        return handle_session_start(ws)
    elif action in ("pre-tool-use", "pre_tool_use"):
        return handle_pre_tool_use()
    else:
        print(f"Unknown action: {action}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
