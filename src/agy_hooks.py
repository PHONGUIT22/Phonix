"""Antigravity CLI (`agy`) Lifecycle Hooks for Phonix v2.0.

Provides deterministic runtime guardrails for coding agents:
1. SessionStart hook: Injects Context MMU symbol map into agent context via injectSteps.
2. PreToolUse hook: Intercepts `read_file`, `view_file`, and `run_command` tool calls,
   blocking reads to sensitive files (.env, *.pem, credentials) and exfiltration commands.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
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


def _notify_gateway(tool_name: str, args: dict[str, Any], decision: str, reason: str = "") -> None:
    """Fires a non-blocking notification to live Phonix HTTP daemon (http://127.0.0.1:8000)."""
    try:
        import httpx

        gw_url = os.environ.get("PHONIX_GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
        payload = {
            "text": f"PreToolUse intercept: tool='{tool_name}', decision='{decision}', reason='{reason}'",
            "role": "developer",
            "department": "engineering",
            "tool_name": tool_name,
            "tool_args": args,
            "decision": decision,
        }
        with httpx.Client(timeout=1.0) as client:
            client.post(f"{gw_url}/v1/z3/verify", json=payload)
    except Exception:
        pass


def _get_circuit_state_path() -> Path:
    env_p = os.environ.get("PHONIX_CIRCUIT_STATE_PATH")
    if env_p:
        return Path(env_p)
    return Path.home() / ".gemini" / "phonix_circuit_state.json"


def _load_circuit_state() -> dict[str, Any]:
    path = _get_circuit_state_path()
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {
        "turn_count": 0,
        "last_call_timestamp": 0.0,
        "last_tool_name": "",
        "last_tool_args_hash": "",
        "consecutive_same_tool_count": 0,
    }


def _save_circuit_state(state: dict[str, Any]) -> None:
    path = _get_circuit_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def handle_pre_tool_use() -> int:
    """Evaluates tool invocation against Zero-Trust policies and stateful Circuit Breaker.

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

    # Stateful Circuit Breaker Tracking
    state = _load_circuit_state()
    now = time.time()
    last_call_ts = float(state.get("last_call_timestamp", 0.0))
    turn_count = int(state.get("turn_count", 0))
    consecutive_count = int(state.get("consecutive_same_tool_count", 0))
    last_tool = str(state.get("last_tool_name", ""))

    current_args_hash = hashlib.sha256(json.dumps(args, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    if (now - last_call_ts) > 45.0:
        turn_count = 1
        consecutive_count = 1
    else:
        turn_count += 1
        if tool_name == last_tool:
            consecutive_count += 1
        else:
            consecutive_count = 1

    updated_state = {
        "turn_count": turn_count,
        "last_call_timestamp": now,
        "last_tool_name": tool_name,
        "last_tool_args_hash": current_args_hash,
        "consecutive_same_tool_count": consecutive_count,
    }
    _save_circuit_state(updated_state)

    # Rule 1 (Anti-Polling Lock)
    if (
        tool_name in ("ManageTask", "manage_task")
        and (args.get("Action") in ("status", "list") or args.get("action") in ("status", "list"))
        and consecutive_count >= 2
    ):
        response = {
            "decision": "deny",
            "reason": "[Phonix Circuit Breaker] Anti-Polling Lock Tripped! Consecutive ManageTask polling is blocked.",
        }
        _notify_gateway(tool_name, args, "deny", response["reason"])
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        return 0

    if tool_name in ("run_command", "Bash", "bash", "execute_command"):
        cmd = args.get("CommandLine") or args.get("command") or args.get("cmd") or ""
        if re.search(r"(?i)(?:Start-Sleep|while\s+true|\bsleep\s+\d+)", cmd):
            response = {
                "decision": "deny",
                "reason": "[Phonix Circuit Breaker] Shell sleep loops are strictly forbidden.",
            }
            _notify_gateway(tool_name, args, "deny", response["reason"])
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            return 0

    # Rule 2 (Turn Budget Circuit Breaker)
    if turn_count > 15:
        response = {
            "decision": "deny",
            "reason": "[Phonix Circuit Breaker Tripped] Task Turn Budget Exceeded (15 consecutive tool turns)! Summarize and report to user.",
        }
        _notify_gateway(tool_name, args, "deny", response["reason"])
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        return 0

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
                _notify_gateway(tool_name, args, "deny", response["reason"])
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                return 0

        # Rule 1b: Technical Hard-Block for source code files
        code_exts = {
            ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java",
            ".cpp", ".c", ".h", ".hpp", ".cs", ".php", ".rb", ".swift", ".kt"
        }
        clean_p = target_path.strip().strip("'\"")
        if clean_p.startswith("file:///"):
            clean_p = clean_p[8:]
        elif clean_p.startswith("file://"):
            clean_p = clean_p[7:]
        p = Path(clean_p)

        # Check if code file: Immediately Hard-Block direct reads regardless of line span
        if (
            p.suffix.lower() in code_exts
            and os.environ.get("PHONIX_ALLOW_DIRECT_READ") != "1"
            and os.environ.get("PHONIX_ALLOW_FULL_READ") != "1"
        ):
            response = {
                "decision": "deny",
                "reason": (
                    f"[Phonix Hard-Block] Direct 'read_file' on source code files ({p.suffix}) is strictly disabled to prevent token loop inflation. "
                    f"You MUST call MCP tool 'phonix_get_pruned_context(query=\"{p.name}\")' to inspect this file, "
                    f"or use 'phonix_surgical_edit' to apply modifications."
                ),
            }
            _notify_gateway(tool_name, args, "deny", response["reason"])
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            return 0

        # For non-code files (.json, .md, .txt, .yaml, .yml, .toml, .lock, .csv): allow bounded reads (<= 120 lines)
        start_line = args.get("StartLine") if args.get("StartLine") is not None else args.get("start_line")
        if start_line is None:
            start_line = args.get("startLine")
        end_line = args.get("EndLine") if args.get("EndLine") is not None else args.get("end_line")
        if end_line is None:
            end_line = args.get("endLine")

        bounded_ok = False
        if start_line is not None and end_line is not None:
            try:
                s = int(start_line)
                e = int(end_line)
                span = abs(e - s)
                if span <= 120:
                    bounded_ok = True
                else:
                    response = {
                        "decision": "deny",
                        "reason": (
                            f"[Phonix Quota Gate] Bounded read range ({span} lines) of '{target_path}' exceeds 120 lines. "
                            f"Specify a smaller range (<= 100 lines)!"
                        ),
                    }
                    _notify_gateway(tool_name, args, "deny", response["reason"])
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
                    return 0
            except (ValueError, TypeError):
                bounded_ok = False

        if not bounded_ok and os.environ.get("PHONIX_ALLOW_FULL_READ") != "1" and os.environ.get("PHONIX_ALLOW_DIRECT_READ") != "1":
            if p.is_file():
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        line_count = sum(1 for _ in f)
                except Exception:
                    line_count = 0

                if line_count > 120:
                    response = {
                        "decision": "deny",
                        "reason": (
                            f"[Phonix Quota Gate] Full-file read of '{target_path}' ({line_count} lines) blocked to protect Quota. "
                            f"Specify StartLine/EndLine (<= 100 lines)!"
                        ),
                    }
                    _notify_gateway(tool_name, args, "deny", response["reason"])
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
                _notify_gateway(tool_name, args, "deny", response["reason"])
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                return 0

    # Allow benign or verified operations
    _notify_gateway(tool_name, args, "allow", "Verified operation allowed.")
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
