"""Model Context Protocol (MCP) Stdio Server for Phonix v2.0.

Exposes Phonix Context MMU and Zero-Trust Guardrails to Antigravity CLI (`agy`)
and Claude Code over JSON-RPC 2.0 over standard I/O (stdio).
Saves developer quotas (Five Hour Limit & Weekly Limit) by serving compact,
pruned, sanitized < 512 token AST frames instead of reading full files.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import sys
from typing import Any

from src.gateway.policy_engine import PolicyRequest
from src.gateway.proxy_server import GatewayCore, _ensure_phonix_hp_rule

logger = logging.getLogger("phonix.mcp")


class PhonixMCPServer:
    """Stdio-based JSON-RPC 2.0 Model Context Protocol Server."""

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, workspace_root: str | None = None) -> None:
        if workspace_root is None:
            env_root = os.environ.get("PHONIX_WORKSPACE")
            if env_root and os.path.isdir(env_root):
                workspace_root = env_root
            elif os.getcwd() and os.path.isdir(os.getcwd()):
                workspace_root = os.getcwd()
            else:
                workspace_root = str(Path(__file__).resolve().parent.parent)
        self.workspace_root = str(Path(workspace_root).resolve())
        _ensure_phonix_hp_rule(self.workspace_root)
        self.core = GatewayCore(workspace_root=self.workspace_root, auto_index=True)

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Returns the 3 primary MCP tools exposed to coding CLI agents."""
        return [
            {
                "name": "phonix_repo_map",
                "description": (
                    "Returns a compact AST Symbol Map of the repository (files, functions/classes, "
                    "line ranges, token counts). Use this first instead of scanning multiple files to save token quota."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path_prefix": {
                            "type": "string",
                            "description": "Optional directory prefix filter (e.g. 'src/gateway')",
                        }
                    },
                },
            },
            {
                "name": "phonix_get_pruned_context",
                "description": (
                    "Retrieves pruned, 1-hop/2-hop call-graph expanded, and Zero-Trust sanitized "
                    "AST frames (< 512 tokens/frame) for a coding task or file path. "
                    "Saves 75-85% context quota compared to reading full files."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Task description, symbol name, or file path",
                        },
                        "max_tokens": {
                            "type": "integer",
                            "description": "Maximum token budget for returned AST context (default: 1536)",
                            "default": 1536,
                        },
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "phonix_verify_zero_trust",
                "description": (
                    "Sanitizes sensitive literals (API keys, secrets, JWTs, internal IPs) into <REDACTED_...> "
                    "placeholders and formally verifies Zero-Trust compliance via Z3 SMT solver."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Code snippet or text to sanitize and verify",
                        },
                        "role": {
                            "type": "string",
                            "description": "Caller RBAC role (admin, engineer, contractor, auditor)",
                            "default": "engineer",
                        },
                        "department": {
                            "type": "string",
                            "description": "Department name for quota verification",
                            "default": "engineering",
                        },
                    },
                    "required": ["text"],
                },
            },
        ]

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        """Processes a single JSON-RPC 2.0 message."""
        method = req.get("method", "")
        req_id = req.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "phonix-mmu", "version": "2.0.0"},
                },
            }

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.get_tool_definitions()},
            }

        if method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            return self._dispatch_tool_call(req_id, tool_name, args)

        if req_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not found"},
            }
        return None

    def _dispatch_tool_call(
        self, req_id: Any, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatches an MCP tool call to the appropriate Phonix subsystem."""
        try:
            # 1. phonix_repo_map
            if tool_name == "phonix_repo_map":
                path_prefix = args.get("path_prefix", "").strip()
                cached = self.core.kv_prefix_cache.get_prefix("repo_symbol_map")
                raw_map = cached.text if cached else ""

                if path_prefix and raw_map:
                    filtered_lines = [
                        line for line in raw_map.splitlines()
                        if line.startswith(path_prefix) or path_prefix in line
                    ]
                    map_text = "\n".join(filtered_lines) if filtered_lines else f"# No files matched prefix '{path_prefix}'"
                else:
                    map_text = raw_map or "# Repository symbol map is empty."

                formatted_result = (
                    f"=== Phonix Context MMU Repository Symbol Map ===\n"
                    f"Indexed Files: {self.core.file_trie.total_files} | Registered Frames: {len(self.core._frame_registry)}\n"
                    f"Tip: Call 'phonix_get_pruned_context' for specific functions or classes to save token quota.\n\n"
                    f"{map_text}"
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": formatted_result}], "isError": False},
                }

            # 2. phonix_get_pruned_context (aliased from phonix_page_context)
            elif tool_name in ("phonix_get_pruned_context", "phonix_page_context"):
                query = args.get("query", "")
                max_tokens = int(args.get("max_tokens", 1536))

                # Step A: Speculative Trie matching for file paths
                self.core.speculative_inspector.reset_stream()
                inspection = self.core.speculative_inspector.process_chunk(query)

                candidate_files = list(inspection.candidate_files)
                for arg_file in args.get("target_files", []):
                    if arg_file not in candidate_files:
                        candidate_files.append(arg_file)

                # Step B: Gather candidate frames from matched files AND symbol/keyword search
                frames = []
                seen_ids: set[str] = set()
                for file_path in candidate_files:
                    f_list = self.core._file_to_frames.get(file_path, [])
                    if not f_list:
                        f_list = self.core.ast_slicer.slice_file(file_path)
                    for f in f_list:
                        if f.frame_id not in seen_ids:
                            frames.append(f)
                            seen_ids.add(f.frame_id)

                # Also match symbols or keywords across the workspace registry if query mentions symbols
                query_lower = query.lower()
                for f in self.core._frame_registry.values():
                    if f.frame_id in seen_ids:
                        continue
                    if (
                        (f.symbol_name and len(f.symbol_name) >= 3 and f.symbol_name.lower() in query_lower)
                        or (f.file_path and f.file_path.lower() in query_lower)
                    ):
                        frames.append(f)
                        seen_ids.add(f.frame_id)

                # If still empty, run smart Micro-Router relevance scoring across all indexed frames
                if not frames and self.core._frame_registry:
                    all_frames = list(self.core._frame_registry.values())
                    router_res = self.core.micro_router.route_and_prune(
                        user_prompt=query, candidate_frames=all_frames
                    )
                    sel_set = set(router_res.selected_ast_frames)
                    frames = [f for f in all_frames if f.frame_id in sel_set]

                # Step C: Call-graph BFS expansion (1-hop / 2-hop)
                seed_symbols = [f.symbol_name for f in frames[:5]]
                if seed_symbols:
                    paged_frames = self.core.call_graph_pager.page_graph(
                        seed_symbols, max_hops=2, max_token_budget=max_tokens
                    )
                    paged_ids = {f.frame_id for f in paged_frames}
                    for f in frames:
                        if f.frame_id not in paged_ids:
                            paged_frames.append(f)
                            paged_ids.add(f.frame_id)
                else:
                    paged_frames = frames[:6]

                # Step D: Micro-Router GBNF Pruning + MMU Eviction
                if paged_frames:
                    router_decision = self.core.micro_router.route_and_prune(
                        user_prompt=query, candidate_frames=paged_frames
                    )
                    sel_ids = set(router_decision.selected_ast_frames)
                    drop_ids = set(router_decision.drop_irrelevant_frames)
                    pruned = [
                        f for f in paged_frames
                        if (f.frame_id in sel_ids or not sel_ids) and f.frame_id not in drop_ids
                    ]
                    if pruned:
                        paged_frames = pruned

                eviction_res = self.core.frame_evictor.evict(paged_frames, token_budget=max_tokens)
                retained_frames = eviction_res.retained_frames

                # Optional Proprietary Moat Enhancement (private_moat)
                moat_header = ""
                try:
                    from private_moat.behavioral_hotspot_engine import BehavioralHotspotEngine
                    from private_moat.foveated_ast_compactor import FoveatedASTCompactor

                    hotspot_eng = BehavioralHotspotEngine(workspace_root=self.core.workspace_root)
                    retained_frames = hotspot_eng.rerank_and_expand_frames(
                        user_prompt=query,
                        candidate_frames=retained_frames,
                    )
                    compactor = FoveatedASTCompactor(top_k_focal=1)
                    retained_frames, _, _ = compactor.compact_frames(
                        frames=retained_frames,
                        user_prompt=query,
                    )
                    moat_header = " [Phonix Pro Foveated]"
                except (ImportError, Exception):
                    moat_header = ""

                # Step E: Zero-Trust AST Sanitization
                rendered_blocks = []
                total_tokens = 0
                for f in retained_frames:
                    san = self.core.sanitizer.sanitize(f.raw_code)
                    total_tokens += f.token_count
                    rendered_blocks.append(
                        f"=== AST Frame: {f.frame_id} (Symbol: {f.symbol_name}, File: {f.file_path}, "
                        f"Lines {f.start_line}-{f.end_line}, {f.token_count} tokens) ===\n"
                        f"{san.sanitized_text}\n"
                    )

                if not rendered_blocks:
                    content_text = f"No AST frames matched query '{query}'. Candidate files checked: {candidate_files}"
                else:
                    content_text = (
                        f"Phonix Context MMU{moat_header}: Paged & Pruned {len(retained_frames)} AST frames ({total_tokens} tokens / budget {max_tokens}):\n\n"
                        + "\n".join(rendered_blocks)
                    )

                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": content_text}], "isError": False},
                }

            # 3. phonix_verify_zero_trust (aliased from phonix_verify_safety)
            elif tool_name in ("phonix_verify_zero_trust", "phonix_verify_safety"):
                text_to_verify = args.get("text") or args.get("text_or_code") or ""
                role = args.get("role") or args.get("user_role") or "engineer"
                department = args.get("department", "engineering")
                target_upstream = args.get("target_upstream", "anthropic")

                san = self.core.sanitizer.sanitize(text_to_verify)
                req = PolicyRequest(
                    user_id="mcp-agent",
                    role=role,
                    department=department,
                    target_upstream=target_upstream,
                    estimated_tokens=len(text_to_verify) // 4,
                    unredacted_secrets_count=0,
                )
                decision = self.core.policy_engine.evaluate(req)

                redacted_details = [
                    f"- {r.category} -> {r.placeholder} (len: {len(r.original_value)})"
                    for r in san.redactions
                ]
                details_str = "\n".join(redacted_details) if redacted_details else "None (Clean)"

                summary_text = (
                    f"=== Phonix Zero-Trust Safety Verification ===\n"
                    f"Decision: {'ALLOWED' if decision.is_allowed else 'BLOCKED'}\n"
                    f"Z3 Proof Status: {decision.z3_proof_status}\n"
                    f"Reason: {decision.reason}\n"
                    f"Enforced Upstream: {decision.enforced_upstream}\n"
                    f"Detected Sensitive Literals ({san.redaction_count}):\n{details_str}\n\n"
                    f"[Sanitized Text Preview]\n{san.sanitized_text[:500]}"
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": summary_text}], "isError": False},
                }

            # Optional compatibility helper: phonix_inspect_symbol
            elif tool_name == "phonix_inspect_symbol":
                symbol_name = args.get("symbol_name", "")
                frames = self.core.call_graph_pager.get_symbol_frames(symbol_name)
                if not frames:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Symbol '{symbol_name}' not found."}],
                            "isError": True,
                        },
                    }
                frame = frames[0]
                callers = list(self.core.call_graph_pager._adjacency_in.get(symbol_name, set()))
                callees = list(self.core.call_graph_pager._adjacency_out.get(symbol_name, set()))
                san = self.core.sanitizer.sanitize(frame.raw_code)
                result_text = (
                    f"=== Symbol: {symbol_name} ===\n"
                    f"File: {frame.file_path}\n"
                    f"Frame ID: {frame.frame_id}\n"
                    f"Tokens: {frame.token_count}\n"
                    f"Callers: {', '.join(sorted(callers)) or 'none'}\n"
                    f"Callees: {', '.join(sorted(callees)) or 'none'}\n\n"
                    f"[Sanitized AST Code Frame]\n{san.sanitized_text}"
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": result_text}], "isError": False},
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Unknown tool: '{tool_name}'"}],
                        "isError": True,
                    },
                }

        except Exception as exc:
            logger.error("Error executing tool %s: %s", tool_name, exc, exc_info=True)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": f"Tool error: {str(exc)}"}], "isError": True},
            }

    def run_stdio(self) -> None:
        """Runs the JSON-RPC 2.0 loop reading from stdin and writing to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(exc)}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    server = PhonixMCPServer()
    server.run_stdio()
