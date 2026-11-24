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
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse

from src.gateway.policy_engine import PolicyRequest
from src.gateway.proxy_server import GatewayCore, _resolve_within
from src.mmu.output_compactor import run_and_compact

logger = logging.getLogger("phonix.mcp")

_RG_BIN: str | None = shutil.which("rg")

STRICT_EXCLUDED_DIRS: set[str] = {
    "node_modules",
    ".next",
    ".git",
    "dist",
    "build",
    "coverage",
    ".cache",
    "rawdata",
}


class PhonixMCPServer:
    """Stdio-based JSON-RPC 2.0 Model Context Protocol Server."""

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(
        self,
        workspace_root: str | None = None,
        core: GatewayCore | None = None,
        in_http_daemon: bool = False,
    ) -> None:
        self._in_http_daemon = in_http_daemon
        if core is not None:
            self.core = core
            self.workspace_root = str(Path(core.workspace_root).resolve())
        else:
            if workspace_root is None:
                env_root = os.environ.get("PHONIX_WORKSPACE")
                if env_root and os.path.isdir(env_root):
                    workspace_root = env_root
                elif os.getcwd() and os.path.isdir(os.getcwd()):
                    workspace_root = os.getcwd()
                else:
                    workspace_root = str(Path(__file__).resolve().parent.parent)
            self.workspace_root = str(Path(workspace_root).resolve())
            self.core = GatewayCore(workspace_root=self.workspace_root, auto_index=True)
        self._workspace_cores: dict[str, GatewayCore] = {
            os.path.abspath(self.workspace_root): self.core
        }
        self._committed_fovea_files: set[str] = set()
        self._session_vault: dict[str, str] = {}
        self._gateway_down_until: float = 0.0

    def _try_http_gateway(self, endpoint: str, payload: dict[str, Any]) -> str | None:
        """Attempts to forward tool call to live Phonix HTTP Gateway daemon (http://127.0.0.1:8000)."""
        if self._in_http_daemon:
            return None
        env_url = os.environ.get("PHONIX_GATEWAY_URL")
        if not env_url and time.monotonic() < self._gateway_down_until:
            return None

        gw_url = (env_url or "http://127.0.0.1:8000").rstrip("/")
        parsed = urlparse(gw_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # Fast 8ms TCP port check avoids importing httpx (~270ms) when daemon is offline
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.008)
            if sock.connect_ex((host, port)) != 0:
                if not env_url:
                    self._gateway_down_until = time.monotonic() + 30.0
                return None
        except OSError:
            if not env_url:
                self._gateway_down_until = time.monotonic() + 30.0
            return None
        finally:
            sock.close()

        try:
            import httpx

            with httpx.Client(timeout=2.5) as client:
                resp = client.post(f"{gw_url}{endpoint}", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and "result" in data:
                        return str(data["result"])
        except Exception as exc:
            logger.debug(
                "Phonix HTTP Gateway at %s unavailable (%s). Falling back to local MMU.",
                endpoint,
                exc,
            )
        return None

    def _get_or_create_core(self, ws_path: str) -> GatewayCore:
        norm = os.path.abspath(ws_path)
        if norm not in self._workspace_cores:
            self._workspace_cores[norm] = GatewayCore(workspace_root=norm, auto_index=True)
        return self._workspace_cores[norm]

    def _resolve_active_core(
        self, query: str = "", explicit_workspace: str | None = None
    ) -> GatewayCore:
        """Resolves workspace GatewayCore strictly: explicit_workspace -> PHONIX_WORKSPACE -> self.workspace_root.

        Parent-directory sibling scanning is disabled by default to prevent cross-repo
        latency and context leaks; set PHONIX_ALLOW_SIBLING_SCAN=1 to opt in.
        """
        if explicit_workspace:
            return self._get_or_create_core(explicit_workspace)

        env_ws = os.environ.get("PHONIX_WORKSPACE")
        if env_ws and os.path.isdir(env_ws):
            current_core = self._get_or_create_core(os.path.abspath(env_ws))
        else:
            current_core = self.core

        if not query or os.environ.get("PHONIX_ALLOW_SIBLING_SCAN") != "1":
            return current_core

        # Opt-in sibling lookup (only when PHONIX_ALLOW_SIBLING_SCAN=1)
        query_lower = query.lower()
        for fpath in current_core._file_to_frames.keys():
            if fpath.lower() in query_lower or os.path.basename(fpath).lower() in query_lower:
                return current_core

        for sym in getattr(current_core.call_graph_pager, "_symbol_to_frames", {}).keys():
            if len(sym) >= 3 and sym.lower() in query_lower:
                return current_core

        repo_root = Path(__file__).resolve().parent.parent
        siblings_container = repo_root.parent

        if siblings_container.is_dir():
            sub_queries = [q.strip() for q in query.split("|") if q.strip()]
            tokens = set(re.findall(r"[a-zA-Z0-9_\-\.]+", query_lower))

            GENERIC_TOKENS = {
                "src", "app", "lib", "test", "tests", "page", "index", "route",
                "layout", "main", "types", "data", "components", "api", "public",
                "default", "styles", "style", "utils", "config", "constants", "tsx", "ts", "js", "jsx"
            }

            try:
                scores: dict[str, int] = {}
                for sibling in siblings_container.iterdir():
                    if not sibling.is_dir() or sibling.name.startswith("."):
                        continue
                    if not (
                        (sibling / ".git").is_dir()
                        or (sibling / "src").is_dir()
                        or (sibling / "package.json").is_file()
                    ):
                        continue

                    score = 0
                    sib_name_lower = sibling.name.lower()
                    if sib_name_lower in query_lower:
                        score += 250
                    elif any(t in sib_name_lower for t in tokens if len(t) >= 5 and t not in GENERIC_TOKENS):
                        score += 150

                    for q in sub_queries:
                        clean_q = q.strip().replace("\\", "/").strip("/'\"")
                        if (sibling / clean_q).is_file():
                            score += 500
                        if len(q) >= 6 and ("-" in q or "_" in q):
                            for sub in ("src/lib", "src", "app", "lib"):
                                sdir = sibling / sub
                                if sdir.is_dir():
                                    for f in sdir.glob("*.ts"):
                                        try:
                                            if q in f.read_text(encoding="utf-8", errors="ignore"):
                                                score += 300
                                                break
                                        except Exception:
                                            pass

                    for sub in ("src", "app", "lib"):
                        search_dir = sibling / sub
                        if not search_dir.is_dir():
                            continue
                        for root, dirs, files in os.walk(search_dir):
                            dirs[:] = [
                                d for d in dirs
                                if d not in GatewayCore.IGNORED_DIRS
                                and d not in STRICT_EXCLUDED_DIRS
                                and not d.startswith(".")
                            ]
                            for fname in files:
                                fname_lower = fname.lower()
                                base_lower = os.path.splitext(fname_lower)[0]
                                if base_lower not in GENERIC_TOKENS:
                                    if fname_lower in tokens or base_lower in tokens:
                                        score += 80

                    if score > 0:
                        scores[str(sibling.resolve())] = score

                if scores:
                    best_sib = max(scores.items(), key=lambda x: x[1])[0]
                    logger.info(
                        "Smart Workspace Switch: Routing query '%s' to best sibling project %s (score=%d)",
                        query,
                        Path(best_sib).name,
                        scores[best_sib],
                    )
                    return self._get_or_create_core(best_sib)
            except Exception as e_scan:
                logger.debug("Sibling workspace scan error: %s", e_scan)

        return current_core

    @staticmethod
    def get_tool_definitions() -> list[dict[str, Any]]:
        """Returns the primary MCP tools exposed to coding CLI agents."""
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
                    "Retrieves pruned AST frames or verbatim [Lines X-Y] edit windows for one or more files, "
                    "data slugs, or text anchors separated by '|' (multi-query batching). "
                    "Use for_edit=True for verbatim copy-pasteable lines preserving exact whitespace."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Task description, symbol name, file path, or multiple targets separated by '|' (e.g. 'file.tsx | slug-name | anchorText')",
                        },
                        "max_tokens": {
                            "type": "integer",
                            "description": "Maximum token budget for returned AST context (default: 1400)",
                            "default": 1400,
                        },
                        "for_edit": {
                            "type": "boolean",
                            "description": "When true (default for edits/slugs), returns verbatim [Lines X-Y] windows with exact whitespace for direct edit_file/phonix_surgical_edit copy-paste.",
                            "default": True,
                        },
                        "detail": {
                            "type": "string",
                            "enum": ["minimal", "standard", "full"],
                            "description": "Output verbosity: 'minimal' (default for for_edit/colon ranges: 1-line header + verbatim code), 'standard' (per-file L0-L2 once + windows), or 'full'.",
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
            {
                "name": "phonix_surgical_edit",
                "description": (
                    "Apply one or more exact target->replacement edits to a file in a single step with "
                    "automatic Windows CRLF (\\r\\n) vs LF (\\n) line-ending normalization. "
                    "Prevents edit_file newline mismatch loops."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Relative or absolute path to the target file",
                        },
                        "edits": {
                            "type": "array",
                            "description": "List of exact replacements to apply sequentially",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "target": {
                                        "type": "string",
                                        "description": "Exact text or lines to be replaced",
                                    },
                                    "replacement": {
                                        "type": "string",
                                        "description": "Replacement text or lines",
                                    },
                                },
                                "required": ["target", "replacement"],
                            },
                        },
                    },
                    "required": ["file_path", "edits"],
                },
            },
            {
                "name": "phonix_symbol_impact",
                "description": (
                    "Returns definition location(s), callers (with file:line snippets), and callees "
                    "for a symbol in 1 compact response before refactoring."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "symbol": {
                            "type": "string",
                            "description": "Symbol name (function, class, or method) to analyze",
                        },
                        "max_tokens": {
                            "type": "integer",
                            "description": "Maximum token budget for impact report (default: 1024)",
                            "default": 1024,
                        },
                        "include_snippets": {
                            "type": "boolean",
                            "description": "Include 1-line call-site snippets for callers (default: true)",
                            "default": True,
                        },
                    },
                    "required": ["symbol"],
                },
            },
            {
                "name": "phonix_run_compact",
                "description": (
                    "Executes a workspace test, build, lint, or git diff command safely and compacts "
                    "verbose output while saving full logs to .phonix_runtime/last_cmd_output.log."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Shell command to execute inside workspace root",
                        },
                        "max_tokens": {
                            "type": "integer",
                            "description": "Maximum token budget for compacted output (default: 800)",
                            "default": 800,
                        },
                        "timeout_sec": {
                            "type": "integer",
                            "description": "Command execution timeout in seconds (default: 60)",
                            "default": 60,
                        },
                    },
                    "required": ["command"],
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

    def _tool_repo_map(
        self,
        path_prefix: str = "",
        max_tokens: int = 256,
        workspace_root: str | None = None,
    ) -> str:
        """Executes repository symbol map generation with optional HTTP daemon delegation."""
        remote = self._try_http_gateway(
            "/v1/mmu/repo-map",
            {
                "path_prefix": path_prefix,
                "max_tokens": max_tokens,
                "workspace_root": workspace_root or os.environ.get("PHONIX_WORKSPACE") or os.getcwd(),
            },
        )
        if remote is not None:
            return remote

        core = self._resolve_active_core(query=path_prefix, explicit_workspace=workspace_root)
        if core.file_trie.total_files == 0 and not core._frame_registry:
            core.index_workspace()
        cached = core.kv_prefix_cache.get_prefix("repo_symbol_map")
        raw_map = cached.text if cached else ""

        if path_prefix and raw_map:
            filtered_lines = [
                line for line in raw_map.splitlines()
                if line.startswith(path_prefix) or path_prefix in line
            ]
            map_text = "\n".join(filtered_lines) if filtered_lines else f"# No files matched prefix '{path_prefix}'"
        else:
            map_text = raw_map or "# Repository symbol map is empty."

        return (
            f"=== Phonix Context MMU Repository Symbol Map ===\n"
            f"Indexed Files: {core.file_trie.total_files} | Registered Frames: {len(core._frame_registry)}\n"
            f"Tip: Call 'phonix_get_pruned_context' for specific functions or classes to save token quota.\n\n"
            f"{map_text}"
        )

    def _format_window_with_gmmu(
        self,
        rel_path: str,
        snippet: str,
        all_content: str,
        line_range: tuple[int, int] | None = None,
    ) -> str:
        """Renders a verbatim window using proprietary G-MMU (L0 -> L3) if available, or standard verbatim."""
        norm_path = rel_path.replace("\\", "/")
        is_committed = (
            norm_path in self._committed_fovea_files
            or Path(norm_path).name in self._committed_fovea_files
        )
        try:
            from private_moat.foveated_ast_compactor import render_gmmu_stratified_bundle

            return render_gmmu_stratified_bundle(
                file_path=norm_path,
                target_snippet_or_lines=snippet,
                all_file_content=all_content,
                line_range=line_range,
                committed=is_committed,
            )
        except ImportError:
            from src.mmu.gmmu import render_gmmu_bundle

            s_line = line_range[0] if line_range else 1
            e_line = line_range[1] if line_range else len(all_content.splitlines())
            return render_gmmu_bundle(
                file_path=norm_path,
                all_content=all_content,
                start_line=s_line,
                end_line=e_line,
                target_snippet=snippet,
                committed=is_committed,
            )

    def _format_grouped_windows_with_gmmu(
        self,
        rel_path: str,
        windows: list[tuple[int, int, str]],
        all_content: str,
        detail: str = "minimal",
    ) -> str:
        """Renders grouped windows for a file using minimal or deduplicated L0-L3 G-MMU."""
        norm_path = rel_path.replace("\\", "/")
        is_committed = (
            norm_path in self._committed_fovea_files
            or Path(norm_path).name in self._committed_fovea_files
        )
        try:
            from private_moat.foveated_ast_compactor import render_gmmu_stratified_grouped_bundle

            return render_gmmu_stratified_grouped_bundle(
                file_path=norm_path,
                windows=windows,
                all_file_content=all_content,
                committed=is_committed,
                detail=detail,
            )
        except ImportError:
            from src.mmu.gmmu import render_gmmu_grouped_bundle

            grouped_input = [(s, e, snip) for s, e, snip in windows]
            return render_gmmu_grouped_bundle(
                file_path=norm_path,
                all_content=all_content,
                windows=grouped_input,
                committed=is_committed,
                detail=detail,
            )

    @staticmethod
    def _rg_find_files(sub_q: str, scan_dirs: list[Path], excluded_dirs: set[str]) -> list[Path] | None:
        """Uses cached ripgrep (`rg`) when available on PATH to locate files containing sub_q."""
        if not _RG_BIN or not scan_dirs:
            return None

        cmd = [_RG_BIN, "-l", "--fixed-strings", "--no-messages"]
        for d in sorted(excluded_dirs):
            cmd.extend(["-g", f"!{d}/**", "-g", f"!{d}"])
        cmd.extend(["-g", "!.*"])
        cmd.extend(["--", sub_q])
        cmd.extend(str(d) for d in scan_dirs)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            if proc.returncode in (0, 1):
                return [Path(p.strip()) for p in proc.stdout.splitlines() if p.strip()]
        except Exception:
            return None
        return None

    def _extract_verbatim_windows(
        self,
        core: GatewayCore,
        sub_queries: list[str],
        max_tokens: int = 1536,
        detail: str = "minimal",
    ) -> list[str]:
        """Extracts exact verbatim edit windows using incremental mtime cache + grouped G-MMU."""
        ws_path = Path(core.workspace_root).resolve()
        seen_regions: set[tuple[str, int, int]] = set()
        # Preserve file order and group extracted (s_idx, e_idx, snippet) windows per rel_path
        grouped_windows: dict[str, dict[str, Any]] = {}

        def _add_window(rel_path: str, all_content: str, s_idx: int, e_idx: int, snippet: str) -> None:
            region = (rel_path, s_idx, e_idx)
            if region in seen_regions:
                return
            seen_regions.add(region)
            bucket = grouped_windows.setdefault(
                rel_path, {"content": all_content, "windows": []}
            )
            bucket["content"] = all_content
            bucket["windows"].append((s_idx, e_idx, snippet))

        target_exts = (".ts", ".tsx", ".js", ".jsx", ".json", ".py", ".html", ".css", ".md")
        excluded_dirs = set(GatewayCore.IGNORED_DIRS) | set(STRICT_EXCLUDED_DIRS)
        cached_entries = core.refresh_file_index(
            extensions=target_exts,
            scan_subdirs=("src", "app", "lib"),
            extra_excluded_dirs=STRICT_EXCLUDED_DIRS,
        )
        scan_dirs = [ws_path / d for d in ("src", "app", "lib") if (ws_path / d).is_dir()]
        if not scan_dirs:
            scan_dirs = [ws_path]

        entries_by_name: dict[str, list[dict[str, Any]]] = {}
        for entry in cached_entries:
            entries_by_name.setdefault(Path(entry["rel_path"]).name.lower(), []).append(entry)

        for raw_q in sub_queries:
            sub_q = raw_q.strip()
            if not sub_q:
                continue

            # 1. Colon Line-Range Syntax: <file_path>:<start>-<end>
            colon_match = re.match(r"^(.+?):(\d+)-(\d+)$", sub_q)
            if colon_match:
                colon_file_part = colon_match.group(1).replace("\\", "/").strip("'\"")
                start_l = int(colon_match.group(2))
                end_l = int(colon_match.group(3))
                s_idx = min(start_l, end_l)
                e_idx = max(start_l, end_l)

                colon_entry: dict[str, Any] | None = None
                try:
                    resolved_colon = _resolve_within(ws_path, colon_file_part)
                    if resolved_colon.is_file():
                        colon_entry = core.get_cached_file(resolved_colon)
                except PermissionError:
                    colon_entry = None

                if colon_entry is None and not Path(colon_file_part).is_absolute() and ".." not in colon_file_part:
                    target_name = Path(colon_file_part).name.lower()
                    matched_list = entries_by_name.get(target_name, [])
                    if matched_list:
                        colon_entry = matched_list[0]

                if colon_entry is None and not Path(colon_file_part).is_absolute() and ".." not in colon_file_part:
                    try:
                        for cand in ws_path.rglob(f"*{Path(colon_file_part).name}"):
                            if (
                                cand.is_file()
                                and not any(p in cand.parts for p in excluded_dirs)
                            ):
                                colon_entry = core.get_cached_file(cand)
                                break
                    except Exception:
                        pass

                if colon_entry is not None:
                    rel_path = colon_entry["rel_path"]
                    content = colon_entry["content"]
                    all_lines = colon_entry["lines"]
                    total_lines = len(all_lines)
                    s_idx = max(1, s_idx)
                    e_idx = min(total_lines, e_idx)
                    slice_lines = all_lines[s_idx - 1 : e_idx]
                    _add_window(rel_path, content, s_idx, e_idx, "\n".join(slice_lines))
                    continue

            clean_q = sub_q.replace("\\", "/").strip("'\"")

            # Case A: Is clean_q a file path in workspace?
            file_entry: dict[str, Any] | None = None
            try:
                cand_resolved = _resolve_within(ws_path, clean_q)
                if cand_resolved.is_file():
                    file_entry = core.get_cached_file(cand_resolved)
            except PermissionError:
                file_entry = None

            if file_entry is None and " " not in clean_q and not Path(clean_q).is_absolute() and ".." not in clean_q:
                matched_list = entries_by_name.get(Path(clean_q).name.lower(), [])
                if matched_list:
                    file_entry = matched_list[0]

            if file_entry is not None and " " not in clean_q and (clean_q.endswith((".tsx", ".ts", ".jsx", ".js", ".py", ".json", ".html", ".css", ".md", ".yaml", ".yml")) or "/" in clean_q):
                rel_path = file_entry["rel_path"]
                content = file_entry["content"]
                lines = file_entry["lines"]
                total_lines = len(lines)

                if total_lines <= 120:
                    _add_window(rel_path, content, 1, total_lines, content)
                    continue
                else:
                    top_lines = "\n".join(lines[:50])
                    _add_window(rel_path, content, 1, 50, top_lines)
                    continue

            # Case B: Slug or Pattern search (ripgrep fast path -> mtime-cached fallback)
            rg_paths = self._rg_find_files(sub_q, scan_dirs, excluded_dirs)
            if rg_paths is not None:
                search_entries: list[dict[str, Any]] = []
                for rp in rg_paths:
                    if rp.suffix.lower() in target_exts:
                        ce = core.get_cached_file(rp)
                        if ce is not None:
                            search_entries.append(ce)
            else:
                search_entries = cached_entries

            for cand_entry in search_entries:
                cand_text = cand_entry["content"]
                if sub_q not in cand_text:
                    continue

                rel_path = cand_entry["rel_path"]
                lines = cand_entry["lines"]

                for idx, line in enumerate(lines):
                    if sub_q not in line:
                        continue

                    is_slug = "slug:" in line or "slug" in line

                    if is_slug:
                        obj_start = idx
                        while obj_start > 0 and not lines[obj_start].strip().startswith("{") and (idx - obj_start) < 10:
                            obj_start -= 1

                        header_end = idx
                        while header_end < len(lines) and (header_end - idx) < 40:
                            cur_l = lines[header_end].strip()
                            if cur_l.startswith("faqItems:") or cur_l.startswith("contentHtml:") or ("slug:" in cur_l and header_end > idx):
                                break
                            header_end += 1

                        h_start_num = obj_start + 1
                        h_end_num = header_end
                        h_content = "\n".join(lines[obj_start:header_end])
                        _add_window(rel_path, cand_text, h_start_num, h_end_num, h_content)

                        faq_start = None
                        faq_end = None
                        for k in range(idx, min(idx + 180, len(lines))):
                            if "faqItems:" in lines[k]:
                                faq_start = k
                                break
                            if "slug:" in lines[k] and k > idx:
                                break

                        if faq_start is not None:
                            depth = 0
                            for k in range(faq_start, min(faq_start + 120, len(lines))):
                                depth += lines[k].count("[") - lines[k].count("]")
                                if depth <= 0 and k > faq_start:
                                    faq_end = k + 1
                                    break
                            if faq_end is not None:
                                f_start_num = faq_start + 1
                                f_end_num = faq_end
                                f_content = "\n".join(lines[faq_start:faq_end])
                                _add_window(rel_path, cand_text, f_start_num, f_end_num, f_content)
                        break
                    else:
                        w_start = max(0, idx - 10)
                        w_end = min(len(lines), idx + 15)
                        w_content = "\n".join(lines[w_start:w_end])
                        _add_window(rel_path, cand_text, w_start + 1, w_end, w_content)
                        break

        # Enforce max_tokens budget across all extracted verbatim windows via water-filling
        if max_tokens > 0 and grouped_windows:
            char_budget = max(256, max_tokens * 4)
            all_win_refs: list[tuple[str, int]] = []
            for rel_path, bucket in grouped_windows.items():
                for w_idx in range(len(bucket["windows"])):
                    all_win_refs.append((rel_path, w_idx))

            total_snippet_chars = sum(
                len(grouped_windows[rp]["windows"][wi][2]) for rp, wi in all_win_refs
            )
            header_reserve = len(all_win_refs) * 75 + (
                0 if detail == "minimal" else len(grouped_windows) * 900
            )
            avail_chars = max(240, char_budget - header_reserve)

            if total_snippet_chars > avail_chars and all_win_refs:
                # Progressive water-filling allocation so small windows stay intact
                lengths = [
                    len(grouped_windows[rp]["windows"][wi][2]) for rp, wi in all_win_refs
                ]
                alloc = [0] * len(all_win_refs)
                remaining = avail_chars
                active = list(range(len(all_win_refs)))
                while active and remaining > 0:
                    share = max(1, remaining // len(active))
                    next_active: list[int] = []
                    used_this_round = 0
                    for idx_ref in active:
                        need = lengths[idx_ref] - alloc[idx_ref]
                        if need <= share:
                            alloc[idx_ref] += need
                            used_this_round += need
                        else:
                            alloc[idx_ref] += share
                            used_this_round += share
                            next_active.append(idx_ref)
                    if used_this_round == 0:
                        break
                    remaining -= used_this_round
                    active = next_active

                for pos, (rp, wi) in enumerate(all_win_refs):
                    s_idx, e_idx, snip = grouped_windows[rp]["windows"][wi]
                    cap = alloc[pos]
                    if len(snip) > cap:
                        snip_lines = snip.splitlines()
                        kept_lines: list[str] = []
                        used_c = 0
                        for ln in snip_lines:
                            cost = len(ln) + 1
                            if used_c + cost > max(80, cap - 90) and kept_lines:
                                break
                            kept_lines.append(ln)
                            used_c += cost
                        new_end = s_idx + len(kept_lines) - 1
                        omitted_start = new_end + 1
                        if omitted_start <= e_idx:
                            kept_lines.append(
                                f"... [truncated; use {rp}:{omitted_start}-{e_idx} for remainder]"
                            )
                        grouped_windows[rp]["windows"][wi] = (
                            s_idx,
                            new_end,
                            "\n".join(kept_lines),
                        )

        windows: list[str] = []
        for rel_path, bucket in grouped_windows.items():
            windows.append(
                self._format_grouped_windows_with_gmmu(
                    rel_path=rel_path,
                    windows=bucket["windows"],
                    all_content=bucket["content"],
                    detail=detail,
                )
            )
        return windows

    def _tool_get_pruned_context(
        self,
        query: str = "",
        max_tokens: int = 1400,
        for_edit: bool = True,
        detail: str | None = None,
        workspace_root: str | None = None,
        target_files: list[str] | None = None,
    ) -> str:
        """Retrieves deterministic AST frames with dynamic workspace resolution and HTTP delegation."""
        remote_payload: dict[str, Any] = {
            "query": query,
            "max_tokens": max_tokens,
            "for_edit": for_edit,
            "workspace_root": workspace_root or os.environ.get("PHONIX_WORKSPACE") or os.getcwd(),
            "target_files": target_files or [],
        }
        if detail is not None:
            remote_payload["detail"] = detail
        remote = self._try_http_gateway("/v1/mmu/prune", remote_payload)
        if remote is not None:
            return remote

        core = self._resolve_active_core(query=query, explicit_workspace=workspace_root)
        sub_queries = [q.strip() for q in query.split("|") if q.strip()]

        has_colon_range = any(re.match(r"^.+?:\d+-\d+$", q) for q in sub_queries)
        if detail in ("minimal", "standard", "full"):
            effective_detail = detail
        elif for_edit or has_colon_range:
            effective_detail = "minimal"
        else:
            effective_detail = "standard"

        # Fast exact pattern / slug / file window extraction when for_edit is requested or multi-query
        if for_edit or len(sub_queries) > 1 or any("-" in q or "/" in q or ":" in q for q in sub_queries):
            windows = self._extract_verbatim_windows(
                core, sub_queries, max_tokens=max_tokens, detail=effective_detail
            )
            if windows:
                if effective_detail == "minimal":
                    return "\n\n".join(windows)
                return (
                    f"Phonix Context MMU v2.1 [Verbatim Edit Windows]: Located {len(windows)} file bundle(s) in '{Path(core.workspace_root).name}':\n\n"
                    + "\n\n".join(windows)
                )

        # Step A: Speculative Trie matching for file paths
        if core.file_trie.total_files == 0 and not core._frame_registry:
            core.index_workspace()
        core.speculative_inspector.reset_stream()
        inspection = core.speculative_inspector.process_chunk(query)

        candidate_files = list(inspection.candidate_files)
        for arg_file in (target_files or []):
            if arg_file not in candidate_files:
                candidate_files.append(arg_file)

        # Step B: Gather candidate frames from matched files AND symbol/keyword search
        frames = []
        seen_ids: set[str] = set()
        for file_path in candidate_files:
            f_list = core._file_to_frames.get(file_path, [])
            if not f_list:
                f_list = core.ast_slicer.slice_file(file_path)
            for f in f_list:
                if f.frame_id not in seen_ids:
                    frames.append(f)
                    seen_ids.add(f.frame_id)

        # Also match file paths, stems, and symbols across the workspace
        query_lower = query.lower()
        tokens = set(re.findall(r"[a-zA-Z0-9_\-]+", query_lower))

        for fpath, flist in core._file_to_frames.items():
            fpath_lower = fpath.lower()
            stem_lower = Path(fpath).stem.lower()
            base_lower = Path(fpath).name.lower()
            if (
                stem_lower in tokens
                or base_lower in tokens
                or (len(query_lower) >= 4 and query_lower in fpath_lower)
                or any(t in stem_lower for t in tokens if len(t) >= 4)
            ):
                for f in flist:
                    if f.frame_id not in seen_ids:
                        frames.append(f)
                        seen_ids.add(f.frame_id)

        for f in core._frame_registry.values():
            if f.frame_id in seen_ids:
                continue
            sym_lower = (f.symbol_name or "").lower()
            fpath_lower = (f.file_path or "").lower()
            if (
                (sym_lower and len(sym_lower) >= 3 and (sym_lower in query_lower or sym_lower in tokens))
                or (fpath_lower and (fpath_lower in query_lower or query_lower in fpath_lower))
                or any(t in sym_lower for t in tokens if len(t) >= 4)
            ):
                frames.append(f)
                seen_ids.add(f.frame_id)

        # If still empty, run smart Micro-Router relevance scoring across all indexed frames
        if not frames and core._frame_registry:
            all_frames = list(core._frame_registry.values())
            router_res = core.micro_router.route_and_prune(
                user_prompt=query, candidate_frames=all_frames
            )
            sel_set = set(router_res.selected_ast_frames)
            frames = [f for f in all_frames if f.frame_id in sel_set]

        # Step C: Call-graph BFS expansion (1-hop / 2-hop)
        seed_symbols = [f.symbol_name for f in frames[:5]]
        if seed_symbols:
            paged_frames = core.call_graph_pager.page_graph(
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
            router_decision = core.micro_router.route_and_prune(
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

        eviction_res = core.frame_evictor.evict(paged_frames, token_budget=max_tokens)
        retained_frames = eviction_res.retained_frames

        # Optional Proprietary Moat Enhancement (private_moat)
        moat_header = ""
        try:
            from private_moat.behavioral_hotspot_engine import BehavioralHotspotEngine
            from private_moat.foveated_ast_compactor import FoveatedASTCompactor

            hotspot_eng = BehavioralHotspotEngine(workspace_root=core.workspace_root)
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
            san = core.sanitizer.sanitize(f.raw_code, existing_vault=self._session_vault)
            self._session_vault.update(san.vault)
            total_tokens += f.token_count
            rendered_blocks.append(
                f"=== AST Frame: {f.frame_id} (Symbol: {f.symbol_name}, File: {f.file_path}, "
                f"Lines {f.start_line}-{f.end_line}, {f.token_count} tokens) ===\n"
                f"{san.sanitized_text}\n"
            )

        if not rendered_blocks:
            return f"No AST frames matched query '{query}'. Candidate files checked: {candidate_files}"
        return (
            f"Phonix Context MMU{moat_header}: Paged & Pruned {len(retained_frames)} AST frames ({total_tokens} tokens / budget {max_tokens}):\n\n"
            + "\n".join(rendered_blocks)
        )

    def _tool_verify_zero_trust(
        self,
        text: str = "",
        role: str = "engineer",
        department: str = "engineering",
        target_upstream: str = "anthropic",
        workspace_root: str | None = None,
    ) -> str:
        """Formal Zero-Trust verification and policy evaluation with optional HTTP delegation."""
        remote = self._try_http_gateway(
            "/v1/z3/verify",
            {
                "text": text,
                "role": role,
                "department": department,
                "target_upstream": target_upstream,
                "workspace_root": workspace_root or os.environ.get("PHONIX_WORKSPACE") or os.getcwd(),
            },
        )
        if remote is not None:
            return remote

        core = self._resolve_active_core(explicit_workspace=workspace_root)
        san = core.sanitizer.sanitize(text)
        req = PolicyRequest(
            user_id="mcp-agent",
            role=role,
            department=department,
            target_upstream=target_upstream,
            estimated_tokens=len(text) // 4,
            unredacted_secrets_count=0,
        )
        decision = core.policy_engine.evaluate(req)

        redacted_details = [
            f"- {r.category} -> {r.placeholder} (len: {len(r.original_value)})"
            for r in san.redactions
        ]
        details_str = "\n".join(redacted_details) if redacted_details else "None (Clean)"

        return (
            f"=== Phonix Zero-Trust Safety Verification ===\n"
            f"Decision: {'ALLOWED' if decision.is_allowed else 'BLOCKED'}\n"
            f"Z3 Proof Status: {decision.z3_proof_status}\n"
            f"Reason: {decision.reason}\n"
            f"Enforced Upstream: {decision.enforced_upstream}\n"
            f"Detected Sensitive Literals ({san.redaction_count}):\n{details_str}\n\n"
            f"[Sanitized Text Preview]\n{san.sanitized_text[:500]}"
        )

    def _rehydrate_from_session_vault(self, text: str) -> str:
        """Restores known <REDACTED_*> placeholders from the session ephemeral vault."""
        if not text or not self._session_vault or "<REDACTED_" not in text:
            return text
        out = text
        for placeholder, original in self._session_vault.items():
            if placeholder in out:
                out = out.replace(placeholder, original)
        return out

    def _tool_symbol_impact(
        self,
        symbol: str,
        max_tokens: int = 1024,
        include_snippets: bool = True,
        workspace_root: str | None = None,
    ) -> str:
        """Returns definitions, deduplicated callers (file:line + snippet), and callees in 1 turn."""
        clean_sym = symbol.strip()
        if not clean_sym:
            raise ValueError("symbol must be a non-empty string.")

        core = self._resolve_active_core(query=clean_sym, explicit_workspace=workspace_root)
        # Refresh indexed/cached files so external edits are immediately reflected
        cached_entries = core.refresh_file_index(
            extensions=(".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".c", ".cpp"),
            scan_subdirs=("src", "app", "lib"),
            extra_excluded_dirs=STRICT_EXCLUDED_DIRS,
        )

        # 1. Find Definition Frame(s)
        def_frames = []
        seen_def_keys: set[tuple[str, int, int]] = set()
        for f in core._frame_registry.values():
            sym_name = f.symbol_name or ""
            is_match = (
                sym_name == clean_sym
                or sym_name.endswith(f".{clean_sym}")
                or sym_name.startswith(f"{clean_sym}.")
                or sym_name.startswith(f"{clean_sym}#")
            )
            if is_match:
                key = (f.file_path, f.start_line, f.end_line)
                if key not in seen_def_keys:
                    seen_def_keys.add(key)
                    def_frames.append(f)

        def_lines: list[str] = []
        def_line_set: set[tuple[str, int]] = set()
        callees: set[str] = set()
        for f in def_frames:
            sig = next((ln.strip() for ln in f.raw_code.splitlines() if ln.strip()), f.symbol_name)
            def_lines.append(f"- {f.file_path}:{f.start_line}-{f.end_line} | {sig[:120]}")
            for ln in range(f.start_line, f.end_line + 1):
                def_line_set.add((f.file_path, ln))
            callees.update(f.dependencies or [])
            callees.update(core.call_graph_pager.get_callees(f.symbol_name))

        callees.update(core.call_graph_pager.get_callees(clean_sym))
        callees.discard(clean_sym)

        # 2. Find Callers (call graph + cached text call-site scan)
        graph_callers = core.call_graph_pager.get_callers(clean_sym)
        short_sym = clean_sym.split(".")[-1]
        sym_pat = re.compile(rf"\b{re.escape(short_sym)}\b")
        def_decl_pat = re.compile(
            rf"^\s*(?:async\s+)?(?:def|class|function|interface|type|struct|fn|func)\s+{re.escape(short_sym)}\b"
        )

        caller_entries: list[str] = []
        seen_caller_sites: set[tuple[str, int]] = set()

        for entry in cached_entries:
            rel_path = entry["rel_path"]
            if short_sym not in entry["content"]:
                continue
            for idx, line in enumerate(entry["lines"], start=1):
                if (rel_path, idx) in seen_caller_sites:
                    continue
                if not sym_pat.search(line):
                    continue
                stripped = line.strip()
                if def_decl_pat.match(stripped):
                    continue
                # Skip the definition header line itself
                if any(
                    f.file_path == rel_path and idx == f.start_line
                    for f in def_frames
                ):
                    continue
                seen_caller_sites.add((rel_path, idx))
                if include_snippets:
                    caller_entries.append(f"- {rel_path}:{idx}: {stripped[:120]}")
                else:
                    caller_entries.append(f"- {rel_path}:{idx}")

        # Include graph-only callers not already covered by line scan
        if graph_callers:
            existing_files_or_syms = "\n".join(caller_entries)
            for gc in sorted(graph_callers):
                if gc == clean_sym:
                    continue
                g_frames = core.call_graph_pager.get_symbol_frames(gc)
                if g_frames:
                    gf = g_frames[0]
                    if (gf.file_path, gf.start_line) not in seen_caller_sites and gc not in existing_files_or_syms:
                        seen_caller_sites.add((gf.file_path, gf.start_line))
                        caller_entries.append(f"- {gf.file_path}:{gf.start_line} (symbol: {gc})")

        # 3. Format compact output strictly within max_tokens (~4 chars/token)
        char_budget = max(320, max_tokens * 4)
        sections: list[str] = [f"=== Phonix Symbol Impact: {clean_sym} ==="]
        sections.append(
            f"Definitions ({len(def_lines)}):\n"
            + ("\n".join(def_lines[:10]) if def_lines else "- (none indexed)")
        )
        sections.append(
            f"Callers ({len(caller_entries)}):\n"
            + ("\n".join(caller_entries[:25]) if caller_entries else "- (none found)")
        )
        sorted_callees = sorted(callees)
        sections.append(
            f"Callees ({len(sorted_callees)}):\n"
            + (", ".join(sorted_callees[:25]) if sorted_callees else "(none)")
        )

        output = "\n\n".join(sections)
        if len(output) > char_budget:
            output = output[: char_budget - 40].rstrip() + "\n... [truncated to max_tokens]"
        return output

    def _tool_run_compact(
        self,
        command: str,
        max_tokens: int = 800,
        timeout_sec: int = 60,
        workspace_root: str | None = None,
    ) -> str:
        """Executes a command in workspace_root and returns compacted output."""
        core = self._resolve_active_core(explicit_workspace=workspace_root)
        return run_and_compact(
            command=command,
            workspace_root=core.workspace_root,
            max_tokens=max_tokens,
            timeout_sec=timeout_sec,
        )

    def _tool_surgical_edit(
        self,
        file_path: str,
        edits: list[dict[str, str]],
        workspace_root: str | None = None,
    ) -> str:
        """Applies atomic sequential target->replacement edits with automatic CRLF/LF normalization."""
        # Rehydrate known placeholders from session vault and guard against unknown placeholders
        sanitized_edits: list[dict[str, str]] = []
        for idx, edit in enumerate(edits, start=1):
            t_str = self._rehydrate_from_session_vault(edit.get("target", ""))
            r_str = self._rehydrate_from_session_vault(edit.get("replacement", ""))
            unresolved = re.findall(r"<REDACTED_[A-Za-z0-9_]+>", r_str)
            if unresolved:
                raise ValueError(
                    f"Edit #{idx} aborted: unresolved redaction placeholder(s) {unresolved} "
                    f"in replacement would corrupt '{file_path}'."
                )
            sanitized_edits.append({"target": t_str, "replacement": r_str})
        edits = sanitized_edits

        remote = self._try_http_gateway(
            "/v1/mmu/surgical-edit",
            {
                "file_path": file_path,
                "edits": edits,
                "workspace_root": workspace_root or os.environ.get("PHONIX_WORKSPACE") or os.getcwd(),
            },
        )
        if remote is not None:
            self._committed_fovea_files.add(file_path.replace("\\", "/"))
            self._committed_fovea_files.add(Path(file_path).name)
            return remote

        core = self._resolve_active_core(query=file_path, explicit_workspace=workspace_root)
        ws_path = Path(core.workspace_root).resolve()

        # 1. Confinement check: resolve path and raise PermissionError unless strictly inside ws_path
        target = _resolve_within(ws_path, file_path)
        if not target.is_file():
            # Fallback search in workspace by filename
            pattern = Path(file_path).name
            matches = [
                cand for cand in ws_path.rglob(f"*{pattern}")
                if (
                    cand.is_file()
                    and not any(part in cand.parts for part in GatewayCore.IGNORED_DIRS)
                    and not any(part in cand.parts for part in STRICT_EXCLUDED_DIRS)
                )
            ]
            if len(matches) > 1:
                match_rel_paths = [str(m.relative_to(ws_path)).replace("\\", "/") for m in matches]
                raise ValueError(
                    f"Ambiguous file path '{file_path}': found multiple matches in workspace: {match_rel_paths}. "
                    "Please specify the exact relative path."
                )
            elif len(matches) == 1:
                target = _resolve_within(ws_path, matches[0])
            else:
                raise FileNotFoundError(f"File '{file_path}' not found in '{ws_path}'")

        raw_bytes = target.read_bytes()
        is_crlf = b"\r\n" in raw_bytes
        content = raw_bytes.decode("utf-8", errors="replace")

        applied_count = 0
        encoding_repaired_count = 0
        for idx, edit in enumerate(edits, start=1):
            target_str = edit.get("target", "")
            replacement_str = edit.get("replacement", "")
            if not target_str:
                continue

            # 1. Exact match attempt
            if target_str in content:
                content = content.replace(target_str, replacement_str, 1)
                applied_count += 1
                continue

            # 2. CRLF/LF normalized match attempt
            norm_content = content.replace("\r\n", "\n")
            norm_target = target_str.replace("\r\n", "\n")
            norm_replacement = replacement_str.replace("\r\n", "\n")

            if norm_target in norm_content:
                norm_content = norm_content.replace(norm_target, norm_replacement, 1)
                if is_crlf:
                    content = norm_content.replace("\n", "\r\n")
                else:
                    content = norm_content
                applied_count += 1
                continue

            # 3. Encoding auto-repair: only after exact and CRLF-normalized matching fail,
            # and ONLY if the repaired target appears exactly once in the file.
            repaired = False
            for cand_enc in ("latin-1", "cp1252"):
                try:
                    re_t = target_str.encode(cand_enc).decode("utf-8")
                except Exception:
                    continue

                if not re_t:
                    continue

                c_count = content.count(re_t)
                nc_count = norm_content.count(re_t.replace("\r\n", "\n"))

                if c_count == 1:
                    re_rep = replacement_str
                    try:
                        re_rep = replacement_str.encode(cand_enc).decode("utf-8")
                    except Exception:
                        pass
                    content = content.replace(re_t, re_rep, 1)
                    applied_count += 1
                    encoding_repaired_count += 1
                    repaired = True
                    break
                elif c_count == 0 and nc_count == 1:
                    norm_re_t = re_t.replace("\r\n", "\n")
                    re_rep = replacement_str
                    try:
                        re_rep = replacement_str.encode(cand_enc).decode("utf-8")
                    except Exception:
                        pass
                    norm_re_rep = re_rep.replace("\r\n", "\n")
                    norm_content = norm_content.replace(norm_re_t, norm_re_rep, 1)
                    if is_crlf:
                        content = norm_content.replace("\n", "\r\n")
                    else:
                        content = norm_content
                    applied_count += 1
                    encoding_repaired_count += 1
                    repaired = True
                    break

            if not repaired:
                raise ValueError(
                    f"Edit #{idx} failed: target string not found in '{file_path}'. "
                    f"Target snippet: {target_str[:80]!r}"
                )

        # Atomic write back
        target.write_bytes(content.encode("utf-8"))

        # Re-index target file in GatewayCore and record committed fovea
        try:
            rel_str = str(target.relative_to(ws_path)).replace("\\", "/")
            self._committed_fovea_files.add(rel_str)
            self._committed_fovea_files.add(target.name)
            self._committed_fovea_files.add(file_path.replace("\\", "/"))
            core.get_cached_file(target)
        except Exception:
            pass

        repair_note = f" (including {encoding_repaired_count} encoding auto-repaired edit(s))" if encoding_repaired_count > 0 else ""
        return (
            f"[Phonix Surgical Edit] Successfully applied {applied_count}/{len(edits)} edit(s){repair_note} to '{target.name}' "
            f"({len(content.splitlines())} lines, line endings: {'CRLF' if is_crlf else 'LF'})."
        )

    def _dispatch_tool_call(
        self, req_id: Any, tool_name: str, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatches an MCP tool call to the appropriate Phonix subsystem."""
        try:
            # 1. phonix_repo_map
            if tool_name == "phonix_repo_map":
                res = self._tool_repo_map(
                    path_prefix=args.get("path_prefix", "").strip(),
                    max_tokens=int(args.get("max_tokens", 256)),
                    workspace_root=args.get("workspace_root"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
                }

            # 2. phonix_get_pruned_context (aliased from phonix_page_context)
            elif tool_name in ("phonix_get_pruned_context", "phonix_page_context"):
                res = self._tool_get_pruned_context(
                    query=args.get("query", ""),
                    max_tokens=int(args.get("max_tokens", 1400)),
                    for_edit=bool(args.get("for_edit", True)),
                    detail=args.get("detail"),
                    workspace_root=args.get("workspace_root"),
                    target_files=args.get("target_files", []),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
                }

            # 3. phonix_verify_zero_trust (aliased from phonix_verify_safety)
            elif tool_name in ("phonix_verify_zero_trust", "phonix_verify_safety"):
                text_to_verify = args.get("text") or args.get("text_or_code") or ""
                role = args.get("role") or args.get("user_role") or "engineer"
                department = args.get("department", "engineering")
                target_upstream = args.get("target_upstream", "anthropic")
                res = self._tool_verify_zero_trust(
                    text=text_to_verify,
                    role=role,
                    department=department,
                    target_upstream=target_upstream,
                    workspace_root=args.get("workspace_root"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
                }

            # 4. phonix_surgical_edit
            elif tool_name == "phonix_surgical_edit":
                file_path = args.get("file_path", "")
                edits = args.get("edits", [])
                res = self._tool_surgical_edit(
                    file_path=file_path,
                    edits=edits,
                    workspace_root=args.get("workspace_root"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
                }

            # 5. phonix_symbol_impact
            elif tool_name == "phonix_symbol_impact":
                res = self._tool_symbol_impact(
                    symbol=args.get("symbol", ""),
                    max_tokens=int(args.get("max_tokens", 1024)),
                    include_snippets=bool(args.get("include_snippets", True)),
                    workspace_root=args.get("workspace_root"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
                }

            # 6. phonix_run_compact
            elif tool_name == "phonix_run_compact":
                res = self._tool_run_compact(
                    command=args.get("command", ""),
                    max_tokens=int(args.get("max_tokens", 800)),
                    timeout_sec=int(args.get("timeout_sec", 60)),
                    workspace_root=args.get("workspace_root"),
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": res}], "isError": False},
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
                callers = list(self.core.call_graph_pager.get_callers(symbol_name))
                callees = list(self.core.call_graph_pager.get_callees(symbol_name))
                san = self.core.sanitizer.sanitize(frame.raw_code, existing_vault=self._session_vault)
                self._session_vault.update(san.vault)
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


def run_stdio_server(workspace_root: str | None = None) -> None:
    """Runs the Stdio MCP Server for a target workspace."""
    if workspace_root is not None:
        resolved_ws = str(Path(workspace_root).resolve())
    else:
        env_root = os.environ.get("PHONIX_WORKSPACE")
        if env_root and os.path.isdir(env_root):
            resolved_ws = str(Path(env_root).resolve())
        else:
            resolved_ws = str(Path(os.getcwd()).resolve())

    logger.info("Phonix MCP Stdio Server running for workspace: %s", resolved_ws)
    server = PhonixMCPServer(workspace_root=resolved_ws)
    server.run_stdio()


if __name__ == "__main__":
    run_stdio_server()
