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
import sys
from typing import Any

from src.gateway.policy_engine import PolicyRequest
from src.gateway.proxy_server import GatewayCore, _ensure_phonix_hp_rule

logger = logging.getLogger("phonix.mcp")

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
            _ensure_phonix_hp_rule(self.workspace_root)
            self.core = GatewayCore(workspace_root=self.workspace_root, auto_index=True)
        self._workspace_cores: dict[str, GatewayCore] = {
            os.path.abspath(self.workspace_root): self.core
        }
        self._committed_fovea_files: set[str] = set()

    def _try_http_gateway(self, endpoint: str, payload: dict[str, Any]) -> str | None:
        """Attempts to forward tool call to live Phonix HTTP Gateway daemon (http://127.0.0.1:8000)."""
        if self._in_http_daemon:
            return None
        gw_url = os.environ.get("PHONIX_GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
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
            _ensure_phonix_hp_rule(norm)
            self._workspace_cores[norm] = GatewayCore(workspace_root=norm, auto_index=True)
        return self._workspace_cores[norm]

    def _resolve_active_core(
        self, query: str = "", explicit_workspace: str | None = None
    ) -> GatewayCore:
        """Dynamically switches to the appropriate workspace GatewayCore based on query context and cwd."""
        if explicit_workspace:
            return self._get_or_create_core(explicit_workspace)

        # 1. Determine active base workspace: PHONIX_WORKSPACE -> os.getcwd() -> self.workspace_root
        active_dir = os.environ.get("PHONIX_WORKSPACE") or os.getcwd()
        norm_active = os.path.abspath(active_dir)
        current_core = self._get_or_create_core(norm_active) if os.path.isdir(norm_active) else self.core

        if not query:
            return current_core

        # 2. Check if current_core already matches files or symbols in query
        query_lower = query.lower()
        for fpath in current_core._file_to_frames.keys():
            if fpath.lower() in query_lower or os.path.basename(fpath).lower() in query_lower:
                return current_core

        for sym in getattr(current_core.call_graph_pager, "_symbol_to_frames", {}).keys():
            if len(sym) >= 3 and sym.lower() in query_lower:
                return current_core

        # 3. Smart Multi-Project Lookup: Search sibling projects under Phonix repo parent
        repo_root = Path(__file__).resolve().parent.parent  # D:\UIT\NamBonUIT\Phonix
        siblings_container = repo_root.parent  # D:\UIT\NamBonUIT

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
                    # Only consider coding repositories
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

                    # Check exact paths from query
                    for q in sub_queries:
                        clean_q = q.strip().replace("\\", "/").strip("/'\"")
                        if (sibling / clean_q).is_file():
                            score += 500
                        # Check slug occurrences in candidate files
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

                    # Non-generic file name matches in sibling folders
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
                            "description": "Maximum token budget for returned AST context (default: 1536)",
                            "default": 1536,
                        },
                        "for_edit": {
                            "type": "boolean",
                            "description": "When true (default for edits/slugs), returns verbatim [Lines X-Y] windows with exact whitespace for direct edit_file/phonix_surgical_edit copy-paste.",
                            "default": True,
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
            s_line = line_range[0] if line_range else 1
            e_line = line_range[1] if line_range else len(all_content.splitlines())
            return f"=== Verbatim Edit Window: {norm_path} [Lines {s_line}-{e_line}] ===\n{snippet}"

    def _extract_verbatim_windows(
        self,
        core: GatewayCore,
        sub_queries: list[str],
        max_tokens: int = 1536,
    ) -> list[str]:
        """Extracts exact verbatim edit windows with exact [Lines X-Y] line numbers."""
        ws_path = Path(core.workspace_root)
        windows: list[str] = []
        seen_regions: set[tuple[str, int, int]] = set()

        # Fast search list of source files (prioritize src/, app/, lib/)
        scan_dirs = [ws_path / d for d in ("src", "app", "lib") if (ws_path / d).is_dir()]
        if not scan_dirs:
            scan_dirs = [ws_path]

        candidate_files: list[Path] = []
        for sdir in scan_dirs:
            for root, dirs, files in os.walk(sdir):
                dirs[:] = [
                    d for d in dirs
                    if d not in GatewayCore.IGNORED_DIRS
                    and d not in STRICT_EXCLUDED_DIRS
                    and not d.startswith(".")
                ]
                for f in files:
                    if f.endswith((".ts", ".tsx", ".js", ".jsx", ".json", ".py", ".html", ".css", ".md")):
                        candidate_files.append(Path(root) / f)

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

                colon_target: Path | None = None
                if (ws_path / colon_file_part).is_file():
                    colon_target = ws_path / colon_file_part
                elif Path(colon_file_part).is_file():
                    colon_target = Path(colon_file_part)
                else:
                    target_name = Path(colon_file_part).name.lower()
                    for cand in candidate_files:
                        if cand.name.lower() == target_name:
                            colon_target = cand
                            break

                if colon_target is None:
                    try:
                        for cand in ws_path.rglob(f"*{Path(colon_file_part).name}"):
                            if (
                                not any(p in cand.parts for p in GatewayCore.IGNORED_DIRS)
                                and not any(p in cand.parts for p in STRICT_EXCLUDED_DIRS)
                            ):
                                colon_target = cand
                                break
                    except Exception:
                        pass

                if colon_target is not None:
                    try:
                        rel_path = str(colon_target.relative_to(ws_path)).replace("\\", "/")
                    except ValueError:
                        rel_path = colon_file_part
                    content = colon_target.read_text(encoding="utf-8", errors="ignore")
                    all_lines = content.splitlines()
                    total_lines = len(all_lines)
                    s_idx = max(1, s_idx)
                    e_idx = min(total_lines, e_idx)
                    region = (rel_path, s_idx, e_idx)
                    if region not in seen_regions:
                        seen_regions.add(region)
                        slice_lines = all_lines[s_idx - 1 : e_idx]
                        slice_text = "\n".join(slice_lines)
                        windows.append(
                            self._format_window_with_gmmu(
                                rel_path=rel_path,
                                snippet=slice_text,
                                all_content=content,
                                line_range=(s_idx, e_idx),
                            )
                        )
                    continue

            clean_q = sub_q.replace("\\", "/").strip("'\"")

            # Case A: Is clean_q a file path in workspace?
            file_match: Path | None = None
            if (ws_path / clean_q).is_file():
                file_match = ws_path / clean_q
            elif " " not in clean_q:
                for cand in candidate_files:
                    if cand.name.lower() == Path(clean_q).name.lower():
                        file_match = cand
                        break

            if file_match is not None and " " not in clean_q and (clean_q.endswith((".tsx", ".ts", ".jsx", ".js", ".py", ".json", ".html", ".css", ".md", ".yaml", ".yml")) or "/" in clean_q):
                rel_path = str(file_match.relative_to(ws_path)).replace("\\", "/")
                content = file_match.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                total_lines = len(lines)

                if total_lines <= 120:
                    region = (rel_path, 1, total_lines)
                    if region not in seen_regions:
                        seen_regions.add(region)
                        windows.append(
                            self._format_window_with_gmmu(
                                rel_path=rel_path,
                                snippet=content,
                                all_content=content,
                                line_range=(1, total_lines),
                            )
                        )
                    continue
                else:
                    top_lines = "\n".join(lines[:50])
                    region = (rel_path, 1, 50)
                    if region not in seen_regions:
                        seen_regions.add(region)
                        windows.append(
                            self._format_window_with_gmmu(
                                rel_path=rel_path,
                                snippet=top_lines,
                                all_content=content,
                                line_range=(1, 50),
                            )
                        )
                    continue

            # Case B: Slug or Pattern search across workspace source files
            for cand_file in candidate_files:
                try:
                    cand_text = cand_file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                if sub_q not in cand_text:
                    continue

                rel_path = str(cand_file.relative_to(ws_path)).replace("\\", "/")
                lines = cand_text.splitlines()

                # Find line numbers containing sub_q
                for idx, line in enumerate(lines):
                    if sub_q not in line:
                        continue

                    is_slug = "slug:" in line or "slug" in line

                    if is_slug:
                        # 1. Header / metadata window
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
                        h_region = (rel_path, h_start_num, h_end_num)
                        if h_region not in seen_regions:
                            seen_regions.add(h_region)
                            h_content = "\n".join(lines[obj_start:header_end])
                            windows.append(
                                self._format_window_with_gmmu(
                                    rel_path=rel_path,
                                    snippet=h_content,
                                    all_content=cand_text,
                                    line_range=(h_start_num, h_end_num),
                                )
                            )

                        # 2. Closing / FAQ window
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
                                f_region = (rel_path, f_start_num, f_end_num)
                                if f_region not in seen_regions:
                                    seen_regions.add(f_region)
                                    f_content = "\n".join(lines[faq_start:faq_end])
                                    windows.append(
                                        self._format_window_with_gmmu(
                                            rel_path=rel_path,
                                            snippet=f_content,
                                            all_content=cand_text,
                                            line_range=(f_start_num, f_end_num),
                                        )
                                    )
                        break
                    else:
                        # General anchor match (table row, heading, anchor)
                        w_start = max(0, idx - 10)
                        w_end = min(len(lines), idx + 15)
                        w_region = (rel_path, w_start + 1, w_end)
                        if w_region not in seen_regions:
                            seen_regions.add(w_region)
                            w_content = "\n".join(lines[w_start:w_end])
                            windows.append(
                                self._format_window_with_gmmu(
                                    rel_path=rel_path,
                                    snippet=w_content,
                                    all_content=cand_text,
                                    line_range=(w_start + 1, w_end),
                                )
                            )
                        break
        return windows

    def _tool_get_pruned_context(
        self,
        query: str = "",
        max_tokens: int = 1536,
        for_edit: bool = True,
        workspace_root: str | None = None,
        target_files: list[str] | None = None,
    ) -> str:
        """Retrieves deterministic AST frames with dynamic multi-repo resolution and HTTP delegation."""
        remote = self._try_http_gateway(
            "/v1/mmu/prune",
            {
                "query": query,
                "max_tokens": max_tokens,
                "for_edit": for_edit,
                "workspace_root": workspace_root or os.environ.get("PHONIX_WORKSPACE") or os.getcwd(),
                "target_files": target_files or [],
            },
        )
        if remote is not None:
            return remote

        core = self._resolve_active_core(query=query, explicit_workspace=workspace_root)
        sub_queries = [q.strip() for q in query.split("|") if q.strip()]

        # Fast exact pattern / slug / file window extraction when for_edit is requested or multi-query
        if for_edit or len(sub_queries) > 1 or any("-" in q or "/" in q or ":" in q for q in sub_queries):
            windows = self._extract_verbatim_windows(core, sub_queries, max_tokens=max_tokens)
            if windows:
                return (
                    f"Phonix Context MMU v2.1 [Verbatim Edit Windows]: Located {len(windows)} target region(s) in '{Path(core.workspace_root).name}':\n\n"
                    + "\n\n".join(windows)
                )

        # Step A: Speculative Trie matching for file paths
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
            san = core.sanitizer.sanitize(f.raw_code)
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

    def _tool_surgical_edit(
        self,
        file_path: str,
        edits: list[dict[str, str]],
        workspace_root: str | None = None,
    ) -> str:
        """Applies atomic sequential target->replacement edits with automatic CRLF/LF normalization."""
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
        ws_path = Path(core.workspace_root)

        target = Path(file_path)
        if not target.is_absolute():
            target = ws_path / target
        if not target.is_file():
            # Fallback search in workspace
            matches = [
                cand for cand in ws_path.rglob(f"*{Path(file_path).name}")
                if (
                    not any(part in cand.parts for part in GatewayCore.IGNORED_DIRS)
                    and not any(part in cand.parts for part in STRICT_EXCLUDED_DIRS)
                )
            ]
            if matches:
                target = matches[0]
            else:
                raise FileNotFoundError(f"File '{file_path}' not found in '{ws_path}'")

        raw_bytes = target.read_bytes()
        is_crlf = b"\r\n" in raw_bytes
        content = raw_bytes.decode("utf-8", errors="replace")

        applied_count = 0
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
            else:
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
            frames = core.ast_slicer.slice_file(str(target))
            core._file_to_frames[rel_str] = frames
            for f in frames:
                core._frame_registry[f.frame_id] = f
        except Exception:
            pass

        return (
            f"[Phonix Surgical Edit] Successfully applied {applied_count}/{len(edits)} edit(s) to '{target.name}' "
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
                    max_tokens=int(args.get("max_tokens", 1536)),
                    for_edit=bool(args.get("for_edit", True)),
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
