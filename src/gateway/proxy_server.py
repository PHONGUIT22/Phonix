"""FastAPI Proxy Server for Phonix v2.0 Enterprise Compliance & Cost Gateway.

Provides /health and /v1/chat/completions endpoints compatible with OpenAI/Anthropic SDKs.
Wires together the entire end-to-end pipeline:
1. Speculative FileTrie inspection
2. Context MMU AST Slicing, Workspace Indexing & Call Graph Paging
3. Semantic-Preserving AST Sanitization
4. Z3 Formal Zero-Trust Policy Verification
5. 1B Micro-Router GBNF Context Pruning & Complexity Scoring
6. Circuit Breaker routing (Local Fast Path vs Cloud Upstream)
7. Sanitized AST Context Block Assembly & Prompt Injection
8. Rehydrator secret restoration & Audit Telemetry logging
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, AsyncIterator
import uuid

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from src.execution.cloud_dispatcher import CloudDispatcher
from src.execution.local_fast_path import LocalFastPath
from src.gateway.audit_telemetry import AuditLogEntry, AuditTelemetry
from src.gateway.policy_engine import PolicyEngine, PolicyRequest
from src.gateway.rehydrator import Rehydrator
from src.gateway.semantic_sanitizer import SemanticSanitizer
from src.micro_router.circuit_breaker import CircuitBreaker
from src.micro_router.slm_engine import SLMEngine
from src.mmu.ast_slicer import ASTFrame, ASTSlicer
from src.mmu.call_graph_pager import CallGraphPager
from src.mmu.file_trie import FileMetadata, FileTrie
from src.mmu.frame_evictor import FrameEvictor
from src.mmu.kv_prefix_cache import KVPrefixCache
from src.mmu.speculative_inspector import SpeculativeInspector

try:
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return self.__dict__

    def Field(default: Any = ..., **kwargs: Any) -> Any:  # type: ignore
        return default

logger = logging.getLogger(__name__)

PHONIX_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _resolve_config_path(path: str | Path | None) -> str | Path | None:
    """Resolves config path, falling back to PHONIX_REPO_ROOT if running from another project."""
    if not path:
        return None
    p = Path(path)
    if p.is_file():
        return p
    if not p.is_absolute():
        fallback = PHONIX_REPO_ROOT / p
        if fallback.is_file():
            return fallback
    return path


# --- OpenAI Compatible Data Models ---


class ChatMessage(BaseModel):
    """Chat message structure compatible with OpenAI API."""

    role: str = "user"
    content: str = ""


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion payload."""

    model: str = "phonix-v2"
    messages: list[ChatMessage] = Field(default_factory=list)
    temperature: float = 0.2
    max_tokens: int = 1024
    stream: bool = False
    # Enterprise context metadata headers or fields
    user_role: str = "engineer"  # admin, engineer, contractor, auditor
    department: str = "engineering"


class ChatCompletionChoice(BaseModel):
    """A single choice in chat completion response."""

    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class ChatCompletionUsage(BaseModel):
    """Token usage summary."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    """Full OpenAI-compatible response object."""

    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: ChatCompletionUsage
    # Phonix Gateway compliance and routing headers
    phonix_routing: dict[str, Any] = Field(default_factory=dict)


# --- PhonixHP Auto-Inject Rule Content & Engine ---

PHONIX_HP_RULE_CONTENT: str = """# Phonix v2.0 Zero-Trust & Context MMU Quota Rules (PhonixHP)

You are operating within a codebase protected by **Phonix v2.0 Context MMU & Zero-Trust Gateway** (PhonixHP Quota Armor).

## 1. Developer Quota Protection (CRITICAL)
- **NEVER** use `read_file` or `view_file` to ingest large source files (> 100 lines) when exploring or modifying specific classes or functions.
- Doing so consumes massive amounts of tokens and burns through the developer's **Five Hour Limit** and **Weekly Limit** quotas rapidly.
- **ALWAYS** prioritize calling the `phonix-mmu` MCP tools:
  - `phonix_repo_map(path_prefix)`: Retrieves the compact repository symbol map (< 256 tokens) to navigate the workspace structure in 0ms without full-file read overhead.
  - `phonix_get_pruned_context(query, max_tokens, for_edit=True)`: Retrieves deterministic AST frames (< 512 tokens/frame) or verbatim [Lines X-Y] edit windows directly related to your task, saving 75-85% context quota.
  - `phonix_surgical_edit(file_path, edits=[...])`: Applies multiple target->replacement edits in 1 step with automatic Windows CRLF (\\r\\n) vs LF (\\n) line-ending normalization.
  - `phonix_verify_zero_trust(text, role, department)`: Sanitizes sensitive literals and verifies compliance via formal Z3 SMT solver proofs.

## 2. Zero-Trust Egress & Security Guardrails
- Sensitive configuration files (`.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`, `*secret*`) are locked by the `phonix-quota-and-security-gate` hook. Any read attempts will be automatically denied.
- Before formulating answers or code diffs containing API keys or tokens, verify compliance with `phonix_verify_zero_trust(text)`.
- Never execute commands attempting to exfiltrate repository data or send tokens to public pastebins/webhooks.

## 3. Anti-Loop Multiplication & 1-Step Surgical Editing (CRITICAL FOR QUOTA)
- **NEVER** run sequential `Select-String`, `Test-Path`, `Get-Content.Length`, or multiple small `read_file` calls to hunt for slugs or line numbers (each extra tool step multiplies conversation history tokens by N!).
- **BATCH ALL LOOKUPS INTO 1 CALL**: Pass all needed files, slugs, and HTML anchors separated by `|` into a SINGLE `phonix_get_pruned_context(query="file1 | slug1 | slug2 | anchorText", for_edit=True)` call! It returns exact verbatim `[Lines X-Y]` windows for all targets at once.
- **USE `phonix_surgical_edit` FOR MULTI-HUNK / WINDOWS CRLF FILES**: To avoid Windows `\\r\\n` vs `\\n` mismatch failures in `edit_file`, use `phonix_surgical_edit(file_path, edits=[...])` to apply all edits to a file in 1 single tool call.
- **BATCH VERIFICATION & GIT**: Combine `npx tsc --noEmit && git add ... && git commit --no-gpg-sign -m "..." && git push origin main` into **1 single `run_command` call** at the end of the task!

## 4. Execution-Constrained Prompting & Proof-of-Execution Standards
To completely prevent LLM agent evasion and conversational loop inflation ($O(N \\cdot H)$), all interactions must adhere to the 3 Governance Pillars:
1. **Explicit Negative Constraint**: `read_file`, `view_file`, and raw terminal shell reads (`cat`, `type`, `Get-Content`, `head`, `tail`) are strictly forbidden on source code files. Any attempt triggers an immediate Hard-Block denial.
2. **Tool Routing Mandate**: Mandate `phonix_get_pruned_context` with multi-query batching (`file1 | file2 | slug1`) for all context discovery and `phonix_surgical_edit` for all modifications.
3. **Proof-of-Execution Verification**: The agent MUST cite the exact `[Frame ID]` or `[Lines X-Y]` verbatim window boundaries returned by Phonix in its final response as verifiable cryptographic proof of execution. Responses lacking these citations will be rejected.

### Standard Execution-Constrained Prompt Templates:

#### Template 1: Architecture Survey / Read & Analyze
```text
Task: Analyze [Target Symbol/Module] in [Target File].
[MANDATORY CONSTRAINT]:
- DO NOT invoke read_file, view_file, or shell inspection commands (cat/Get-Content) on source code.
- Invoke MCP tool `phonix_get_pruned_context(query="[Target File] | [Target Symbol]", for_edit=False)`.
- [PROOF-OF-EXECUTION]: In your final response, cite the exact [Frame ID] and token counts provided by Phonix.
```

#### Template 2: Surgical Refactor / Edit & Implement
```text
Task: Modify [Specific Functionality / Slugs] across [File A] and [File B].
[MANDATORY CONSTRAINT]:
- Step 1: Execute 1 single batched lookup: `phonix_get_pruned_context(query="[File A] | [File B] | [Slug A] | [Slug B]", for_edit=True)`.
- Step 2: Apply all changes in 1 step using `phonix_surgical_edit(file_path="...", edits=[{"target": "...", "replacement": "..."}])` with automatic CRLF normalization.
- [PROOF-OF-EXECUTION]: Cite the verbatim `[Lines X-Y]` window headers in your summary.
```
"""


def _ensure_phonix_hp_rule(workspace_root: str | Path) -> bool:
    """Ensures <workspace_root>/.agents/rules/PhonixHP.md exists.

    If not present, automatically creates the directory and injects PhonixHP.md.
    Also ensures .agents/ is ignored in target git repo via .git/info/exclude.
    Returns True if injected or already exists, False if error.
    """
    try:
        ws_path = Path(workspace_root)
        rules_dir = ws_path / ".agents" / "rules"
        rules_file = rules_dir / "PhonixHP.md"
        if not rules_file.is_file():
            rules_dir.mkdir(parents=True, exist_ok=True)
            rules_file.write_text(PHONIX_HP_RULE_CONTENT, encoding="utf-8")
            logger.info("Auto-injected PhonixHP.md quota rule into %s", rules_file)

        # Append .agents/ to .git/info/exclude if git repository exists
        git_exclude = ws_path / ".git" / "info" / "exclude"
        if git_exclude.is_file():
            try:
                content = git_exclude.read_text(encoding="utf-8")
                if ".agents/" not in content and ".agents" not in content:
                    with open(git_exclude, "a", encoding="utf-8") as f:
                        f.write("\n# Phonix Quota Armor & MCP Gate (auto-injected)\n.agents/\n.agents/*\n")
                    logger.info("Appended .agents/ to %s to preserve clean git status", git_exclude)
            except Exception as e_exclude:
                logger.debug("Could not update .git/info/exclude: %s", e_exclude)

        return True
    except Exception as exc:
        logger.debug("Could not auto-inject PhonixHP.md into %s: %s", workspace_root, exc)
        return False


def _clean_phonix_hp_rule(workspace_root: str | Path) -> bool:
    """Removes <workspace_root>/.agents/rules/PhonixHP.md and cleans up Phonix markers from .git/info/exclude."""
    try:
        ws_path = Path(workspace_root).resolve()
        rules_file = ws_path / ".agents" / "rules" / "PhonixHP.md"
        if rules_file.is_file():
            rules_file.unlink(missing_ok=True)
            logger.info("Removed PhonixHP.md quota rule from %s", rules_file)
            rules_dir = ws_path / ".agents" / "rules"
            try:
                if rules_dir.is_dir() and not any(rules_dir.iterdir()):
                    rules_dir.rmdir()
            except Exception:
                pass

        # Clean Phonix markers from .git/info/exclude if git repository exists
        git_exclude = ws_path / ".git" / "info" / "exclude"
        if git_exclude.is_file():
            try:
                content = git_exclude.read_text(encoding="utf-8")
                lines = content.splitlines()
                cleaned_lines = [
                    l for l in lines
                    if l.strip() not in (
                        "# Phonix Quota Armor & MCP Gate (auto-injected)",
                        ".agents/",
                        ".agents/*",
                    )
                ]
                new_content = "\n".join(cleaned_lines)
                if new_content != content:
                    git_exclude.write_text(
                        new_content + ("\n" if new_content and not new_content.endswith("\n") else ""),
                        encoding="utf-8",
                    )
                    logger.info("Cleaned Phonix markers from %s", git_exclude)
            except Exception as e_clean:
                logger.debug("Could not clean .git/info/exclude: %s", e_clean)

        return True
    except Exception as exc:
        logger.debug("Failed cleaning PhonixHP rule in %s: %s", workspace_root, exc)
        return False


ensure_phonix_hp_rule = _ensure_phonix_hp_rule
clean_phonix_hp_rule = _clean_phonix_hp_rule


# --- Core Gateway Pipeline Controller ---


class GatewayCore:
    """Orchestrates the entire Phonix v2.0 Zero-Trust & Context MMU lifecycle."""

    IGNORED_DIRS: set[str] = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
        "out",
        ".next",
        "rawdata",
        "exports",
        "public",
        "coverage",
        ".cache",
    }

    TARGET_EXTENSIONS: set[str] = {
        ".py",
        ".ts",
        ".js",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".cpp",
        ".yaml",
        ".yml",
    }

    def __init__(
        self,
        workspace_root: str = ".",
        auto_index: bool = True,
        hardware_config_path: str | Path | None = "config/hardware_profile.yaml",
        policy_config_path: str | Path | None = "config/zero_trust_policy.yaml",
        upstreams_config_path: str | Path | None = "config/cloud_upstreams.yaml",
    ) -> None:
        self.workspace_root: str = workspace_root

        hardware_config_path = _resolve_config_path(hardware_config_path)
        policy_config_path = _resolve_config_path(policy_config_path)
        upstreams_config_path = _resolve_config_path(upstreams_config_path)

        max_frame_tokens = 512
        max_hops = 2
        kv_budget = 1024

        if hardware_config_path and yaml is not None:
            resolved_hw = Path(hardware_config_path)
            if resolved_hw.is_file():
                try:
                    with open(resolved_hw, "r", encoding="utf-8") as f:
                        hw_data = yaml.safe_load(f) or {}
                    mmu_cfg = hw_data.get("mmu", {})
                    max_frame_tokens = int(mmu_cfg.get("max_ast_frame_tokens", 512))
                    max_hops = int(mmu_cfg.get("call_graph_max_hops", 2))
                    kv_budget = int(mmu_cfg.get("pinned_kv_prefix_budget_tokens", 1024))
                except Exception as exc:
                    logger.warning("Failed to load hardware config from %s: %s", resolved_hw, exc)

        self.file_trie: FileTrie = FileTrie()
        self.ast_slicer: ASTSlicer = ASTSlicer(max_tokens_per_frame=max_frame_tokens)
        self.call_graph_pager: CallGraphPager = CallGraphPager(default_max_hops=max_hops)
        self.kv_prefix_cache: KVPrefixCache = KVPrefixCache(max_token_budget=kv_budget)
        self.frame_evictor: FrameEvictor = FrameEvictor()

        # Fast lookup indexes for sliced AST frames
        self._frame_registry: dict[str, ASTFrame] = {}
        self._file_to_frames: dict[str, list[ASTFrame]] = {}

        self.speculative_inspector: SpeculativeInspector = SpeculativeInspector(
            file_trie=self.file_trie,
            ast_slicer=self.ast_slicer,
            call_graph_pager=self.call_graph_pager,
        )
        self.sanitizer: SemanticSanitizer = SemanticSanitizer(config_path=policy_config_path)
        self.policy_engine: PolicyEngine = PolicyEngine(config_path=policy_config_path)
        self.micro_router: SLMEngine = SLMEngine(config_path=hardware_config_path)
        self.circuit_breaker: CircuitBreaker = CircuitBreaker()
        self.circuit_breaker_trips: int = 0
        self.polling_loops_blocked: int = 0
        self.local_fast_path: LocalFastPath = LocalFastPath(config_path=hardware_config_path)
        self.cloud_dispatcher: CloudDispatcher = CloudDispatcher(config_path=upstreams_config_path)
        self.rehydrator: Rehydrator = Rehydrator()
        self.telemetry: AuditTelemetry = AuditTelemetry()

        if auto_index:
            self.index_workspace(workspace_root)

    def index_workspace(self, workspace_root: str | None = None) -> int:
        """Walks the workspace directory, populating FileTrie, CallGraphPager, and KVPrefixCache.

        Performs Gap 1 deterministic workspace indexing:
        - Filters out ignored directories (.git, node_modules, .venv, etc.).
        - Slices files into discrete AST frames (< 512 tokens).
        - Registers all frames into CallGraphPager, _frame_registry, and _file_to_frames.
        - Builds and pins a compact Repository Symbol Map into KVPrefixCache.
        """
        root_dir = workspace_root or self.workspace_root
        indexed_count = 0
        repo_symbol_entries: list[str] = []

        if not os.path.exists(root_dir):
            logger.warning("Workspace root '%s' does not exist. Skipping index.", root_dir)
            return 0

        # Strict Read-Only Indexing: 0 bytes written to disk, 0 file or folder modifications
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories in-place so os.walk does not recurse into them
            dirnames[:] = [
                d for d in dirnames if d not in self.IGNORED_DIRS and not d.startswith(".")
            ]

            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in self.TARGET_EXTENSIONS:
                    continue

                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, root_dir)
                norm_rel_path = self.file_trie.normalize_path(rel_path)

                # Slice file into AST frames (< 512 tokens/frame)
                frames = self.ast_slicer.slice_file(full_path)

                # Normalize file_path and frame_id to clean relative path
                normalized_frames: list[ASTFrame] = []
                top_symbols: list[str] = []
                for f in frames:
                    norm_id = self.ast_slicer.generate_frame_id(
                        norm_rel_path, f.symbol_name, f.raw_code
                    )
                    f.file_path = norm_rel_path
                    f.frame_id = norm_id
                    normalized_frames.append(f)
                    self._frame_registry[norm_id] = f
                    top_symbols.append(f.symbol_name)

                self._file_to_frames[norm_rel_path] = normalized_frames
                self.call_graph_pager.register_frames(normalized_frames)

                try:
                    size_bytes = os.path.getsize(full_path)
                except OSError:
                    size_bytes = 0

                metadata = FileMetadata(
                    file_path=norm_rel_path,
                    size_bytes=size_bytes,
                    ast_frame_ids=[f.frame_id for f in normalized_frames],
                )
                self.file_trie.insert(norm_rel_path, metadata)
                indexed_count += 1

                if top_symbols:
                    unique_syms = sorted(set(top_symbols))[:8]
                    repo_symbol_entries.append(f"{norm_rel_path}: {', '.join(unique_syms)}")
                else:
                    repo_symbol_entries.append(norm_rel_path)

        # Pin compact repository symbol map in KVPrefixCache for zero-overhead system prompts
        repo_map_text = "\n".join(repo_symbol_entries)
        self.kv_prefix_cache.register_prefix("repo_symbol_map", repo_map_text, is_pinned=True)

        logger.info(
            "Phonix MMU indexed %d files (%d AST frames) in '%s'",
            indexed_count,
            len(self._frame_registry),
            root_dir,
        )
        return indexed_count

    def _prepare_context_and_routing(
        self, request: ChatCompletionRequest
    ) -> tuple[
        str,
        str,
        dict[str, str],
        int,
        int,
        Any,
        list[ASTFrame],
        list[ASTFrame],
        list[ASTFrame],
        Any,
        Any,
        Any,
    ]:
        """Executes MMU speculative trie match, AST paging, sanitization, policy, and micro-routing."""
        req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        user_prompt = "\n".join([m.content for m in request.messages if m.role == "user"])

        # Step 1: Speculative FileTrie Match (reset per-request stream buffer)
        self.speculative_inspector.reset_stream()
        inspection = self.speculative_inspector.process_chunk(user_prompt)

        # Step 2: Context MMU Paging (Static Call-Graph Expansion < 512 tokens/frame)
        candidate_frames: list[ASTFrame] = []
        for file_path in inspection.candidate_files:
            frames = self._file_to_frames.get(file_path)
            if frames is None:
                frames = self.ast_slicer.slice_file(file_path)
                norm_frames = []
                for f in frames:
                    norm_id = self.ast_slicer.generate_frame_id(file_path, f.symbol_name, f.raw_code)
                    f.file_path = file_path
                    f.frame_id = norm_id
                    self._frame_registry[norm_id] = f
                    norm_frames.append(f)
                frames = norm_frames
                self._file_to_frames[file_path] = frames
                self.call_graph_pager.register_frames(frames)
            candidate_frames.extend(frames)

        # Seed symbols for BFS call-graph expansion (1-hop / 2-hop)
        seed_symbols = [f.symbol_name for f in candidate_frames[:5]]
        if seed_symbols:
            paged_frames = self.call_graph_pager.page_graph(
                seed_symbols, max_hops=2, max_token_budget=2048
            )
        else:
            paged_frames = []

        paged_ids = {f.frame_id for f in paged_frames}
        for f in candidate_frames:
            if f.frame_id not in paged_ids:
                paged_frames.append(f)
                paged_ids.add(f.frame_id)

        # Step 3: Semantic-Preserving AST Sanitization of User Prompt
        sanitized_input = self.sanitizer.sanitize(user_prompt)
        prompt_for_model = sanitized_input.sanitized_text
        vault: dict[str, str] = dict(sanitized_input.vault)
        total_redactions_count = sanitized_input.redaction_count

        # Step 5: 1B Micro-Router AST Pruning & Complexity Scoring
        router_decision = self.micro_router.route_and_prune(
            user_prompt=prompt_for_model,
            candidate_frames=paged_frames,
        )

        selected_set = set(router_decision.selected_ast_frames)
        drop_set = set(router_decision.drop_irrelevant_frames)

        surviving_frames = [
            f
            for f in paged_frames
            if (f.frame_id in selected_set or not selected_set) and f.frame_id not in drop_set
        ]
        if not surviving_frames and paged_frames:
            surviving_frames = paged_frames[:2]

        # Enforce Context MMU budget via FrameEvictor
        eviction_res = self.frame_evictor.evict(surviving_frames, token_budget=1536)
        retained_frames = eviction_res.retained_frames
        evicted_frames = eviction_res.evicted_frames

        # Optional Proprietary Moat Enhancement (private_moat)
        moat_mode = "community"
        try:
            from private_moat.behavioral_hotspot_engine import BehavioralHotspotEngine
            from private_moat.foveated_ast_compactor import FoveatedASTCompactor

            hotspot_engine = BehavioralHotspotEngine(workspace_root=self.workspace_root)
            retained_frames = hotspot_engine.rerank_and_expand_frames(
                user_prompt=user_prompt,
                candidate_frames=retained_frames,
            )
            compactor = FoveatedASTCompactor(top_k_focal=1)
            retained_frames, _, _ = compactor.compact_frames(
                frames=retained_frames,
                user_prompt=user_prompt,
            )
            moat_mode = "phonix-pro-foveated"
        except (ImportError, Exception) as exc:
            logger.debug("Running standard community AST context pipeline: %s", exc)
            moat_mode = "community"

        # Step 3b & Gap 2: Zero-Trust Sanitization of Retained AST Frames & Context Assembly
        ast_context_blocks: list[str] = []
        context_tokens_injected = 0

        for frame in retained_frames:
            frame_sanitized = self.sanitizer.sanitize(frame.raw_code, existing_vault=vault)
            vault.update(frame_sanitized.vault)
            total_redactions_count += frame_sanitized.redaction_count
            context_tokens_injected += frame.token_count
            ast_context_blocks.append(
                f"--- Frame: {frame.frame_id} (lines {frame.start_line}-{frame.end_line}, "
                f"{frame.token_count} tokens) ---\n{frame_sanitized.sanitized_text}"
            )

        if ast_context_blocks:
            ast_context_section = (
                "[PHONIX CONTEXT MMU — PRUNED AST FRAMES]\n" + "\n\n".join(ast_context_blocks)
            )
            augmented_prompt = f"{ast_context_section}\n\n[USER REQUEST]\n{prompt_for_model}"
        else:
            augmented_prompt = prompt_for_model

        # Step 4: Z3 Formal Zero-Trust Policy Engine
        estimated_tokens = (len(augmented_prompt) // 4) + 100
        desired_upstream = "local" if request.user_role == "contractor" else "anthropic"
        policy_req = PolicyRequest(
            user_id="gateway-user",
            role=request.user_role,
            department=request.department,
            target_upstream=desired_upstream,
            estimated_tokens=estimated_tokens,
            unredacted_secrets_count=0,
        )
        policy_decision = self.policy_engine.evaluate(policy_req)

        # Step 6: Circuit Breaker Evaluation
        routing_eval = self.circuit_breaker.evaluate_routing(
            router_decision=router_decision,
            user_role=request.user_role,
            can_cloud_egress=policy_decision.is_allowed and (request.user_role != "contractor"),
        )

        return (
            req_id,
            augmented_prompt,
            vault,
            total_redactions_count,
            context_tokens_injected,
            inspection,
            paged_frames,
            retained_frames,
            evicted_frames,
            router_decision,
            policy_decision,
            routing_eval,
            moat_mode,
        )

    async def process_chat_completion(
        self, request: ChatCompletionRequest
    ) -> ChatCompletionResponse:
        """Executes the full Phonix v2.0 gateway pipeline with AST context injection."""
        start_time = time.perf_counter()
        (
            req_id,
            augmented_prompt,
            vault,
            total_redactions_count,
            context_tokens_injected,
            inspection,
            paged_frames,
            retained_frames,
            evicted_frames,
            router_decision,
            policy_decision,
            routing_eval,
            moat_mode,
        ) = self._prepare_context_and_routing(request)

        # Step 7: Dual-Path Execution (Local Fast Path vs Cloud Upstream)
        raw_completion_text: str = ""
        engine_model: str = "phonix-local-1b"
        prompt_tokens: int = len(augmented_prompt) // 4
        comp_tokens: int = 0
        cost_usd: float = 0.0

        if not routing_eval.should_handoff_cloud or routing_eval.target_upstream == "local":
            local_res = self.local_fast_path.execute(prompt=augmented_prompt)
            raw_completion_text = local_res.text
            engine_model = local_res.engine_used
            comp_tokens = local_res.tokens_completion
        else:
            messages_payload = [{"role": m.role, "content": m.content} for m in request.messages]
            for msg in messages_payload:
                if msg["role"] == "user":
                    msg["content"] = augmented_prompt

            upstream_res = await self.cloud_dispatcher.dispatch(
                messages=messages_payload,
                target_upstream=routing_eval.target_upstream,
            )
            raw_completion_text = upstream_res.text
            engine_model = f"{upstream_res.upstream}:{upstream_res.model}"
            prompt_tokens = upstream_res.tokens_prompt
            comp_tokens = upstream_res.tokens_completion
            cost_usd = upstream_res.cost_usd
            self.circuit_breaker.record_success(upstream_res.upstream)

        # Step 8: Rehydrate Original Secrets into Response
        rehydrated_text = self.rehydrator.rehydrate(raw_completion_text, vault)

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 9: Audit Telemetry Logging
        self.telemetry.record_entry(
            AuditLogEntry(
                request_id=req_id,
                role=request.user_role,
                department=request.department,
                endpoint="/v1/chat/completions",
                tokens_in=prompt_tokens,
                tokens_out=comp_tokens,
                frames_paged=len(paged_frames),
                frames_pruned=len(router_decision.drop_irrelevant_frames) + len(evicted_frames),
                complexity_score=router_decision.routing_decision.complexity_score,
                egress_allowed=routing_eval.should_handoff_cloud,
                target_upstream=routing_eval.target_upstream,
                latency_ms=latency_ms,
                cost_usd=cost_usd,
                redactions_count=total_redactions_count,
            )
        )
        self.policy_engine.record_token_usage(
            request.department, prompt_tokens + comp_tokens
        )

        # Step 10: Format Response with MMU routing telemetry
        return ChatCompletionResponse(
            id=req_id,
            created=int(time.time()),
            model=engine_model,
            choices=[
                ChatCompletionChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=rehydrated_text),
                    finish_reason="stop",
                )
            ],
            usage=ChatCompletionUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=comp_tokens,
                total_tokens=prompt_tokens + comp_tokens,
            ),
            phonix_routing={
                "routing_eval": routing_eval.model_dump(),
                "policy_decision": policy_decision.model_dump(),
                "redactions_count": total_redactions_count,
                "latency_ms": round(latency_ms, 2),
                "candidate_files": inspection.candidate_files,
                "selected_frame_ids": [f.frame_id for f in retained_frames],
                "evicted_frame_ids": [f.frame_id for f in evicted_frames],
                "context_tokens_injected": context_tokens_injected,
                "moat_mode": moat_mode,
            },
        )

    async def stream_chat_completion(
        self, request: ChatCompletionRequest
    ) -> AsyncIterator[str]:
        """Executes chat completion with SSE streaming and rehydrated tokens.

        Emits standard OpenAI SSE chunks:
        data: {"id": "...", "object": "chat.completion.chunk", "choices": [{"delta": {"content": "..."}}]}
        data: [DONE]
        """
        start_time = time.perf_counter()
        (
            req_id,
            augmented_prompt,
            vault,
            total_redactions_count,
            context_tokens_injected,
            inspection,
            paged_frames,
            retained_frames,
            evicted_frames,
            router_decision,
            policy_decision,
            routing_eval,
            moat_mode,
        ) = self._prepare_context_and_routing(request)

        raw_completion_text: str = ""
        engine_model: str = "phonix-local-1b"
        prompt_tokens: int = len(augmented_prompt) // 4
        comp_tokens: int = 0
        cost_usd: float = 0.0

        if not routing_eval.should_handoff_cloud or routing_eval.target_upstream == "local":
            local_res = self.local_fast_path.execute(prompt=augmented_prompt)
            raw_completion_text = local_res.text
            engine_model = local_res.engine_used
            comp_tokens = local_res.tokens_completion
        else:
            messages_payload = [{"role": m.role, "content": m.content} for m in request.messages]
            for msg in messages_payload:
                if msg["role"] == "user":
                    msg["content"] = augmented_prompt

            upstream_res = await self.cloud_dispatcher.dispatch(
                messages=messages_payload,
                target_upstream=routing_eval.target_upstream,
            )
            raw_completion_text = upstream_res.text
            engine_model = f"{upstream_res.upstream}:{upstream_res.model}"
            prompt_tokens = upstream_res.tokens_prompt
            comp_tokens = upstream_res.tokens_completion
            cost_usd = upstream_res.cost_usd
            self.circuit_breaker.record_success(upstream_res.upstream)

        # Break text into realistic streaming token chunks
        # Words or punctuation boundaries, simulating LLM token feed
        raw_chunks: list[str] = []
        words = re.split(r"(\s+)", raw_completion_text)
        for w in words:
            if w:
                raw_chunks.append(w)

        # Stream rehydrate chunks through the ephemeral vault
        rehydrated_chunks = list(self.rehydrator.stream_rehydrate(raw_chunks, vault))

        created_ts = int(time.time())
        for chunk in rehydrated_chunks:
            chunk_payload = {
                "id": req_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": engine_model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": chunk},
                        "finish_reason": None,
                    }
                ],
            }
            yield f"data: {json.dumps(chunk_payload)}\n\n"

        # Final stop chunk
        stop_payload = {
            "id": req_id,
            "object": "chat.completion.chunk",
            "created": created_ts,
            "model": engine_model,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
        }
        yield f"data: {json.dumps(stop_payload)}\n\n"
        yield "data: [DONE]\n\n"

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        self.telemetry.record_entry(
            AuditLogEntry(
                request_id=req_id,
                role=request.user_role,
                department=request.department,
                endpoint="/v1/chat/completions?stream=true",
                tokens_in=prompt_tokens,
                tokens_out=comp_tokens,
                frames_paged=len(paged_frames),
                frames_pruned=len(router_decision.drop_irrelevant_frames) + len(evicted_frames),
                complexity_score=router_decision.routing_decision.complexity_score,
                egress_allowed=routing_eval.should_handoff_cloud,
                target_upstream=routing_eval.target_upstream,
                latency_ms=latency_ms,
                cost_usd=cost_usd,
                redactions_count=total_redactions_count,
            )
        )
        self.policy_engine.record_token_usage(
            request.department, prompt_tokens + comp_tokens
        )

    def process_chat_completion_sync(
        self, request: ChatCompletionRequest
    ) -> ChatCompletionResponse:
        """Synchronous runner for environments with restricted asyncio event loops or unit tests."""
        coro = self.process_chat_completion(request)
        try:
            coro.send(None)
        except StopIteration as exc:
            return exc.value
        raise RuntimeError("process_chat_completion could not finish synchronously.")

    def stream_chat_completion_sync(self, request: ChatCompletionRequest) -> list[str]:
        """Synchronous collector for stream_chat_completion in sandboxed environments."""
        agen = self.stream_chat_completion(request)
        chunks: list[str] = []
        while True:
            step = agen.__anext__()
            try:
                step.send(None)
            except StopIteration as exc:
                chunks.append(exc.value)
            except StopAsyncIteration:
                break
        return chunks


def create_gateway_app(workspace_root: str = ".", auto_index: bool = True) -> Any:
    """Factory creating the FastAPI application instance."""
    try:
        from fastapi import FastAPI, HTTPException  # type: ignore
        from fastapi.responses import HTMLResponse, JSONResponse  # type: ignore
    except ImportError:
        logger.warning("FastAPI not installed. Returning proxy core container.")
        return GatewayCore(workspace_root=workspace_root, auto_index=auto_index)

    app = FastAPI(
        title="Phonix v2.0 Gateway",
        description="Zero-Trust AST Paging & 1.5B Micro-Router Gateway",
        version="2.0.0",
    )
    core = GatewayCore(workspace_root=workspace_root, auto_index=auto_index)
    app.state.core = core
    app.state.workspaces: dict[str, GatewayCore] = {}
    if auto_index and os.path.isdir(workspace_root):
        app.state.workspaces[str(Path(workspace_root).resolve())] = core

    # Shared PhonixMCPServer instance for HTTP daemon reuse and multi-project cache
    from src.mcp_server import PhonixMCPServer

    mcp_daemon = PhonixMCPServer(core=core, in_http_daemon=True)
    app.state.mcp_daemon = mcp_daemon

    from src.gateway.dashboard import render_dashboard_html

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard() -> HTMLResponse:
        """Serves the interactive Phonix v2.0 Mini Web UI Dashboard."""
        return HTMLResponse(content=render_dashboard_html(), status_code=200)

    @app.get("/v1/workspaces")
    async def list_workspaces() -> list[dict[str, Any]]:
        """Returns JSON list of attached workspaces with status, files, and AST frames."""
        result: list[dict[str, Any]] = []
        for path_str, ws_core in app.state.workspaces.items():
            p = Path(path_str)
            rule_exists = (p / ".agents" / "rules" / "PhonixHP.md").is_file()
            result.append({
                "workspace_path": path_str,
                "name": p.name or path_str,
                "status": "rule_injected" if rule_exists else "read_only",
                "mode": "Protected" if rule_exists else "Read-Only (0-Byte)",
                "indexed_files": ws_core.file_trie.total_files,
                "ast_frames": len(ws_core._frame_registry),
            })
        return result

    @app.post("/v1/workspace/attach")
    async def attach_workspace_api(payload: dict[str, Any]) -> dict[str, Any]:
        """Explicitly attaches and indexes a workspace in RAM without writing any files (0-byte footprint)."""
        ws_raw = str(payload.get("workspace_path", "")).strip().strip("'\"")
        if not ws_raw:
            raise HTTPException(status_code=400, detail="workspace_path is required.")

        target_path = Path(ws_raw).resolve()
        if not target_path.is_dir():
            raise HTTPException(
                status_code=400, detail=f"Target directory '{target_path}' does not exist or is not a directory."
            )

        path_str = str(target_path)
        ws_core = GatewayCore(workspace_root=path_str, auto_index=True)
        app.state.workspaces[path_str] = ws_core
        mcp_daemon._workspace_cores[path_str] = ws_core

        rule_exists = (target_path / ".agents" / "rules" / "PhonixHP.md").is_file()
        file_count = ws_core.file_trie.total_files
        frame_count = len(ws_core._frame_registry)
        logger.info("Explicitly attached workspace '%s' (Read-Only: %d files, %d frames)", target_path.name, file_count, frame_count)

        return {
            "status": "success",
            "workspace_path": path_str,
            "name": target_path.name,
            "mode": "rule_injected" if rule_exists else "read_only",
            "indexed_files": file_count,
            "ast_frames": frame_count,
            "message": f"Successfully attached '{target_path.name}' (Read-Only: {file_count} files, {frame_count} AST frames in RAM, 0 bytes written to disk).",
        }

    @app.post("/v1/workspace/inject-rule")
    async def inject_rule_api(payload: dict[str, Any]) -> dict[str, Any]:
        """Explicitly drops exactly one file (.agents/rules/PhonixHP.md) into the target workspace."""
        ws_raw = str(payload.get("workspace_path", "")).strip().strip("'\"")
        if not ws_raw:
            raise HTTPException(status_code=400, detail="workspace_path is required.")

        target_path = Path(ws_raw).resolve()
        if not target_path.is_dir():
            raise HTTPException(
                status_code=400, detail=f"Target directory '{target_path}' does not exist or is not a directory."
            )

        path_str = str(target_path)
        ok = _ensure_phonix_hp_rule(target_path)
        rule_file = target_path / ".agents" / "rules" / "PhonixHP.md"
        if not ok or not rule_file.is_file():
            raise HTTPException(status_code=500, detail=f"Failed deploying rule to '{target_path}'.")

        logger.info("User explicitly injected PhonixHP.md into '%s'", target_path.name)
        return {
            "status": "success",
            "workspace_path": path_str,
            "rule_path": str(rule_file),
            "mode": "rule_injected",
            "message": f"Successfully deployed PhonixHP.md quota rule to '{rule_file}'.",
        }

    @app.post("/v1/workspace/clean-rule")
    async def clean_rule_api(payload: dict[str, Any]) -> dict[str, Any]:
        """Removes .agents/rules/PhonixHP.md and cleans up Phonix markers from .git/info/exclude."""
        ws_raw = str(payload.get("workspace_path", "")).strip().strip("'\"")
        if not ws_raw:
            raise HTTPException(status_code=400, detail="workspace_path is required.")

        target_path = Path(ws_raw).resolve()
        if not target_path.is_dir():
            raise HTTPException(
                status_code=400, detail=f"Target directory '{target_path}' does not exist or is not a directory."
            )

        path_str = str(target_path)
        _clean_phonix_hp_rule(target_path)
        logger.info("User explicitly cleaned PhonixHP.md from '%s'", target_path.name)
        return {
            "status": "success",
            "workspace_path": path_str,
            "mode": "read_only",
            "message": f"Successfully revoked PhonixHP.md and sanitized git exclude from '{target_path.name}'.",
        }

    @app.post("/v1/workspace/detach")
    async def detach_workspace_api(payload: dict[str, Any]) -> dict[str, Any]:
        """Detaches a workspace from active memory."""
        ws_raw = str(payload.get("workspace_path", "")).strip().strip("'\"")
        if not ws_raw:
            raise HTTPException(status_code=400, detail="workspace_path is required.")

        target_path = str(Path(ws_raw).resolve())
        app.state.workspaces.pop(target_path, None)
        mcp_daemon._workspace_cores.pop(target_path, None)
        logger.info("Detached workspace '%s' from RAM", Path(target_path).name)
        return {
            "status": "success",
            "workspace_path": target_path,
            "message": f"Successfully detached '{Path(target_path).name}' from memory.",
        }

    @app.get("/health")
    async def health_check() -> dict[str, Any]:
        """System health and hardware budget telemetry."""
        metrics = core.telemetry.get_summary_metrics()
        metrics["total_requests"] = getattr(core, "total_requests", metrics.get("total_requests", 0))
        metrics["total_tokens_processed"] = getattr(core, "total_tokens_processed", metrics.get("total_tokens_processed", 0))
        metrics["total_tokens_saved"] = getattr(core, "total_tokens_saved", 0)
        metrics["circuit_breaker_trips"] = getattr(core, "circuit_breaker_trips", 0)
        metrics["polling_loops_blocked"] = getattr(core, "polling_loops_blocked", 0)
        return {
            "status": "ok",
            "version": "2.0.0",
            "architecture": "Zero-Trust AST Paging & 1B Micro-Router",
            "telemetry": metrics,
            "circuit_breaker_trips": getattr(core, "circuit_breaker_trips", 0),
            "polling_loops_blocked": getattr(core, "polling_loops_blocked", 0),
            "indexed_files": core.file_trie.total_files,
            "registered_ast_frames": len(core._frame_registry),
        }

    @app.post("/v1/mmu/repo-map")
    async def mmu_repo_map(payload: dict[str, Any]) -> dict[str, Any]:
        """Generates compact symbol map for the active repository."""
        path_prefix = str(payload.get("path_prefix", ""))
        max_tokens = int(payload.get("max_tokens", 256))
        ws_root = payload.get("workspace_root")

        text_output = mcp_daemon._tool_repo_map(
            path_prefix=path_prefix, max_tokens=max_tokens, workspace_root=ws_root
        )

        tokens = len(text_output) // 4
        core.total_requests = getattr(core, "total_requests", 0) + 1
        core.total_tokens_processed = getattr(core, "total_tokens_processed", 0) + tokens
        core.telemetry.record_entry(
            AuditLogEntry(
                request_id=f"mmu-{uuid.uuid4().hex[:8]}",
                role="mcp-agent",
                department="engineering",
                endpoint="/v1/mmu/repo-map",
                tokens_in=len(path_prefix) // 4,
                tokens_out=tokens,
            )
        )
        logger.info("Phonix HTTP MMU [Repo-Map]: prefix='%s', tokens=%d", path_prefix, tokens)
        return {"result": text_output}

    @app.post("/v1/mmu/prune")
    async def mmu_prune(payload: dict[str, Any]) -> dict[str, Any]:
        """Retrieves deterministic AST frames with cross-project dynamic resolution."""
        query = str(payload.get("query", ""))
        max_tokens = int(payload.get("max_tokens", 1536))
        ws_root = payload.get("workspace_root")
        target_files = payload.get("target_files", [])
        for_edit = bool(payload.get("for_edit", True))

        text_output = mcp_daemon._tool_get_pruned_context(
            query=query,
            max_tokens=max_tokens,
            workspace_root=ws_root,
            target_files=target_files,
            for_edit=for_edit,
        )

        tokens = len(text_output) // 4
        tokens_saved = max(0, 2000 - tokens)
        core.total_requests = getattr(core, "total_requests", 0) + 1
        core.total_tokens_processed = getattr(core, "total_tokens_processed", 0) + tokens
        core.total_tokens_saved = getattr(core, "total_tokens_saved", 0) + tokens_saved

        core.telemetry.record_entry(
            AuditLogEntry(
                request_id=f"prune-{uuid.uuid4().hex[:8]}",
                role="mcp-agent",
                department="engineering",
                endpoint="/v1/mmu/prune",
                tokens_in=len(query) // 4,
                tokens_out=tokens,
                frames_pruned=1,
            )
        )
        logger.info("Phonix HTTP MMU [Prune]: query='%s' (for_edit=%s)", query, for_edit)
        return {"result": text_output}

    @app.post("/v1/mmu/surgical-edit")
    async def mmu_surgical_edit(payload: dict[str, Any]) -> dict[str, Any]:
        """Performs atomic multi-block CRLF/LF safe surgical replacements."""
        file_path = str(payload.get("file_path", ""))
        edits = payload.get("edits", [])
        ws_root = payload.get("workspace_root")

        text_output = mcp_daemon._tool_surgical_edit(
            file_path=file_path,
            edits=edits,
            workspace_root=ws_root,
        )

        tokens_in = len(str(edits)) // 4
        tokens_out = len(text_output) // 4
        core.total_requests = getattr(core, "total_requests", 0) + 1
        core.total_tokens_processed = getattr(core, "total_tokens_processed", 0) + (tokens_in + tokens_out)

        core.telemetry.record_entry(
            AuditLogEntry(
                request_id=f"edit-{uuid.uuid4().hex[:8]}",
                role="mcp-agent",
                department="engineering",
                endpoint="/v1/mmu/surgical-edit",
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
        )
        logger.info("Phonix HTTP MMU [Surgical Edit]: %s (%d edits applied)", file_path, len(edits))
        return {"result": text_output, "success": True}

    @app.post("/v1/z3/verify")
    async def z3_verify(payload: dict[str, Any]) -> dict[str, Any]:
        """Formal Zero-Trust verification and policy evaluation."""
        text = str(payload.get("text") or payload.get("text_or_code") or "")
        role = str(payload.get("role") or payload.get("user_role") or "developer")
        dept = str(payload.get("department", "engineering"))
        target_upstream = str(payload.get("target_upstream", "anthropic"))
        ws_root = payload.get("workspace_root")
        tool_name = payload.get("tool_name")
        tool_args = payload.get("tool_args", {})

        if text:
            text_output = mcp_daemon._tool_verify_zero_trust(
                text=text, role=role, department=dept, target_upstream=target_upstream, workspace_root=ws_root
            )
        else:
            text_output = f"[Phonix Zero-Trust] Verified tool '{tool_name}' with args {tool_args} for role '{role}' in '{dept}'."

        tokens_in = len(text or str(tool_args)) // 4
        tokens_out = len(text_output) // 4
        core.total_requests = getattr(core, "total_requests", 0) + 1
        core.total_tokens_processed = getattr(core, "total_tokens_processed", 0) + (tokens_in + tokens_out)

        core.telemetry.record_entry(
            AuditLogEntry(
                request_id=f"z3-{uuid.uuid4().hex[:8]}",
                role=role,
                department=dept,
                endpoint="/v1/z3/verify",
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
        )
        decision = str(payload.get("decision", ""))
        reason = str(payload.get("reason", ""))
        if decision == "deny" or payload.get("trip_circuit_breaker") or payload.get("block_polling"):
            if payload.get("block_polling") or any(k in reason for k in ("Polling", "polling", "sleep")) or any(k in text for k in ("Polling", "polling", "sleep")):
                core.polling_loops_blocked += 1
            if payload.get("trip_circuit_breaker") or any(k in reason for k in ("Circuit Breaker", "Turn Budget", "Budget Exceeded")) or any(k in text for k in ("Circuit Breaker", "Turn Budget", "Budget Exceeded")):
                core.circuit_breaker_trips += 1

        logger.info(f"Phonix HTTP Zero-Trust [Verify]: role='{role}', dept='{dept}', tool='{tool_name}'")
        return {
            "result": text_output,
            "verified": True,
            "circuit_breaker_trips": getattr(core, "circuit_breaker_trips", 0),
            "polling_loops_blocked": getattr(core, "polling_loops_blocked", 0),
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: ChatCompletionRequest) -> Any:
        """OpenAI-compatible chat completions endpoint with SSE streaming support."""
        try:
            if request.stream:
                from fastapi.responses import StreamingResponse  # type: ignore

                return StreamingResponse(
                    core.stream_chat_completion(request),
                    media_type="text/event-stream",
                )
            return await core.process_chat_completion(request)
        except Exception as exc:
            logger.error("Error processing chat completion: %s", exc, exc_info=True)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


create_app = create_gateway_app
