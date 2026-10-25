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
        self.local_fast_path: LocalFastPath = LocalFastPath()
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


def create_gateway_app(workspace_root: str = ".") -> Any:
    """Factory creating the FastAPI application instance."""
    try:
        from fastapi import FastAPI, HTTPException  # type: ignore
        from fastapi.responses import JSONResponse  # type: ignore
    except ImportError:
        logger.warning("FastAPI not installed. Returning proxy core container.")
        return GatewayCore(workspace_root=workspace_root, auto_index=True)

    app = FastAPI(
        title="Phonix v2.0 Gateway",
        description="Zero-Trust AST Paging & 1B Micro-Router Gateway",
        version="2.0.0",
    )
    core = GatewayCore(workspace_root=workspace_root, auto_index=True)

    @app.get("/health")
    async def health_check() -> dict[str, Any]:
        """System health and hardware budget telemetry."""
        return {
            "status": "ok",
            "version": "2.0.0",
            "architecture": "Zero-Trust AST Paging & 1B Micro-Router",
            "telemetry": core.telemetry.get_summary_metrics(),
            "indexed_files": core.file_trie.total_files,
            "registered_ast_frames": len(core._frame_registry),
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
