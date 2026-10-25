"""Local 1B SLM Inference Engine for Phonix v2.0 Micro-Router.

Executes quantized 1B parameters SLM (Llama-3.2-1B-Instruct Q4_K_M) within a strict
1.2GB VRAM envelope. Constrains decoding via GBNF grammar to guarantee valid JSON schema.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from src.micro_router.gbnf_enforcer import GBNFEnforcer, RouterDecisionOutput

if TYPE_CHECKING:
    from src.mmu.ast_slicer import ASTFrame

logger = logging.getLogger(__name__)


class SLMEngine:
    """Manages the 1B/1.5B SLM instance with strict 1.2GB VRAM cap and GBNF-constrained decoding.

    Performs exactly two responsibilities:
    1. Prunes candidate AST frames to preserve only task-critical context.
    2. Computes normalized task complexity score and cloud handoff flag.
    """

    ROUTER_JSON_SCHEMA: dict[str, Any] = {
        "type": "object",
        "properties": {
            "task_category": {
                "type": "string",
                "enum": [
                    "boilerplate",
                    "refactor",
                    "debugging",
                    "architecture",
                    "security_audit",
                    "general_qa",
                ],
            },
            "complexity_score": {"type": "number"},
            "requires_cloud_handoff": {"type": "boolean"},
            "selected_ast_frames": {"type": "array", "items": {"type": "string"}},
            "dropped_ast_frames": {"type": "array", "items": {"type": "string"}},
            "reasoning_summary": {"type": "string"},
        },
        "required": [
            "task_category",
            "complexity_score",
            "requires_cloud_handoff",
            "selected_ast_frames",
            "dropped_ast_frames",
            "reasoning_summary",
        ],
    }

    SYSTEM_PROMPT: str = (
        "You are the Phonix v2.0 Micro-Router. Your task is to inspect candidate AST frames and user prompt, "
        "select relevant frames, drop irrelevant frames, classify the task, and calculate a complexity score [0.0 - 1.0]. "
        "Strictly adhere to the output JSON schema."
    )

    def __init__(
        self,
        model_path: str = "models/Llama-3.2-1B-Instruct-Q4_K_M.gguf",
        vram_budget_mb: float = 1228.8,
        n_ctx: int = 4096,
        gpu_layers: int = 16,
        config_path: str | Path | None = "config/hardware_profile.yaml",
        ollama_url: str | None = None,
        ollama_model: str = "qwen2.5-coder:1.5b",
    ) -> None:
        self.model_path: str = model_path
        self.vram_budget_mb: float = vram_budget_mb
        self.n_ctx: int = n_ctx
        self.gpu_layers: int = gpu_layers
        self.ollama_url: str = ollama_url if ollama_url is not None else ""
        self.ollama_model: str = ollama_model

        # Dynamically load hardware settings from YAML if available
        if config_path and yaml is not None:
            resolved_path = Path(config_path)
            if resolved_path.is_file():
                try:
                    with open(resolved_path, "r", encoding="utf-8") as f:
                        cfg = yaml.safe_load(f) or {}
                    slm_cfg = cfg.get("router_slm", {})
                    if isinstance(slm_cfg, dict):
                        self.model_path = slm_cfg.get("local_model_path", self.model_path)
                        self.vram_budget_mb = float(slm_cfg.get("vram_budget_mb", self.vram_budget_mb))
                        self.n_ctx = int(slm_cfg.get("context_window_tokens", self.n_ctx))
                        self.gpu_layers = int(slm_cfg.get("gpu_layers_offload", self.gpu_layers))
                        if not self.ollama_url and "ollama_url" in slm_cfg:
                            self.ollama_url = str(slm_cfg["ollama_url"])
                        if ollama_model == "qwen2.5-coder:1.5b" and "ollama_model" in slm_cfg:
                            self.ollama_model = str(slm_cfg["ollama_model"])
                except Exception as exc:
                    logger.warning("Failed to load hardware config from %s: %s", resolved_path, exc)

        # Allow environment variable overrides
        if os.environ.get("PHONIX_OLLAMA_URL"):
            self.ollama_url = os.environ["PHONIX_OLLAMA_URL"]
        if os.environ.get("PHONIX_OLLAMA_MODEL"):
            self.ollama_model = os.environ["PHONIX_OLLAMA_MODEL"]
        if ollama_url is not None:
            self.ollama_url = ollama_url

        # Fast test/offline isolation toggle
        is_test_env = (
            "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules
        ) and os.environ.get("PHONIX_LIVE_OLLAMA_TEST") != "1"
        if os.environ.get("PHONIX_DISABLE_OLLAMA") == "1" or is_test_env:
            if ollama_url is None:
                self.ollama_url = ""

        self.enforcer: GBNFEnforcer = GBNFEnforcer()
        self._llm: Any = None
        self._is_loaded: bool = False

    def load_model(self) -> bool:
        """Loads the local GGUF model into memory using llama-cpp-python.

        If llama-cpp-python is unavailable or model weights are missing,
        logs warning and marks engine for heuristic fallback mode.
        """
        try:
            from llama_cpp import Llama  # type: ignore

            logger.info(
                "Loading 1B SLM from %s with %d GPU layers (VRAM cap: %.1f MB)",
                self.model_path,
                self.gpu_layers,
                self.vram_budget_mb,
            )
            self._llm = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_gpu_layers=self.gpu_layers,
                verbose=False,
            )
            self._is_loaded = True
            return True
        except (ImportError, Exception) as exc:
            logger.warning(
                "llama-cpp-python or model weight unavailable (%s). Falling back to heuristic routing.",
                exc,
            )
            self._is_loaded = False
            return False

    def route_and_prune(
        self, user_prompt: str, candidate_frames: list[ASTFrame]
    ) -> RouterDecisionOutput:
        """Generates GBNF-constrained routing and AST context pruning decision.

        TODO (Phonix v2.0):
        - Implement zero-copy prompt caching by passing KV prefix pointer directly to llama-cpp.
        - Stream grammar logits mask during speculative token decoding.
        """
        candidate_ids = [f.frame_id for f in candidate_frames]

        if not self._is_loaded or self._llm is None:
            # Check if local Ollama endpoint is configured for router inference
            if self.ollama_url:
                try:
                    import httpx  # type: ignore

                    endpoint = self.ollama_url.rstrip("/")
                    if not endpoint.endswith("/api/generate"):
                        endpoint = f"{endpoint}/api/generate"

                    formatted_prompt = self._format_prompt(user_prompt, candidate_frames)
                    payload: dict[str, Any] = {
                        "model": self.ollama_model,
                        "prompt": formatted_prompt,
                        "format": self.ROUTER_JSON_SCHEMA,
                        "stream": False,
                        "options": {"temperature": 0.0},
                    }
                    with httpx.Client(timeout=3.0) as client:
                        resp = client.post(endpoint, json=payload)
                        # Fallback for Ollama versions that only accept "json" string
                        if resp.status_code == 400:
                            payload["format"] = "json"
                            resp = client.post(endpoint, json=payload)

                        if resp.status_code == 200:
                            raw_json = resp.json().get("response", "")
                            decision = self.enforcer.parse_and_validate(raw_json)

                            # Sanitize frame sets to ensure only valid candidate IDs exist
                            valid_candidate_set = set(candidate_ids)
                            decision.selected_ast_frames = [
                                fid for fid in decision.selected_ast_frames if fid in valid_candidate_set
                            ]
                            decision.dropped_ast_frames = [
                                fid for fid in decision.dropped_ast_frames if fid in valid_candidate_set
                            ]

                            # Fallback if SLM wiped out all frames while candidates were present
                            if not decision.selected_ast_frames and candidate_frames:
                                fallback = self.enforcer.create_fallback_decision(
                                    candidate_frames=candidate_frames, prompt=user_prompt
                                )
                                decision.selected_ast_frames = fallback.selected_ast_frames
                                decision.dropped_ast_frames = fallback.dropped_ast_frames

                            return decision
                except Exception as exc:
                    logger.debug("Ollama router inference skipped/failed: %s", exc)

            # Deterministic heuristic fallback when weights are not present
            return self.enforcer.create_fallback_decision(
                candidate_frames=candidate_frames, prompt=user_prompt
            )

        try:
            from llama_cpp import LlamaGrammar  # type: ignore

            grammar_text = self.enforcer.load_grammar_text()
            grammar = LlamaGrammar.from_string(grammar_text)

            formatted_prompt = self._format_prompt(user_prompt, candidate_frames)

            response = self._llm.create_completion(
                prompt=formatted_prompt,
                max_tokens=256,
                temperature=0.0,
                grammar=grammar,
            )

            raw_text = response["choices"][0]["text"]
            return self.enforcer.parse_and_validate(raw_text)

        except Exception as exc:
            logger.error("Error executing GBNF-constrained SLM generation: %s", exc)
            return self.enforcer.create_fallback_decision(
                candidate_frames=candidate_frames, prompt=user_prompt
            )

    def _format_prompt(self, user_prompt: str, candidate_frames: list[ASTFrame]) -> str:
        """Constructs compact input prompt for 1B/1.5B SLM router."""
        frames_summary = [
            {"id": f.frame_id, "symbol": f.symbol_name, "tokens": f.token_count}
            for f in candidate_frames
        ]
        guidelines = (
            "CRITICAL INSTRUCTIONS:\n"
            "- selected_ast_frames and dropped_ast_frames MUST ONLY contain exact IDs from Candidate Frames.\n"
            "- Every candidate ID must be categorized into either selected_ast_frames or dropped_ast_frames.\n"
            "- complexity_score MUST be a float between 0.0 and 1.0 (>= 0.7 sets requires_cloud_handoff: true; < 0.7 sets requires_cloud_handoff: false).\n"
            "- task_category MUST be one of: boilerplate, refactor, debugging, architecture, security_audit, general_qa.\n"
            "- Output valid JSON strictly following the schema."
        )
        return (
            f"<|system|>\n{self.SYSTEM_PROMPT}\n{guidelines}\n"
            f"<|user|>\nUser Request: {user_prompt}\n"
            f"Candidate Frames: {json.dumps(frames_summary)}\n"
            f"<|assistant|>\n"
        )
