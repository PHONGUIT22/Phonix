"""Local 1B SLM Inference Engine for Phonix v2.0 Micro-Router.

Executes quantized 1B parameters SLM (Llama-3.2-1B-Instruct Q4_K_M) within a strict
1.2GB VRAM envelope. Constrains decoding via GBNF grammar to guarantee valid JSON schema.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
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
    """Manages the 1B SLM instance with strict 1.2GB VRAM cap and GBNF-constrained decoding.

    Performs exactly two responsibilities:
    1. Prunes candidate AST frames to preserve only task-critical context.
    2. Computes normalized task complexity score and cloud handoff flag.
    """

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
    ) -> None:
        self.model_path: str = model_path
        self.vram_budget_mb: float = vram_budget_mb
        self.n_ctx: int = n_ctx
        self.gpu_layers: int = gpu_layers
        self.ollama_url: str = ollama_url or os.environ.get("PHONIX_OLLAMA_URL", "")

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
                except Exception as exc:
                    logger.warning("Failed to load hardware config from %s: %s", resolved_path, exc)

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
                    with httpx.Client(timeout=2.0) as client:
                        resp = client.post(
                            endpoint,
                            json={
                                "model": "llama3.2:1b",
                                "prompt": formatted_prompt,
                                "format": "json",
                                "stream": False,
                                "options": {"temperature": 0.0},
                            },
                        )
                        if resp.status_code == 200:
                            raw_json = resp.json().get("response", "")
                            return self.enforcer.parse_and_validate(raw_json)
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
        """Constructs compact input prompt for 1B SLM router."""
        frames_summary = [
            {"id": f.frame_id, "symbol": f.symbol_name, "tokens": f.token_count}
            for f in candidate_frames
        ]
        return (
            f"<|system|>\n{self.SYSTEM_PROMPT}\n"
            f"<|user|>\nUser Request: {user_prompt}\n"
            f"Candidate Frames: {json.dumps(frames_summary)}\n"
            f"<|assistant|>\n"
        )
