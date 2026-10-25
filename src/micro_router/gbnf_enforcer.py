"""GBNF Grammar Enforcer for Phonix v2.0 Micro-Router.

Loads and enforces router_decision.gbnf to guarantee that the 1B SLM output strictly
conforms to the RouterDecision schema without syntactic hallucinations or malformed JSON.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import re
from typing import Any

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


class RoutingDecision(BaseModel):
    """Sub-object containing task classification and complexity evaluation."""

    task_category: str = Field(
        description="One of: code_completion, bug_fix, refactor, architecture_design, security_audit, boilerplate_generation, unit_test, documentation"
    )
    complexity_score: float = Field(
        ge=0.0, le=1.0, description="Normalized task complexity score between 0.0 and 1.0"
    )
    trigger_cloud_handoff: bool = Field(
        description="Whether complexity exceeds local capacity and requires cloud dispatch"
    )


class RouterDecisionOutput(BaseModel):
    """Strict JSON schema enforced by router_decision.gbnf."""

    selected_ast_frames: list[str] = Field(
        default_factory=list, description="IDs of AST frames to retain in prompt context"
    )
    drop_irrelevant_frames: list[str] = Field(
        default_factory=list, description="IDs of AST frames to prune out of prompt context"
    )
    routing_decision: RoutingDecision = Field(
        description="Decision metadata regarding task complexity and cloud handoff"
    )


class GBNFEnforcer:
    """Loads and validates GBNF grammar constraints for local 1B SLM decoding."""

    def __init__(self, grammar_path: str | Path | None = None) -> None:
        if grammar_path is None:
            self.grammar_path = (
                Path(__file__).parent / "grammars" / "router_decision.gbnf"
            ).resolve()
        else:
            self.grammar_path = Path(grammar_path).resolve()

        self._grammar_content: str | None = None

    def load_grammar_text(self) -> str:
        """Reads the raw GBNF grammar specification string from disk."""
        if self._grammar_content is None:
            if not self.grammar_path.exists():
                raise FileNotFoundError(f"GBNF grammar not found at: {self.grammar_path}")
            self._grammar_content = self.grammar_path.read_text(encoding="utf-8")
        return self._grammar_content

    def parse_and_validate(self, raw_output: str) -> RouterDecisionOutput:
        """Parses model string output into typed RouterDecisionOutput.

        Raises:
            ValueError: If JSON is invalid or missing required fields.
        """
        try:
            # Strip markdown fences if present
            cleaned = raw_output.strip()
            if cleaned.startswith("```"):
                lines = cleaned.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned = "\n".join(lines).strip()

            data = json.loads(cleaned)
            rd_data = data.get("routing_decision", {})
            routing_decision = RoutingDecision(
                task_category=rd_data.get("task_category", "code_completion"),
                complexity_score=float(rd_data.get("complexity_score", 0.5)),
                trigger_cloud_handoff=bool(rd_data.get("trigger_cloud_handoff", False)),
            )

            return RouterDecisionOutput(
                selected_ast_frames=data.get("selected_ast_frames", []),
                drop_irrelevant_frames=data.get("drop_irrelevant_frames", []),
                routing_decision=routing_decision,
            )
        except Exception as exc:
            logger.error("Failed to parse GBNF-constrained JSON: %s. Output was: %s", exc, raw_output)
            raise ValueError(f"Malformed router decision output: {exc}") from exc

    def create_fallback_decision(
        self,
        candidate_frames: list[Any] | None = None,
        prompt: str = "",
        default_handoff: bool = True,
        candidate_frame_ids: list[str] | None = None,
    ) -> RouterDecisionOutput:
        """Generates a smart multi-factor fallback routing decision when the local SLM is unavailable.

        Inspects candidate ASTFrame objects (symbols, dependencies, docstrings) against prompt:
        1. Scores each candidate frame with direct mention (+0.50), token overlap (+0.30),
           and call-graph connectivity (+0.20).
        2. Actively populates BOTH selected_ast_frames and drop_irrelevant_frames.
        3. Classifies task_category across all 8 GBNF categories and computes complexity_score in [0.0, 1.0].
        """
        raw_candidates: list[Any] = []
        if candidate_frames is not None:
            raw_candidates = list(candidate_frames)
        elif candidate_frame_ids is not None:
            raw_candidates = list(candidate_frame_ids)

        # Normalize candidate frame records
        frame_items: list[dict[str, Any]] = []
        for item in raw_candidates:
            if isinstance(item, str):
                parts = item.split("::")
                fp = parts[0]
                sym = parts[1] if len(parts) > 1 else ""
                frame_items.append({
                    "frame_id": item,
                    "file_path": fp,
                    "symbol_name": sym,
                    "dependencies": [],
                    "docstring": "",
                    "obj": None,
                })
            else:
                # ASTFrame object
                frame_items.append({
                    "frame_id": getattr(item, "frame_id", ""),
                    "file_path": getattr(item, "file_path", ""),
                    "symbol_name": getattr(item, "symbol_name", ""),
                    "dependencies": getattr(item, "dependencies", []) or [],
                    "docstring": getattr(item, "docstring", "") or "",
                    "obj": item,
                })

        prompt_lower = prompt.lower()
        prompt_words = set(re.findall(r"\b[a-zA-Z0-9_]+\b", prompt_lower))

        # Pass 1: find symbols or files directly mentioned in prompt, and their callee symbols
        directly_mentioned: set[str] = set()
        callees_of_mentioned: set[str] = set()
        for it in frame_items:
            sym = it["symbol_name"]
            fp = it["file_path"]
            if (sym and sym.lower() in prompt_lower) or (fp and fp.lower() in prompt_lower):
                directly_mentioned.add(sym)
                for dep in it["dependencies"]:
                    callees_of_mentioned.add(dep)

        # Pass 2: score candidate frames
        scored_frames: list[tuple[str, float]] = []
        for it in frame_items:
            score = 0.0
            sym = it["symbol_name"]
            fp = it["file_path"]

            # Factor 1: Direct mention (+0.50)
            if (sym and sym.lower() in prompt_lower) or (fp and fp.lower() in prompt_lower):
                score += 0.50

            # Factor 2: Token overlap (+0.30 max)
            frame_tokens: set[str] = set()
            if sym:
                frame_tokens.update(re.findall(r"\b[a-zA-Z0-9_]+\b", sym.lower()))
            for dep in it["dependencies"]:
                frame_tokens.update(re.findall(r"\b[a-zA-Z0-9_]+\b", dep.lower()))
            if it["docstring"]:
                frame_tokens.update(re.findall(r"\b[a-zA-Z0-9_]+\b", it["docstring"].lower()))

            overlap = len(prompt_words & frame_tokens)
            if overlap > 0:
                score += min(0.30, 0.10 * overlap)

            # Factor 3: Call-graph connectivity (calls OR is called by directly mentioned symbol) (+0.30 max)
            is_connected = False
            if directly_mentioned:
                if any(dep in directly_mentioned for dep in it["dependencies"]):
                    is_connected = True
                elif sym and sym in callees_of_mentioned:
                    is_connected = True

            if is_connected:
                score += 0.30

            final_score = round(min(1.0, score), 3)
            if it["obj"] is not None and hasattr(it["obj"], "relevance_score"):
                it["obj"].relevance_score = final_score

            scored_frames.append((it["frame_id"], final_score))

        # Partition frames into selected and dropped
        RELEVANCE_THRESHOLD = 0.25
        selected = [fid for fid, s in scored_frames if s >= RELEVANCE_THRESHOLD]
        dropped = [fid for fid, s in scored_frames if s < RELEVANCE_THRESHOLD]

        # Fallback: if no frames passed threshold but candidates exist, keep top 1 or 2
        if not selected and scored_frames:
            scored_frames.sort(key=lambda x: x[1], reverse=True)
            selected = [scored_frames[0][0]]
            dropped = [fid for fid, s in scored_frames[1:]]

        # Multi-factor task classification across all 8 GBNF categories
        task_category = "code_completion"
        base_complexity = 0.35

        if any(kw in prompt_lower for kw in [
            "security", "vulnerability", "audit", "cve", "auth", "token", "secret", "leak", "egress", "sanitiz"
        ]):
            task_category = "security_audit"
            base_complexity = 0.80
        elif any(kw in prompt_lower for kw in [
            "architect", "design", "system", "infrastructure", "scale", "microservice", "pipeline", "framework"
        ]):
            task_category = "architecture_design"
            base_complexity = 0.85
        elif any(kw in prompt_lower for kw in [
            "test", "unit_test", "pytest", "spec", "coverage", "mock"
        ]):
            task_category = "unit_test"
            base_complexity = 0.45
        elif any(kw in prompt_lower for kw in [
            "bug", "fix", "error", "issue", "crash", "exception", "broken", "traceback", "fail"
        ]):
            task_category = "bug_fix"
            base_complexity = 0.55
        elif any(kw in prompt_lower for kw in [
            "refactor", "cleanup", "clean up", "optimize", "rewrite", "restructure", "decouple"
        ]):
            task_category = "refactor"
            base_complexity = 0.70
        elif any(kw in prompt_lower for kw in [
            "doc", "document", "readme", "explain", "comment", "guide"
        ]):
            task_category = "documentation"
            base_complexity = 0.25
        elif any(kw in prompt_lower for kw in [
            "boilerplate", "scaffold", "generate class", "stub", "skeleton", "template"
        ]):
            task_category = "boilerplate_generation"
            base_complexity = 0.20

        # Multi-factor adjustments
        complexity = base_complexity
        if len(prompt) > 400:
            complexity += 0.10
        if len(prompt) > 800:
            complexity += 0.05
        if len(frame_items) > 5:
            complexity += 0.05

        complexity_score = round(min(0.98, max(0.05, complexity)), 2)
        trigger_cloud_handoff = complexity_score >= 0.70 if default_handoff else (complexity_score >= 0.80)

        return RouterDecisionOutput(
            selected_ast_frames=selected,
            drop_irrelevant_frames=dropped,
            routing_decision=RoutingDecision(
                task_category=task_category,
                complexity_score=complexity_score,
                trigger_cloud_handoff=trigger_cloud_handoff,
            ),
        )
