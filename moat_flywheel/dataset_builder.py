"""Instruction Dataset Builder for Phonix v2.0 Moat Flywheel.

Synthesizes high-fidelity training pairs from git commits and AST interactions.
Formats pairs into strict GBNF JSON outputs to train the 1B Micro-Router LoRA.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from moat_flywheel.git_diff_harvester import CommitDiffContext

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


class RouterTrainingExample(BaseModel):
    """A single instruction-tuning sample for the 1B Micro-Router."""

    system: str
    user_prompt: str
    candidate_frames: list[str]
    target_output_json: str


class DatasetBuilder:
    """Constructs datasets formatted for fine-tuning the 1B Micro-Router.

    Pairs developer requests with candidate AST frames and ground-truth
    pruning/routing targets enforced by the router_decision.gbnf grammar.
    """

    SYSTEM_PROMPT: str = (
        "You are the Phonix v2.0 Micro-Router. Your task is to inspect candidate AST frames and user prompt, "
        "select relevant frames, drop irrelevant frames, classify the task, and calculate a complexity score [0.0 - 1.0]. "
        "Strictly adhere to the output JSON schema."
    )

    def build_from_diff_contexts(
        self, contexts: list[CommitDiffContext]
    ) -> list[RouterTrainingExample]:
        """Converts commit diff contexts into router training examples.

        TODO (Phonix v2.0):
        - Augment candidate frames with distractor symbols from unrelated files to test pruning robustness.
        - Calibrate complexity score against test failure counts and AST modification depth.
        """
        examples: list[RouterTrainingExample] = []

        for ctx in contexts:
            # Synthetic candidate frame IDs representing the modified symbols + distractors
            selected_frames = [
                f"{ctx.changed_files[0]}::{sym}::hash" for sym in ctx.modified_symbols
            ]
            if not selected_frames and ctx.changed_files:
                selected_frames = [f"{ctx.changed_files[0]}::main::hash"]

            distractor_frames = [
                "src/utils/legacy_helper.py::deprecated_fn::hash",
                "src/config/old_parser.py::parse_v1::hash",
            ]
            all_candidates = selected_frames + distractor_frames

            # Calculate synthetic complexity from diff length and symbols
            is_high_complexity = len(ctx.diff_text) > 1000 or len(ctx.modified_symbols) > 2
            complexity = 0.85 if is_high_complexity else 0.40
            task_category = (
                "refactor"
                if "refactor" in ctx.commit_message.lower()
                else "bug_fix"
                if "fix" in ctx.commit_message.lower()
                else "code_completion"
            )

            target_data = {
                "selected_ast_frames": selected_frames,
                "drop_irrelevant_frames": distractor_frames,
                "routing_decision": {
                    "task_category": task_category,
                    "complexity_score": complexity,
                    "trigger_cloud_handoff": is_high_complexity,
                },
            }

            examples.append(
                RouterTrainingExample(
                    system=self.SYSTEM_PROMPT,
                    user_prompt=f"Task: {ctx.commit_message}\nFiles: {', '.join(ctx.changed_files)}",
                    candidate_frames=all_candidates,
                    target_output_json=json.dumps(target_data, indent=2),
                )
            )

        return examples

    def save_jsonl(self, examples: list[RouterTrainingExample], output_path: str | Path) -> None:
        """Saves examples to JSONL file for Hugging Face / Axolotl / Unsloth trainers."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for ex in examples:
                record = {
                    "messages": [
                        {"role": "system", "content": ex.system},
                        {
                            "role": "user",
                            "content": f"{ex.user_prompt}\nCandidate Frames: {json.dumps(ex.candidate_frames)}",
                        },
                        {"role": "assistant", "content": ex.target_output_json},
                    ]
                }
                f.write(json.dumps(record) + "\n")
