"""Automated Git-Commit AST Triage Dataset Miner & Telemetry Flywheel.

Mines Git commit history and live telemetry traces to generate high-quality SFT datasets
in ChatML format for fine-tuning the 1B/1.5B Micro-Router SLM.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import re
import subprocess
import time
from typing import TYPE_CHECKING, Any

from src.mmu.ast_slicer import ASTFrame, ASTSlicer

if TYPE_CHECKING:
    from src.micro_router.gbnf_enforcer import RouterDecisionOutput

logger = logging.getLogger(__name__)


class RouterDataFlywheel:
    """Dataset Flywheel mining real Git commits and live gateway telemetry for SLM fine-tuning."""

    SYSTEM_PROMPT: str = (
        "You are Phonix v2.0 Micro-Router (1B/1.5B edge SLM). "
        "Your responsibility is to analyze user requests, prune irrelevant candidate AST frames, "
        "and output a deterministic JSON routing decision following the required schema."
    )

    DIFF_FILE_REGEX = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
    HUNK_REGEX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    def __init__(self, workspace_root: str = ".") -> None:
        self.workspace_root = workspace_root
        self.ast_slicer = ASTSlicer()

    def mine_git_history(
        self, repo_path: str | None = None, max_commits: int = 50
    ) -> list[dict[str, Any]]:
        """Mines Git commit history and diff hunks to build AST triage training samples.

        For each commit:
        1. Extracts modified files and exact line ranges modified from git diff hunks.
        2. Slices affected source files into ASTFrame objects.
        3. Labels overlapping frames as `selected_ast_frames` and non-overlapping sibling frames as `dropped_ast_frames`.
        4. Infers task_category, complexity_score, and requires_cloud_handoff.
        5. Formats record into ChatML SFT training format.
        """
        root = repo_path or self.workspace_root
        samples: list[dict[str, Any]] = []

        try:
            # Query commit hashes and subjects
            cmd = ["git", "log", f"-n{max_commits}", "--pretty=format:%H|%s"]
            proc = subprocess.run(
                cmd,
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if proc.returncode != 0:
                logger.warning("git log failed with code %d: %s", proc.returncode, proc.stderr)
                return []

            lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        except Exception as exc:
            logger.error("Failed to query git log: %s", exc)
            return []

        for line in lines:
            if "|" not in line:
                continue
            commit_hash, commit_subject = line.split("|", 1)
            commit_hash = commit_hash.strip()
            commit_subject = commit_subject.strip()

            if not commit_subject or commit_subject.startswith("Merge"):
                continue

            # Query diff hunks for this commit
            try:
                diff_cmd = ["git", "show", "--unified=0", commit_hash]
                diff_proc = subprocess.run(
                    diff_cmd,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                if diff_proc.returncode != 0:
                    continue
                diff_text = diff_proc.stdout
            except Exception:
                continue

            file_modified_ranges: dict[str, list[tuple[int, int]]] = {}
            current_file: str | None = None
            total_modified_lines = 0

            for d_line in diff_text.splitlines():
                file_match = self.DIFF_FILE_REGEX.match(d_line)
                if file_match:
                    current_file = file_match.group(2).strip()
                    file_modified_ranges[current_file] = []
                    continue

                if current_file:
                    hunk_match = self.HUNK_REGEX.match(d_line)
                    if hunk_match:
                        start = int(hunk_match.group(1))
                        count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                        end = start + max(count - 1, 0)
                        file_modified_ranges[current_file].append((start, end))
                        total_modified_lines += max(count, 1)

            # Filter for code files that exist in the repository
            candidate_frames: list[ASTFrame] = []
            selected_frames: list[ASTFrame] = []
            dropped_frames: list[ASTFrame] = []

            for rel_file, ranges in file_modified_ranges.items():
                norm_rel_file = rel_file.replace("\\", "/")
                ext = os.path.splitext(norm_rel_file)[1].lower()
                if ext not in {".py", ".ts", ".js", ".go", ".rs", ".java", ".c", ".cpp"}:
                    continue

                full_file_path = Path(root) / norm_rel_file
                if not full_file_path.is_file():
                    continue

                try:
                    file_frames = self.ast_slicer.slice_file(str(full_file_path))
                except Exception:
                    continue

                for f in file_frames:
                    norm_id = self.ast_slicer.generate_frame_id(
                        norm_rel_file, f.symbol_name, f.raw_code
                    )
                    f.file_path = norm_rel_file
                    f.frame_id = norm_id
                    candidate_frames.append(f)
                    # Check overlap with any modified range
                    is_modified = False
                    for r_start, r_end in ranges:
                        if max(f.start_line, r_start) <= min(f.end_line, r_end):
                            is_modified = True
                            break

                    # Also match if frame symbol is explicitly referenced in commit subject
                    if not is_modified and f.symbol_name and len(f.symbol_name) >= 3:
                        if f.symbol_name.lower() in commit_subject.lower():
                            is_modified = True

                    if is_modified:
                        selected_frames.append(f)
                    else:
                        dropped_frames.append(f)

            # Need at least 1 candidate frame to form an AST triage sample
            if not candidate_frames:
                continue

            # Ensure valid partition: if none selected, select the first frame
            if not selected_frames and candidate_frames:
                selected_frames.append(candidate_frames[0])
                dropped_frames = candidate_frames[1:]
            elif not dropped_frames and len(selected_frames) > 2:
                # Keep top 2 selected, move remainder to dropped for balanced training signal
                dropped_frames = selected_frames[2:]
                selected_frames = selected_frames[:2]

            # Infer task category
            task_category = self._infer_task_category(commit_subject, total_modified_lines)

            # Calculate realistic complexity score
            complexity_score = self._compute_complexity(
                task_category=task_category,
                modified_lines=total_modified_lines,
                selected_count=len(selected_frames),
                total_candidates=len(candidate_frames),
            )
            requires_cloud_handoff = complexity_score >= 0.70

            selected_ids = [f.frame_id for f in selected_frames]
            dropped_ids = [f.frame_id for f in dropped_frames]

            candidate_summary = [
                {"id": f.frame_id, "symbol": f.symbol_name, "tokens": f.token_count}
                for f in candidate_frames
            ]

            decision_payload = {
                "selected_ast_frames": selected_ids,
                "dropped_ast_frames": dropped_ids,
                "routing_decision": {
                    "task_category": task_category,
                    "complexity_score": complexity_score,
                    "trigger_cloud_handoff": requires_cloud_handoff,
                },
            }

            sample = {
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"User Request: {commit_subject}\n"
                            f"Candidate Frames: {json.dumps(candidate_summary)}"
                        ),
                    },
                    {"role": "assistant", "content": json.dumps(decision_payload)},
                ],
                "metadata": {
                    "source": "git_commit_ast_mining",
                    "commit": commit_hash,
                    "subject": commit_subject,
                    "task_category": task_category,
                    "complexity_score": complexity_score,
                    "requires_cloud_handoff": requires_cloud_handoff,
                    "total_modified_lines": total_modified_lines,
                    "selected_count": len(selected_ids),
                    "dropped_count": len(dropped_ids),
                },
            }
            samples.append(sample)

        return samples

    def record_live_distillation_sample(
        self,
        prompt: str,
        candidate_frames: list[ASTFrame],
        decision: RouterDecisionOutput,
        source: str = "live_gateway",
        feedback_score: float = 1.0,
    ) -> dict[str, Any]:
        """Converts a live gateway routing interaction into a ChatML SFT sample."""
        candidate_summary = [
            {"id": f.frame_id, "symbol": f.symbol_name, "tokens": f.token_count}
            for f in candidate_frames
        ]
        decision_dict = decision.model_dump() if hasattr(decision, "model_dump") else decision

        return {
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"User Request: {prompt}\nCandidate Frames: {json.dumps(candidate_summary)}",
                },
                {"role": "assistant", "content": json.dumps(decision_dict)},
            ],
            "metadata": {
                "source": source,
                "feedback_score": feedback_score,
                "timestamp": int(time.time()),
            },
        }

    def export_jsonl(
        self,
        samples: list[dict[str, Any]],
        output_path: str | Path = "data/phonix_router_sft_dataset.jsonl",
    ) -> int:
        """Writes the mined SFT dataset to disk in JSONL format."""
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        return len(samples)

    def calculate_statistics(self, samples: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculates dataset metrics and distribution."""
        total_samples = len(samples)
        if total_samples == 0:
            return {
                "total_samples": 0,
                "total_selected_frames": 0,
                "total_dropped_frames": 0,
                "avg_pruning_ratio": 0.0,
                "local_count": 0,
                "cloud_count": 0,
                "category_distribution": {},
            }

        total_selected = 0
        total_dropped = 0
        local_count = 0
        cloud_count = 0
        categories: dict[str, int] = {}

        for s in samples:
            meta = s.get("metadata", {})
            sel = meta.get("selected_count", 0)
            drp = meta.get("dropped_count", 0)
            total_selected += sel
            total_dropped += drp

            cat = meta.get("task_category", "general_qa")
            categories[cat] = categories.get(cat, 0) + 1

            if meta.get("requires_cloud_handoff", False):
                cloud_count += 1
            else:
                local_count += 1

        tot_frames = total_selected + total_dropped
        avg_pruning_ratio = (total_dropped / tot_frames) if tot_frames > 0 else 0.0

        return {
            "total_samples": total_samples,
            "total_selected_frames": total_selected,
            "total_dropped_frames": total_dropped,
            "avg_pruning_ratio": avg_pruning_ratio,
            "local_count": local_count,
            "cloud_count": cloud_count,
            "local_pct": (local_count / total_samples) * 100.0,
            "cloud_pct": (cloud_count / total_samples) * 100.0,
            "category_distribution": categories,
        }

    @staticmethod
    def _infer_task_category(commit_subject: str, total_lines: int) -> str:
        """Infers router task_category from commit subject prefix and change volume."""
        sub = commit_subject.lower()
        if sub.startswith("feat") or "feature" in sub:
            return "boilerplate" if total_lines < 30 else ("architecture" if total_lines > 200 else "refactor")
        if sub.startswith("fix") or "bug" in sub or "patch" in sub:
            return "debugging"
        if sub.startswith("refactor") or "clean" in sub or "reorganize" in sub:
            return "refactor"
        if (
            sub.startswith("sec")
            or "security" in sub
            or "auth" in sub
            or "zero-trust" in sub
            or "guard" in sub
        ):
            return "security_audit"
        if sub.startswith("test") or "spec" in sub:
            return "boilerplate"
        if sub.startswith("ci") or "docker" in sub or "workflow" in sub or "arch" in sub:
            return "architecture"
        return "general_qa"

    @staticmethod
    def _compute_complexity(
        task_category: str,
        modified_lines: int,
        selected_count: int,
        total_candidates: int,
    ) -> float:
        """Computes normalized complexity score (0.15 - 0.95)."""
        base_weights = {
            "boilerplate": 0.25,
            "debugging": 0.45,
            "refactor": 0.55,
            "architecture": 0.80,
            "security_audit": 0.85,
            "general_qa": 0.40,
        }
        base = base_weights.get(task_category, 0.45)
        line_factor = min(0.15, modified_lines * 0.002)
        frame_factor = min(0.15, selected_count * 0.03)
        return round(min(0.95, max(0.15, base + line_factor + frame_factor)), 2)
