"""Moat Flywheel package for Phonix v2.0.

Harvests developer interactions and git diffs to generate synthetic training datasets
and fine-tune the proprietary 1B Micro-Router LoRA weights.
"""

from __future__ import annotations

from moat_flywheel.dataset_builder import DatasetBuilder, RouterTrainingExample
from moat_flywheel.git_diff_harvester import CommitDiffContext, GitDiffHarvester
from moat_flywheel.train_router_lora import RouterLoRATrainer

__all__ = [
    "CommitDiffContext",
    "DatasetBuilder",
    "GitDiffHarvester",
    "RouterLoRATrainer",
    "RouterTrainingExample",
]
