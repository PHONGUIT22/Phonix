"""Git Diff Harvester for Phonix v2.0 Moat Flywheel.

Extracts historical commits, PR diffs, and modified AST symbols from git repositories
to reconstruct the exact contextual frames developers needed to complete code tasks.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
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


class CommitDiffContext(BaseModel):
    """Contextual metadata harvested from a single git commit."""

    commit_hash: str
    commit_message: str
    changed_files: list[str] = Field(default_factory=list)
    modified_symbols: list[str] = Field(default_factory=list)
    diff_text: str = ""
    timestamp: float = Field(default_factory=time.time)


class GitDiffHarvester:
    """Harvests commits and code diffs from local git repositories.

    Feeds the proprietary training flywheel by isolating modified function/class
    signatures and linking them with developer commit intent.
    """

    DIFF_FUNC_PATTERN: re.Pattern[str] = re.compile(
        r"@@\s+-[0-9,]+\s+\+[0-9,]+\s+@@\s*(?:def|class|async def)?\s*([a-zA-Z0-9_]+)?"
    )

    def harvest_recent_commits(
        self, repo_path: str = ".", max_commits: int = 20
    ) -> list[CommitDiffContext]:
        """Harvests recent commits and diffs using local git command.

        TODO (Phonix v2.0):
        - Integrate with GitHub / GitLab webhooks for continuous real-time harvesting.
        - Parse AST symbol modifications before and after commit to isolate ground-truth dependencies.
        """
        contexts: list[CommitDiffContext] = []
        try:
            cmd = [
                "git",
                "-C",
                repo_path,
                "log",
                f"-n{max_commits}",
                "--pretty=format:%H%x00%s%x00%at",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = res.stdout.strip().splitlines()

            for line in lines:
                parts = line.split("\x00")
                if len(parts) < 3:
                    continue
                commit_hash, commit_msg, timestamp_str = parts[0], parts[1], parts[2]

                diff_cmd = ["git", "-C", repo_path, "show", "--unified=3", commit_hash]
                diff_res = subprocess.run(diff_cmd, capture_output=True, text=True, check=True)
                diff_text = diff_res.stdout

                files_cmd = ["git", "-C", repo_path, "show", "--name-only", "--pretty=format:", commit_hash]
                files_res = subprocess.run(files_cmd, capture_output=True, text=True, check=True)
                changed_files = [f.strip() for f in files_res.stdout.splitlines() if f.strip()]

                modified_symbols = self.extract_modified_symbols(diff_text)

                contexts.append(
                    CommitDiffContext(
                        commit_hash=commit_hash,
                        commit_message=commit_msg,
                        changed_files=changed_files,
                        modified_symbols=modified_symbols,
                        diff_text=diff_text[:5000],  # Truncate for memory efficiency
                        timestamp=float(timestamp_str),
                    )
                )

        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            logger.warning("Git harvest command failed or git not available: %s", exc)
            # Return synthetic sample for offline development
            contexts.append(
                CommitDiffContext(
                    commit_hash="c0ffee012345",
                    commit_message="feat(gateway): implement Z3 token quota check",
                    changed_files=["src/gateway/policy_engine.py"],
                    modified_symbols=["evaluate", "_verify_with_z3"],
                    diff_text="diff --git a/src/gateway/policy_engine.py ...",
                    timestamp=time.time(),
                )
            )

        return contexts

    def extract_modified_symbols(self, diff_text: str) -> list[str]:
        """Extracts function and class names from diff hunk headers."""
        symbols: set[str] = set()
        for match in self.DIFF_FUNC_PATTERN.finditer(diff_text):
            sym = match.group(1)
            if sym and sym not in ("def", "class", "async"):
                symbols.add(sym)
        return sorted(symbols)
