"""Unit and integration test suite for Phonix v2.0."""

from __future__ import annotations

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

__all__ = []
