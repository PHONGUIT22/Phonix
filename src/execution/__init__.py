"""Execution engine package for Phonix v2.0.

Provides dual-path execution:
1. LocalFastPath for simple, boilerplate, or restricted requests executing locally.
2. CloudDispatcher for complex requests routed to Anthropic, OpenAI, or DeepSeek with fallbacks.
"""

from __future__ import annotations

from src.execution.cloud_dispatcher import CloudDispatcher, UpstreamResponse
from src.execution.local_fast_path import LocalFastPath

__all__ = [
    "CloudDispatcher",
    "LocalFastPath",
    "UpstreamResponse",
]
