"""Micro-Router package for Phonix v2.0.

Provides 1B local SLM execution locked by GBNF grammar to perform ONLY two tasks:
1. AST Context Pruning (selecting critical frames, dropping irrelevant ones).
2. Complexity Scoring for Circuit Breaking (evaluating difficulty and triggering cloud handoff).
"""

from __future__ import annotations

from src.micro_router.circuit_breaker import CircuitBreaker, CircuitBreakerStatus
from src.micro_router.gbnf_enforcer import GBNFEnforcer, RouterDecisionOutput
from src.micro_router.slm_engine import SLMEngine

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerStatus",
    "GBNFEnforcer",
    "RouterDecisionOutput",
    "SLMEngine",
]
