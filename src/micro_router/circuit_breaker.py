"""Circuit Breaker & Fallback Controller for Phonix v2.0 Micro-Router.

Monitors model latency, failure rates, and complexity scores to safely determine
when to trigger cloud handoff or degrade gracefully to local fast path.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from src.micro_router.gbnf_enforcer import RouterDecisionOutput

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


class BreakerState(str, Enum):
    """Standard circuit breaker state machine."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Tripped, blocking requests to upstream
    HALF_OPEN = "half_open"  # Trial recovery


class CircuitBreakerStatus(BaseModel):
    """Telemetry status of an upstream circuit breaker."""

    upstream_id: str
    state: BreakerState = BreakerState.CLOSED
    consecutive_failures: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = Field(default_factory=time.time)


class RoutingEvaluation(BaseModel):
    """Final routing decision combining complexity score, circuit breaker status, and RBAC."""

    should_handoff_cloud: bool = Field(description="True if request must be dispatched to cloud")
    target_upstream: str = Field(description="Target destination: local, anthropic, openai, deepseek")
    reason: str = Field(description="Explanation of routing decision")
    complexity_score: float = Field(default=0.0)


class CircuitBreaker:
    """Manages cloud handoff decisions and protects against upstream cascade failures.

    Evaluates whether complexity warrants cloud spend, verifies upstream availability,
    and falls back through the hierarchy (Anthropic -> OpenAI -> DeepSeek -> Local).
    """

    def __init__(
        self,
        complexity_threshold: float = 0.70,
        failure_threshold: int = 3,
        recovery_timeout_sec: float = 60.0,
        default_cloud_upstream: str = "anthropic",
        fallback_sequence: list[str] | None = None,
    ) -> None:
        self.complexity_threshold: float = complexity_threshold
        self.failure_threshold: int = failure_threshold
        self.recovery_timeout_sec: float = recovery_timeout_sec
        self.default_cloud_upstream: str = default_cloud_upstream
        self.fallback_sequence: list[str] = fallback_sequence or [
            "anthropic",
            "openai",
            "deepseek",
        ]
        self._breakers: dict[str, CircuitBreakerStatus] = {
            up: CircuitBreakerStatus(upstream_id=up) for up in self.fallback_sequence
        }

    def evaluate_routing(
        self,
        router_decision: RouterDecisionOutput,
        user_role: str = "engineer",
        can_cloud_egress: bool = True,
    ) -> RoutingEvaluation:
        """Determines final execution path based on complexity, RBAC, and circuit states.

        TODO (Phonix v2.0):
        - Dynamically adjust complexity threshold based on live department token consumption.
        """
        rd = router_decision.routing_decision
        complexity = rd.complexity_score

        # Rule 1: RBAC zero-trust override (contractors or restricted roles can NEVER cloud egress)
        if not can_cloud_egress:
            return RoutingEvaluation(
                should_handoff_cloud=False,
                target_upstream="local",
                reason=f"Role '{user_role}' prohibited from cloud egress by Zero-Trust policy",
                complexity_score=complexity,
            )

        # Rule 2: Low complexity tasks stay local (cost & latency minimization)
        if not rd.trigger_cloud_handoff and complexity < self.complexity_threshold:
            return RoutingEvaluation(
                should_handoff_cloud=False,
                target_upstream="local",
                reason=f"Task complexity ({complexity:.2f}) below cloud threshold ({self.complexity_threshold:.2f})",
                complexity_score=complexity,
            )

        # Rule 3: High complexity requires cloud; find first available upstream
        for upstream in self.fallback_sequence:
            if self.is_upstream_available(upstream):
                return RoutingEvaluation(
                    should_handoff_cloud=True,
                    target_upstream=upstream,
                    reason=f"Cloud handoff triggered (complexity: {complexity:.2f}); dispatched to {upstream}",
                    complexity_score=complexity,
                )

        # Rule 4: All cloud upstreams tripped; gracefully degrade to local
        return RoutingEvaluation(
            should_handoff_cloud=False,
            target_upstream="local",
            reason="All cloud upstreams tripped circuit breaker; degrading to local fast path",
            complexity_score=complexity,
        )

    def is_upstream_available(self, upstream: str) -> bool:
        """Checks if an upstream is healthy or has reached its recovery window."""
        status = self._breakers.get(upstream)
        if status is None:
            return True

        now = time.time()
        if status.state == BreakerState.OPEN:
            if now - status.last_failure_time >= self.recovery_timeout_sec:
                status.state = BreakerState.HALF_OPEN
                status.last_state_change = now
                return True
            return False

        return True

    def record_success(self, upstream: str) -> None:
        """Records a successful upstream call, resetting failure counts."""
        status = self._breakers.get(upstream)
        if status is not None:
            status.total_successes += 1
            status.consecutive_failures = 0
            if status.state == BreakerState.HALF_OPEN:
                status.state = BreakerState.CLOSED
                status.last_state_change = time.time()

    def record_failure(self, upstream: str) -> None:
        """Records an upstream failure and trips breaker if threshold exceeded."""
        status = self._breakers.get(upstream)
        if status is not None:
            now = time.time()
            status.total_failures += 1
            status.consecutive_failures += 1
            status.last_failure_time = now

            if status.consecutive_failures >= self.failure_threshold:
                status.state = BreakerState.OPEN
                status.last_state_change = now
