"""Audit Telemetry & Compliance Logger for Phonix v2.0 Enterprise Gateway.

Captures immutable audit logs, Zero-Trust egress decisions, MMU paging efficiency,
token accounting, and cost savings across local fast-path and cloud upstreams.
"""

from __future__ import annotations

import collections
import threading
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


class AuditLogEntry(BaseModel):
    """Structured audit and compliance event record."""

    request_id: str
    timestamp: float = Field(default_factory=time.time)
    role: str = "engineer"
    department: str = "engineering"
    endpoint: str = "/v1/chat/completions"
    tokens_in: int = 0
    tokens_out: int = 0
    frames_paged: int = 0
    frames_pruned: int = 0
    complexity_score: float = 0.0
    egress_allowed: bool = True
    target_upstream: str = "local"
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    redactions_count: int = 0


class AuditTelemetry:
    """Thread-safe telemetry collector and compliance audit store.

    Maintains in-memory ring buffers and provides aggregation primitives
    for enterprise security dashboards and SIEM exporters.
    """

    def __init__(self, max_buffer_size: int = 10000) -> None:
        self.max_buffer_size: int = max_buffer_size
        self._entries: collections.deque[AuditLogEntry] = collections.deque(
            maxlen=max_buffer_size
        )
        self._lock: threading.Lock = threading.Lock()
        self._total_requests: int = 0
        self._total_violations_blocked: int = 0
        self._total_cost_saved_usd: float = 0.0

    def record_entry(self, entry: AuditLogEntry) -> None:
        """Appends an audit log entry to the circular buffer."""
        with self._lock:
            self._entries.append(entry)
            self._total_requests += 1
            if not entry.egress_allowed:
                self._total_violations_blocked += 1
            # Calculate hypothetical cost saved if routed locally instead of cloud
            if entry.target_upstream == "local":
                # Average cloud cost assumption: $0.005 / 1k tokens
                tokens = entry.tokens_in + entry.tokens_out
                self._total_cost_saved_usd += (tokens / 1000.0) * 0.005

    def get_recent_entries(self, limit: int = 50) -> list[AuditLogEntry]:
        """Retrieves recent audit entries."""
        with self._lock:
            return list(self._entries)[-limit:]

    def get_summary_metrics(self) -> dict[str, Any]:
        """Aggregates system-wide compliance and cost metrics.

        TODO (Phonix v2.0):
        - Integrate OpenTelemetry OTLP exporter to stream traces to Datadog / Prometheus.
        """
        with self._lock:
            total_tokens = sum(e.tokens_in + e.tokens_out for e in self._entries)
            avg_latency = (
                sum(e.latency_ms for e in self._entries) / len(self._entries)
                if self._entries
                else 0.0
            )

            return {
                "total_requests": self._total_requests,
                "buffered_entries": len(self._entries),
                "violations_blocked": self._total_violations_blocked,
                "total_tokens_processed": total_tokens,
                "estimated_cost_saved_usd": round(self._total_cost_saved_usd, 4),
                "avg_latency_ms": round(avg_latency, 2),
            }
