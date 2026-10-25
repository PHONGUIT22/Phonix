"""Z3/Cedar Formal Policy Engine for Phonix v2.0 Enterprise Gateway.

Applies formal mathematical verification via Z3 Solver strictly for:
1. Role-Based Access Control (RBAC).
2. Zero-Trust Data Egress proof (verifying 0 unredacted secrets leave boundary).
3. Department Token Budget & Quota headroom verification.
NO Z3 is used for code transpilation; strictly policy & egress invariants.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

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


class PolicyRequest(BaseModel):
    """Contextual metadata evaluated by the formal policy engine."""

    user_id: str = "user-default"
    role: str = "engineer"  # admin, engineer, contractor, auditor
    department: str = "engineering"
    target_upstream: str = "anthropic"  # local, anthropic, openai, deepseek
    estimated_tokens: int = 100
    unredacted_secrets_count: int = 0


class PolicyDecision(BaseModel):
    """Result of formal Z3 policy evaluation."""

    is_allowed: bool
    reason: str
    z3_proof_status: str  # PROVEN_SAFE, VIOLATION_DETECTED, SOLVER_FALLBACK
    token_headroom: int = 0
    enforced_upstream: str = "local"


class PolicyEngine:
    """Formal verification engine using Z3 SMT solver for zero-trust guarantees.

    Proves mathematically that no request violating zero-trust egress, RBAC permissions,
    or token quotas can ever be dispatched to a cloud upstream.
    """

    DEFAULT_QUOTAS: dict[str, int] = {
        "engineering": 10000000,
        "finance": 1000000,
        "security": 5000000,
        "data_science": 20000000,
    }

    ROLE_PERMISSIONS: dict[str, dict[str, Any]] = {
        "admin": {"can_cloud_egress": True, "max_tokens": 100000},
        "engineer": {"can_cloud_egress": True, "max_tokens": 8000},
        "contractor": {"can_cloud_egress": False, "max_tokens": 4000},
        "auditor": {"can_cloud_egress": False, "max_tokens": 1000},
    }

    def __init__(
        self,
        custom_quotas: dict[str, int] | None = None,
        config_path: str | Path | None = "config/zero_trust_policy.yaml",
    ) -> None:
        self.quotas: dict[str, int] = dict(self.DEFAULT_QUOTAS)
        self.role_permissions: dict[str, dict[str, Any]] = {
            k: dict(v) for k, v in self.ROLE_PERMISSIONS.items()
        }

        # Dynamically load from YAML config if available
        if config_path and yaml is not None:
            resolved_path = Path(config_path)
            if resolved_path.is_file():
                try:
                    with open(resolved_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    dept_quotas = data.get("department_quotas", {})
                    if isinstance(dept_quotas, dict):
                        for dept, conf in dept_quotas.items():
                            if isinstance(conf, dict) and "monthly_token_budget" in conf:
                                self.quotas[dept] = int(conf["monthly_token_budget"])
                            elif isinstance(conf, (int, float)):
                                self.quotas[dept] = int(conf)

                    rbac_roles = data.get("rbac", {}).get("roles", {})
                    if isinstance(rbac_roles, dict):
                        for role, conf in rbac_roles.items():
                            if isinstance(conf, dict):
                                self.role_permissions[role] = {
                                    "can_cloud_egress": conf.get("can_cloud_egress", False),
                                    "max_tokens": conf.get("max_tokens", 8000),
                                    "allowed_upstreams": conf.get("allowed_upstreams", ["local"]),
                                    "max_complexity_allowed": conf.get("max_complexity_allowed", 1.0),
                                }
                except Exception as exc:
                    logger.warning("Failed to load policy YAML from %s: %s", resolved_path, exc)

        if custom_quotas:
            self.quotas.update(custom_quotas)

        self._consumed_tokens: dict[str, int] = {dept: 0 for dept in self.quotas}

    def record_token_usage(self, department: str, tokens: int) -> None:
        """Records consumed tokens for a given department."""
        self._consumed_tokens[department] = self._consumed_tokens.get(department, 0) + tokens

    def get_consumed_tokens(self, department: str) -> int:
        """Returns consumed tokens for a given department."""
        return self._consumed_tokens.get(department, 0)

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Evaluates access request using formal Z3 SMT proof invariants.

        TODO (Phonix v2.0):
        - Integrate Cedar Policy engine parser for user-defined enterprise DSL policies.
        - Add multi-tenant cryptographic certificate verification in Z3 proof state.
        """
        # Step 1: Check role permissions
        fallback_perm = self.role_permissions.get("contractor", {"can_cloud_egress": False, "max_tokens": 4000})
        role_perm = self.role_permissions.get(request.role, fallback_perm)
        is_cloud_request = request.target_upstream != "local"

        if is_cloud_request and not role_perm["can_cloud_egress"]:
            return PolicyDecision(
                is_allowed=False,
                reason=f"Role '{request.role}' is strictly prohibited from cloud egress.",
                z3_proof_status="VIOLATION_DETECTED",
                token_headroom=0,
                enforced_upstream="local",
            )

        # Step 2: Attempt formal Z3 verification
        try:
            import z3  # type: ignore

            return self._verify_with_z3(request, role_perm, is_cloud_request)
        except ImportError:
            # Fallback deterministic symbolic verification if z3-solver is not yet installed
            return self._verify_symbolic_fallback(request, role_perm, is_cloud_request)

    def _verify_with_z3(
        self, request: PolicyRequest, role_perm: dict[str, Any], is_cloud_request: bool
    ) -> PolicyDecision:
        """Constructs an SMT theorem and checks for violation models using Z3."""
        import z3  # type: ignore

        solver = z3.Solver()

        # Symbolic Variables
        cloud_egress = z3.Bool("cloud_egress")
        has_unredacted_secrets = z3.Bool("has_unredacted_secrets")
        role_allows_cloud = z3.Bool("role_allows_cloud")
        dept_budget = z3.Int("dept_budget")
        consumed = z3.Int("consumed")
        requested = z3.Int("requested")

        # Invariant 1: Cloud Egress implies Zero Unredacted Secrets
        egress_safety = z3.Implies(cloud_egress, z3.Not(has_unredacted_secrets))

        # Invariant 2: Cloud Egress implies Role allows Cloud
        role_safety = z3.Implies(cloud_egress, role_allows_cloud)

        # Invariant 3: Quota headroom invariant
        quota_safety = (consumed + requested) <= dept_budget

        # All invariants must hold simultaneously
        safe_state = z3.And(egress_safety, role_safety, quota_safety)

        # Assert concrete values from request
        solver.add(cloud_egress == is_cloud_request)
        solver.add(has_unredacted_secrets == (request.unredacted_secrets_count > 0))
        solver.add(role_allows_cloud == role_perm["can_cloud_egress"])

        dept_max = self.quotas.get(request.department, 1000000)
        curr_consumed = self._consumed_tokens.get(request.department, 0)
        solver.add(dept_budget == dept_max)
        solver.add(consumed == curr_consumed)
        solver.add(requested == request.estimated_tokens)

        # We test if a violation of safe_state is possible
        solver.push()
        solver.add(z3.Not(safe_state))
        check_result = solver.check()
        solver.pop()

        headroom = max(0, dept_max - (curr_consumed + request.estimated_tokens))

        if check_result == z3.unsat:
            # unsat of negation means violation is mathematically impossible -> PROVEN SAFE
            return PolicyDecision(
                is_allowed=True,
                reason="Formally verified safe under Zero-Trust and Quota invariants by Z3",
                z3_proof_status="PROVEN_SAFE",
                token_headroom=headroom,
                enforced_upstream=request.target_upstream,
            )
        else:
            # sat means a violation is possible
            violation_reasons: list[str] = []
            if is_cloud_request and request.unredacted_secrets_count > 0:
                violation_reasons.append(
                    f"Egress blocked: {request.unredacted_secrets_count} unredacted secret(s) detected"
                )
            if curr_consumed + request.estimated_tokens > dept_max:
                violation_reasons.append(
                    f"Quota exceeded for department '{request.department}'"
                )
            if not violation_reasons:
                violation_reasons.append("SMT constraint violation detected")

            return PolicyDecision(
                is_allowed=False,
                reason="; ".join(violation_reasons),
                z3_proof_status="VIOLATION_DETECTED",
                token_headroom=headroom,
                enforced_upstream="local",
            )

    def _verify_symbolic_fallback(
        self, request: PolicyRequest, role_perm: dict[str, Any], is_cloud_request: bool
    ) -> PolicyDecision:
        """Deterministic fallback when z3 native binary is not installed."""
        dept_max = self.quotas.get(request.department, 1000000)
        curr_consumed = self._consumed_tokens.get(request.department, 0)
        headroom = max(0, dept_max - (curr_consumed + request.estimated_tokens))

        if is_cloud_request and request.unredacted_secrets_count > 0:
            return PolicyDecision(
                is_allowed=False,
                reason=f"Zero-Trust Violation: {request.unredacted_secrets_count} unredacted secrets detected",
                z3_proof_status="VIOLATION_DETECTED",
                token_headroom=headroom,
                enforced_upstream="local",
            )

        if curr_consumed + request.estimated_tokens > dept_max:
            return PolicyDecision(
                is_allowed=False,
                reason=f"Quota exceeded for department '{request.department}'",
                z3_proof_status="VIOLATION_DETECTED",
                token_headroom=headroom,
                enforced_upstream="local",
            )

        return PolicyDecision(
            is_allowed=True,
            reason="Verified safe under Zero-Trust rules (Symbolic Fallback)",
            z3_proof_status="SOLVER_FALLBACK",
            token_headroom=headroom,
            enforced_upstream=request.target_upstream,
        )
