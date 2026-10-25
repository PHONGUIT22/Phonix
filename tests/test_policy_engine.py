"""Unit tests for Z3 Formal Zero-Trust Policy Engine."""

from __future__ import annotations

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.gateway.policy_engine import PolicyEngine, PolicyRequest


def test_contractor_cloud_egress_blocked() -> None:
    """Verifies that contractors are strictly forbidden from cloud egress."""
    engine = PolicyEngine()
    req = PolicyRequest(
        role="contractor",
        department="engineering",
        target_upstream="anthropic",
        estimated_tokens=500,
        unredacted_secrets_count=0,
    )
    decision = engine.evaluate(req)

    assert not decision.is_allowed
    assert "strictly prohibited from cloud egress" in decision.reason
    assert decision.enforced_upstream == "local"


def test_unredacted_secrets_cloud_egress_blocked() -> None:
    """Verifies Zero-Trust invariant: cloud egress with unredacted secrets is blocked."""
    engine = PolicyEngine()
    req = PolicyRequest(
        role="engineer",
        department="engineering",
        target_upstream="anthropic",
        estimated_tokens=500,
        unredacted_secrets_count=1,  # Violation
    )
    decision = engine.evaluate(req)

    assert not decision.is_allowed
    assert decision.z3_proof_status == "VIOLATION_DETECTED"
    assert "secret" in decision.reason.lower()


def test_clean_engineer_cloud_request_allowed() -> None:
    """Verifies that compliant engineer request with 0 unredacted secrets is formally permitted."""
    engine = PolicyEngine()
    req = PolicyRequest(
        role="engineer",
        department="engineering",
        target_upstream="anthropic",
        estimated_tokens=500,
        unredacted_secrets_count=0,
    )
    decision = engine.evaluate(req)

    assert decision.is_allowed
    assert decision.z3_proof_status in ("PROVEN_SAFE", "SOLVER_FALLBACK")
    assert decision.token_headroom > 0
    assert decision.enforced_upstream == "anthropic"


def test_department_quota_exhaustion_blocked() -> None:
    """Verifies that exceeding monthly token quota blocks cloud dispatch."""
    # Custom low quota of 1000 tokens for testing
    engine = PolicyEngine(custom_quotas={"engineering": 1000})
    engine.record_token_usage("engineering", 900)

    # Requesting 200 tokens (900 + 200 = 1100 > 1000)
    req = PolicyRequest(
        role="engineer",
        department="engineering",
        target_upstream="anthropic",
        estimated_tokens=200,
        unredacted_secrets_count=0,
    )
    decision = engine.evaluate(req)

    assert not decision.is_allowed
    assert "Quota exceeded" in decision.reason


if __name__ == "__main__":
    test_contractor_cloud_egress_blocked()
    test_unredacted_secrets_cloud_egress_blocked()
    test_clean_engineer_cloud_request_allowed()
    test_department_quota_exhaustion_blocked()
    print("All PolicyEngine tests passed successfully!")
