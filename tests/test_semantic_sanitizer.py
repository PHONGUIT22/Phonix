"""Unit tests for Semantic-Preserving AST Sanitizer and Rehydrator."""

from __future__ import annotations

from pathlib import Path
import sys

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.gateway.rehydrator import Rehydrator
from src.gateway.semantic_sanitizer import SemanticSanitizer


def test_sanitize_preserves_identifiers_while_redacting_literals() -> None:
    """Verifies 100% code identifier preservation while redacting sensitive literals."""
    sanitizer = SemanticSanitizer()
    rehydrator = Rehydrator()

    code_snippet = """
def authenticate_service(api_key: str) -> bool:
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    internal_endpoint = "10.240.12.5"
    admin_contact = "security-lead@company.internal"
    return True
"""
    result = sanitizer.sanitize(code_snippet)

    # Invariant 1: Code identifiers, function names, and variable names remain 100% intact
    assert "def authenticate_service" in result.sanitized_text
    assert "aws_access_key" in result.sanitized_text
    assert "internal_endpoint" in result.sanitized_text
    assert "admin_contact" in result.sanitized_text

    # Invariant 2: Sensitive literals are replaced with typed placeholders
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text
    assert "10.240.12.5" not in result.sanitized_text
    assert "security-lead@company.internal" not in result.sanitized_text

    assert "<REDACTED_AWS_KEY_01>" in result.sanitized_text
    assert "<REDACTED_IP_01>" in result.sanitized_text
    assert "<REDACTED_EMAIL_01>" in result.sanitized_text

    # Invariant 3: Vault captures mappings correctly
    assert result.vault["<REDACTED_AWS_KEY_01>"] == "AKIAIOSFODNN7EXAMPLE"
    assert result.vault["<REDACTED_IP_01>"] == "10.240.12.5"
    assert result.vault["<REDACTED_EMAIL_01>"] == "security-lead@company.internal"

    # Invariant 4: Rehydrator restores text completely
    restored = rehydrator.rehydrate(result.sanitized_text, result.vault)
    assert restored == code_snippet


def test_jwt_redaction() -> None:
    """Verifies that JWT authentication tokens are cleanly redacted."""
    sanitizer = SemanticSanitizer()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f"Bearer {token}"

    res = sanitizer.sanitize(text)
    assert token not in res.sanitized_text
    assert "<REDACTED_JWT_01>" in res.sanitized_text
    assert res.vault["<REDACTED_JWT_01>"] == token


if __name__ == "__main__":
    test_sanitize_preserves_identifiers_while_redacting_literals()
    test_jwt_redaction()
    print("All SemanticSanitizer tests passed successfully!")
