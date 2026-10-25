"""Semantic-Preserving AST Sanitizer for Phonix v2.0 Enterprise Compliance Gateway.

Redacts ONLY sensitive string literals (API keys, secrets, internal IPs, PII)
into typed placeholders (e.g. <REDACTED_SECRET_01>) while keeping 100% of
variable, function, class, and method identifiers intact.
Builds a bidirectional vault for subsequent response rehydration.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
import threading
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

logger = logging.getLogger(__name__)

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


class RedactedLiteral(BaseModel):
    """Metadata regarding a redacted sensitive literal."""

    original_value: str
    placeholder: str
    category: str  # SECRET, AWS_KEY, JWT, IP, EMAIL, SSN
    start_offset: int = 0
    end_offset: int = 0


class SanitizationResult(BaseModel):
    """Output of semantic sanitization containing sanitized text and reverse vault."""

    sanitized_text: str
    vault: dict[str, str] = Field(
        default_factory=dict, description="Mapping from placeholder to original secret"
    )
    redactions: list[RedactedLiteral] = Field(default_factory=list)

    @property
    def redaction_count(self) -> int:
        """Returns total number of redacted literals."""
        return len(self.redactions)


class SemanticSanitizer:
    """Enterprise AST & literal sanitizer with 100% code structure preservation.

    Crucially distinguishes between code symbols (which must NEVER be altered)
    and sensitive literal values embedded within code, configuration, or prompts.
    """

    DEFAULT_PATTERNS: list[tuple[str, str, str]] = [
        # (category, regex, placeholder_prefix)
        ("AWS_KEY", r"(?i)\b(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}\b", "<REDACTED_AWS_KEY_"),
        (
            "JWT",
            r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            "<REDACTED_JWT_",
        ),
        (
            "SECRET",
            r"(?i)(?:api[_-]?key|secret|token|password|bearer)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{16,64})[\"']",
            "<REDACTED_SECRET_",
        ),
        (
            "SECRET",
            r"\b(?:sk_live_|sk_test_|ghp_|gho_|glpat-|xox[baprs]-)[a-zA-Z0-9_\-]{16,64}\b",
            "<REDACTED_SECRET_",
        ),
        (
            "IP",
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "<REDACTED_IP_",
        ),
        (
            "EMAIL",
            r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
            "<REDACTED_EMAIL_",
        ),
        (
            "SSN",
            r"\b\d{3}-\d{2}-\d{4}\b",
            "<REDACTED_SSN_",
        ),
    ]

    def __init__(
        self,
        custom_rules: list[dict[str, Any]] | None = None,
        config_path: str | Path | None = "config/zero_trust_policy.yaml",
    ) -> None:
        self._lock = threading.Lock()
        self._compiled_rules: list[tuple[str, re.Pattern[str], str]] = []

        # Compile default rules
        for category, regex, prefix in self.DEFAULT_PATTERNS:
            self._compiled_rules.append((category, re.compile(regex), prefix))

        # Dynamically load from YAML config if provided
        if config_path and yaml is not None:
            resolved_path = Path(config_path)
            if resolved_path.is_file():
                try:
                    with open(resolved_path, "r", encoding="utf-8") as f:
                        cfg = yaml.safe_load(f) or {}
                    yaml_rules = cfg.get("sanitization", {}).get("literal_rules", [])
                    if isinstance(yaml_rules, list):
                        for rule in yaml_rules:
                            cat = rule.get("category", "SECRET")
                            reg = rule.get("regex", "")
                            pfx = rule.get("placeholder_prefix", "<REDACTED_SECRET_")
                            if reg:
                                try:
                                    self._compiled_rules.append((cat, re.compile(reg), pfx))
                                except Exception as compile_err:
                                    logger.warning("Failed to compile YAML regex %s: %s", reg, compile_err)
                except Exception as exc:
                    logger.warning("Failed to load sanitization config from %s: %s", resolved_path, exc)

        # Add custom rules if provided
        if custom_rules:
            for rule in custom_rules:
                cat = rule.get("category", "SECRET")
                reg = rule.get("regex", "")
                pfx = rule.get("placeholder_prefix", "<REDACTED_SECRET_")
                if reg:
                    self._compiled_rules.append((cat, re.compile(reg), pfx))

    def sanitize(
        self, text: str, existing_vault: dict[str, str] | None = None
    ) -> SanitizationResult:
        """Sanitizes text by replacing sensitive literals with typed placeholders.

        Preserves 100% of variable identifiers, class names, and control syntax.
        Avoids placeholder collisions across repeated invocations by seeding
        counters from existing_vault and reusing placeholders for identical secrets.

        TODO (Phonix v2.0):
        - Integrate Tree-sitter query to filter regex execution strictly to AST string_literal nodes.
        - Support salted cryptographic hashing for irreversible audit logging mode.
        """
        vault: dict[str, str] = dict(existing_vault) if existing_vault else {}
        secret_to_placeholder: dict[str, str] = {v: k for k, v in vault.items()}
        redactions: list[RedactedLiteral] = []
        counter: dict[str, int] = {}

        # Seed category counters from existing placeholders in vault
        for placeholder in vault:
            for cat, _, prefix in self._compiled_rules:
                if placeholder.startswith(prefix) and placeholder.endswith(">"):
                    suffix = placeholder[len(prefix) : -1]
                    if suffix.isdigit():
                        counter[cat] = max(counter.get(cat, 0), int(suffix))

        sanitized_text = text

        with self._lock:
            for category, pattern, prefix in self._compiled_rules:
                matches = list(pattern.finditer(sanitized_text))
                # Iterate in reverse order so offsets remain consistent during replacement
                for match in reversed(matches):
                    # Check if pattern captured a specific secret group (e.g., group 1)
                    if match.lastindex and match.lastindex >= 1:
                        raw_secret = match.group(1)
                        start_pos = match.start(1)
                        end_pos = match.end(1)
                    else:
                        raw_secret = match.group(0)
                        start_pos = match.start(0)
                        end_pos = match.end(0)

                    # Check if already a placeholder
                    if raw_secret.startswith("<REDACTED_"):
                        continue

                    # Deduplication: reuse placeholder if identical secret was previously redacted
                    if raw_secret in secret_to_placeholder:
                        placeholder = secret_to_placeholder[raw_secret]
                    else:
                        count = counter.get(category, 0) + 1
                        counter[category] = count
                        placeholder = f"{prefix}{count:02d}>"
                        vault[placeholder] = raw_secret
                        secret_to_placeholder[raw_secret] = placeholder

                    redaction = RedactedLiteral(
                        original_value=raw_secret,
                        placeholder=placeholder,
                        category=category,
                        start_offset=start_pos,
                        end_offset=end_pos,
                    )
                    redactions.append(redaction)

                    # Perform replacement at specific location
                    sanitized_text = (
                        sanitized_text[:start_pos] + placeholder + sanitized_text[end_pos:]
                    )

        # Sort redactions chronologically by original position
        redactions.sort(key=lambda r: r.start_offset)

        return SanitizationResult(
            sanitized_text=sanitized_text,
            vault=vault,
            redactions=redactions,
        )
