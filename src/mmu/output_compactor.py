"""Terminal Output Compactor for Phonix (`phonix_run_compact`).

Executes validated workspace commands and compacts verbose test, build/lint,
or diff outputs to save token quota while preserving failures, diagnostics,
and a full raw log in `.phonix_runtime/last_cmd_output.log`.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
from typing import Literal

from src.agy_hooks import MALICIOUS_COMMAND_PATTERNS

SLEEP_LOOP_PATTERNS: list[str] = [
    r"(?i)\bStart-Sleep\b",
    r"(?i)\bwhile\s+true\b",
    r"(?i)\bsleep\s+\d+",
]


def estimate_tokens(text: str) -> int:
    """Estimates token count (~4 chars/token) with a minimum of 1 for non-empty text."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def validate_command_safety(command: str) -> None:
    """Validates a shell command against zero-trust malicious and sleep-loop patterns."""
    if not command or not command.strip():
        raise ValueError("Command cannot be empty.")

    for pat in MALICIOUS_COMMAND_PATTERNS:
        if re.search(pat, command):
            raise PermissionError(
                "[Phonix Zero-Trust Gate] Command rejected: detected potential secret exposure or destructive pattern."
            )

    for pat in SLEEP_LOOP_PATTERNS:
        if re.search(pat, command):
            raise PermissionError(
                "[Phonix Circuit Breaker] Command rejected: shell sleep loops are disallowed."
            )


def detect_command_family(
    command: str,
) -> Literal["test", "build_lint", "git_diff", "generic"]:
    """Classifies command into a compactor strategy family."""
    cmd_lower = command.lower().strip()
    if re.search(
        r"\b(pytest|py\.test|unittest|vitest|jest|cargo\s+test|go\s+test|mocha)\b",
        cmd_lower,
    ) or re.search(r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?test\b", cmd_lower):
        return "test"
    if re.search(
        r"\b(tsc|eslint|ruff|mypy|flake8|pylint|biome|cargo\s+check|cargo\s+clippy)\b",
        cmd_lower,
    ) or re.search(r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:build|lint|typecheck)\b", cmd_lower):
        return "build_lint"
    if re.search(r"\bgit\s+diff\b", cmd_lower):
        return "git_diff"
    return "generic"


def _cap_to_token_budget(text: str, max_tokens: int) -> str:
    """Truncates text cleanly by lines to fit within max_tokens (~4 chars/token)."""
    char_budget = max(120, max_tokens * 4)
    if len(text) <= char_budget:
        return text
    lines = text.splitlines()
    kept: list[str] = []
    used = 0
    for line in lines:
        cost = len(line) + 1
        if used + cost > char_budget - 60:
            break
        kept.append(line)
        used += cost
    omitted = len(lines) - len(kept)
    if omitted > 0:
        kept.append(f"... [{omitted} lines truncated to fit {max_tokens}-token budget]")
    return "\n".join(kept)


def _compact_test_output(raw_output: str, max_tokens: int) -> str:
    """Compacts pytest/unittest/vitest/jest/cargo test/go test outputs."""
    lines = raw_output.splitlines()
    if not lines:
        return "(no output)"

    summary_patterns = re.compile(
        r"(?i)(?:^=+\s*.*\b(?:passed|failed|error|skipped|warnings?)\b.*=+$|"
        r"^FAILED\b|^ERROR\b|^Tests?:\s|^Test Suites:\s|^FAIL\s|^---\s+FAIL:|"
        r"^test result:|^\s*Ran\s+\d+\s+test|^OK(?:\s+\(.*\))?$)"
    )
    error_patterns = re.compile(
        r"(?i)(?:^\s*E\s+|AssertionError|Error:|Expected:|Received:|panicked at|Traceback)"
    )
    progress_noise = re.compile(r"^[\.\sFEfxs]+$")

    summary_lines: list[str] = []
    failure_blocks: list[str] = []
    seen_lines: set[str] = set()

    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped or progress_noise.match(stripped):
            i += 1
            continue

        if summary_patterns.search(stripped):
            if stripped not in seen_lines:
                summary_lines.append(line)
                seen_lines.add(stripped)
            i += 1
            continue

        # Capture failure tracebacks / assertion contexts (±3 lines around error/project frame)
        if error_patterns.search(line) or re.match(r"^_{3,}\s+.+\s+_{3,}$", stripped):
            start = max(0, i - 3)
            end = min(n, i + 4)
            block: list[str] = []
            for j in range(start, end):
                candidate = lines[j]
                if "site-packages" in candidate or "node_modules" in candidate:
                    continue
                block.append(candidate)
            block_str = "\n".join(block).strip()
            if block_str and block_str not in seen_lines:
                failure_blocks.append(block_str)
                seen_lines.add(block_str)
            i = end
            continue

        # Keep explicit FAIL / ERROR file lines
        if re.search(r"(?i)\b(?:FAIL|FAILED|ERROR)\b", line) and "PASSED" not in line:
            if stripped not in seen_lines:
                failure_blocks.append(line)
                seen_lines.add(stripped)
        i += 1

    parts: list[str] = []
    if failure_blocks:
        parts.extend(failure_blocks)
    if summary_lines:
        parts.extend(summary_lines)
    if not parts:
        return _compact_generic_output(raw_output, max_tokens)

    return _cap_to_token_budget("\n".join(parts), max_tokens)


def _compact_build_lint_output(raw_output: str, max_tokens: int) -> str:
    """Compacts tsc/eslint/ruff/mypy/build outputs, deduplicating diagnostics."""
    lines = raw_output.splitlines()
    if not lines:
        return "(no output)"

    diag_re = re.compile(
        r"(?i)(?:error\s+TS\d+|:\d+:\d+[:\s-]+(?:error|warn(?:ing)?)|"
        r"\(\d+,\d+\):\s*error|Found\s+\d+\s+errors?|\d+\s+errors?\s+and\s+\d+\s+warnings?|"
        r"Build\s+(?:failed|succeeded)|Compiled\s+successfully)"
    )

    kept: list[str] = []
    seen: set[str] = set()
    dup_count = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if diag_re.search(line) or re.search(r"(?i)\b(?:error|warning|failed)\b", line):
            norm = re.sub(r"\s+", " ", stripped)
            if norm in seen:
                dup_count += 1
                continue
            seen.add(norm)
            kept.append(line)

    if dup_count > 0:
        kept.append(f"... [{dup_count} duplicate diagnostic line(s) deduplicated]")

    if not kept:
        return _compact_generic_output(raw_output, max_tokens)
    return _cap_to_token_budget("\n".join(kept), max_tokens)


def _compact_git_diff_output(raw_output: str, max_tokens: int) -> str:
    """Compacts git diff keeping file headers, hunk headers, and changed lines within budget."""
    lines = raw_output.splitlines()
    if not lines:
        return "(empty diff)"

    kept: list[str] = []
    for line in lines:
        if line.startswith(("diff --git ", "--- ", "+++ ", "@@ ", "+", "-")):
            kept.append(line)
    if not kept:
        kept = lines
    return _cap_to_token_budget("\n".join(kept), max_tokens)


def _compact_generic_output(raw_output: str, max_tokens: int) -> str:
    """Compacts generic output: head + error/warn lines + tail within token budget."""
    lines = raw_output.splitlines()
    if not lines:
        return "(no output)"

    if estimate_tokens(raw_output) <= max_tokens:
        return raw_output

    head = lines[:8]
    tail = lines[-8:] if len(lines) > 16 else []
    important_re = re.compile(r"(?i)\b(error|fail|failed|exception|traceback|warn|warning)\b")

    seen = set(head) | set(tail)
    important: list[str] = []
    for line in lines[8 : max(8, len(lines) - 8)]:
        if important_re.search(line) and line not in seen:
            important.append(line)
            seen.add(line)

    combined: list[str] = list(head)
    if important:
        combined.append("... [filtered diagnostic lines] ...")
        combined.extend(important)
    elif len(lines) > 16:
        combined.append(f"... [{len(lines) - 16} middle lines omitted] ...")
    combined.extend(tail)
    return _cap_to_token_budget("\n".join(combined), max_tokens)


def compact_command_output(
    command: str,
    raw_output: str,
    exit_code: int,
    max_tokens: int = 800,
    log_rel_path: str = ".phonix_runtime/last_cmd_output.log",
) -> str:
    """Compacts raw command output according to command family and appends metrics footer."""
    raw_tokens = estimate_tokens(raw_output)
    body_budget = max(60, max_tokens - 30)
    family = detect_command_family(command)

    if family == "test":
        compacted_body = _compact_test_output(raw_output, body_budget)
    elif family == "build_lint":
        compacted_body = _compact_build_lint_output(raw_output, body_budget)
    elif family == "git_diff":
        compacted_body = _compact_git_diff_output(raw_output, body_budget)
    else:
        compacted_body = _compact_generic_output(raw_output, body_budget)

    compact_tokens = estimate_tokens(compacted_body)
    if raw_tokens > 0:
        savings_pct = max(0.0, round((1.0 - (compact_tokens / raw_tokens)) * 100.0, 1))
    else:
        savings_pct = 0.0

    footer = (
        f"[exit_code={exit_code} | raw={raw_tokens} tokens -> compact={compact_tokens} tokens "
        f"(-{savings_pct}%) | full_log={log_rel_path}]"
    )
    return f"{compacted_body}\n\n{footer}"


def run_and_compact(
    command: str,
    workspace_root: str | Path = ".",
    max_tokens: int = 800,
    timeout_sec: int = 60,
) -> str:
    """Validates, executes, logs raw output, and returns compacted terminal output."""
    validate_command_safety(command)
    ws_path = Path(workspace_root).resolve()

    exit_code = 0
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=str(ws_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        exit_code = proc.returncode
        raw_parts = [p for p in (proc.stdout, proc.stderr) if p]
        raw_output = "\n".join(raw_parts).strip()
    except subprocess.TimeoutExpired as exc:
        exit_code = -1
        out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        raw_output = f"{out}\n{err}\n[Command timed out after {timeout_sec}s]".strip()

    log_dir = ws_path / ".phonix_runtime"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "last_cmd_output.log"
    log_file.write_text(raw_output, encoding="utf-8")

    return compact_command_output(
        command=command,
        raw_output=raw_output,
        exit_code=exit_code,
        max_tokens=max_tokens,
        log_rel_path=".phonix_runtime/last_cmd_output.log",
    )
