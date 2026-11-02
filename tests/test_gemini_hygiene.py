"""Tests for Phase 2 Machine Hygiene:
- Real ~/.gemini directory remains 100% untouched throughout tests.
- Autouse fixture isolates Path.home(), HOME, USERPROFILE, APPDATA, LOCALAPPDATA.
- Hook/circuit state is stored repo-locally under .phonix_runtime/ instead of ~/.gemini.
- 'phonix doctor' scans, lists, and with --fix backs up and removes leftovers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest

from tests.conftest import _REAL_HOME, _REAL_GEMINI, get_real_gemini_violations
from src.agy_hooks import _get_circuit_state_path, _load_circuit_state, _save_circuit_state, PHONIX_RUNTIME_DIR
from src.main import find_phonix_leftovers, doctor_command


def test_real_gemini_directory_untouched():
    """Requirement 3: Verifies that the real ~/.gemini directory was completely untouched."""
    violations = get_real_gemini_violations()
    assert not violations, f"Real ~/.gemini directory was modified: {violations}"


def test_autouse_home_isolation(tmp_path):
    """Requirement 2: Verifies that Path.home() and environment variables point to an isolated temp dir."""
    current_home = Path.home()
    assert current_home != _REAL_HOME
    assert os.environ.get("HOME") == str(current_home)
    assert os.environ.get("USERPROFILE") == str(current_home)
    assert os.environ.get("APPDATA") == str(current_home / "AppData" / "Roaming")
    assert os.environ.get("LOCALAPPDATA") == str(current_home / "AppData" / "Local")


def test_circuit_state_repo_local(tmp_path, monkeypatch):
    """Requirement 1: Verifies hook/circuit state saves to .phonix_runtime/ and never to ~/.gemini."""
    monkeypatch.delenv("PHONIX_CIRCUIT_STATE_PATH", raising=False)
    state_path = _get_circuit_state_path()
    assert state_path == PHONIX_RUNTIME_DIR / "circuit_state.json"
    assert ".gemini" not in str(state_path)

    # Save state to a temp path via env var to verify load/save works cleanly
    temp_state = tmp_path / "custom_runtime" / "circuit_state.json"
    monkeypatch.setenv("PHONIX_CIRCUIT_STATE_PATH", str(temp_state))
    assert _get_circuit_state_path() == temp_state

    test_data = {"turn_count": 5, "last_tool_name": "read_file"}
    _save_circuit_state(test_data)
    assert temp_state.is_file()

    loaded = _load_circuit_state()
    assert loaded.get("turn_count") == 5
    assert loaded.get("last_tool_name") == "read_file"


def test_phonix_doctor_detects_leftovers(tmp_path):
    """Requirement 4: Verifies 'phonix doctor' scans and lists leftovers across categories."""
    fake_home = tmp_path / "fake_home"
    gemini_dir = fake_home / ".gemini"

    # Seed leftovers:
    # 1. State
    state_file = gemini_dir / "phonix_circuit_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text("{}", encoding="utf-8")

    # 2. Rule
    rules_dir = gemini_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / "PhonixHP.md"
    rule_file.write_text("# Phonix rule", encoding="utf-8")

    # 3. Skill
    skill_dir = gemini_dir / "skills" / "phonix_quota_skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text("# Skill", encoding="utf-8")

    # 4. MCP Config
    mcp_file = gemini_dir / "mcp_config.json"
    mcp_file.write_text(
        json.dumps({"mcpServers": {"phonix-mmu": {"command": "python"}, "other-server": {}}}),
        encoding="utf-8",
    )

    # 5. Log
    log_file = gemini_dir / "logs" / "phonix_debug.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text("log line", encoding="utf-8")

    # Scan
    leftovers = find_phonix_leftovers(fake_home)
    assert len(leftovers["state"]) == 1
    assert len(leftovers["rules"]) == 1
    assert len(leftovers["skills"]) == 1
    assert len(leftovers["mcp_configs"]) == 1
    assert len(leftovers["logs"]) == 1

    # Doctor report (fix=False)
    ret = doctor_command(fix=False, home_dir=fake_home)
    assert ret == 0
    # Files should still exist
    assert state_file.is_file()
    assert rule_file.is_file()
    assert skill_dir.is_dir()


def test_phonix_doctor_fix_workflow(tmp_path):
    """Requirement 4: Verifies 'phonix doctor --fix' prompts y/N, backs up to ~/phonix_leftovers_backup/, and cleans."""
    fake_home = tmp_path / "fake_home_fix"
    gemini_dir = fake_home / ".gemini"

    # Seed leftovers
    state_file = gemini_dir / "phonix_circuit_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text('{"turn": 1}', encoding="utf-8")

    rules_dir = gemini_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / "PhonixHP.md"
    rule_file.write_text("# Old Rule", encoding="utf-8")

    mcp_file = gemini_dir / "mcp_config.json"
    mcp_file.write_text(
        json.dumps({"mcpServers": {"phonix-mmu": {"command": "python"}, "keep-server": {"command": "node"}}}),
        encoding="utf-8",
    )

    # Test cancelled prompt ("n")
    with patch("builtins.input", return_value="n"):
        ret_cancel = doctor_command(fix=True, home_dir=fake_home)
        assert ret_cancel == 0
        assert state_file.is_file()
        assert rule_file.is_file()

    # Test confirmed prompt ("y")
    with patch("builtins.input", return_value="y"):
        ret_ok = doctor_command(fix=True, home_dir=fake_home)
        assert ret_ok == 0

    # Verify backed up
    backup_dir = fake_home / "phonix_leftovers_backup"
    assert backup_dir.is_dir()
    assert (backup_dir / "phonix_circuit_state.json").is_file()
    assert (backup_dir / "PhonixHP.md").is_file()
    assert (backup_dir / "mcp_config.json.bak").is_file()

    # Verify leftovers removed from .gemini
    assert not state_file.exists()
    assert not rule_file.exists()

    # Verify MCP config has phonix-mmu removed but keeps other servers
    mcp_data = json.loads(mcp_file.read_text(encoding="utf-8"))
    assert "phonix-mmu" not in mcp_data.get("mcpServers", {})
    assert "keep-server" in mcp_data.get("mcpServers", {})
