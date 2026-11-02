"""Tests for Phase 1 Security Hardening:
- Loopback default host and PHONIX_API_TOKEN enforcement for non-loopback hosts.
- Middleware: Host header validation, Origin header validation, X-Phonix-Token for non-loopback clients.
- Workspace authorization (_authorize_workspace) returning 403 for unauthorized workspaces.
- Path confinement (_resolve_within) preventing traversal attacks.
- Ambiguous file path detection in surgical edit.
- Encoding auto-repair in surgical edit (only after exact/CRLF fail, only if unique, reported in output).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from src.gateway.proxy_server import (
    create_gateway_app,
    is_loopback_host,
    _resolve_within,
    _authorize_workspace,
)
from src.main import run_server
from src.mcp_server import PhonixMCPServer


# ---------------------------------------------------------------------------
# 1. Loopback Host & PHONIX_API_TOKEN Enforcement
# ---------------------------------------------------------------------------

def test_is_loopback_host():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("127.0.0.2") is True
    assert is_loopback_host("testserver") is True
    assert is_loopback_host("127.0.0.1:8000") is True

    assert is_loopback_host("0.0.0.0") is False
    assert is_loopback_host("192.168.1.5") is False
    assert is_loopback_host("example.com") is False
    assert is_loopback_host("evil.com") is False
    assert is_loopback_host(None) is False


def test_run_server_non_loopback_requires_token(monkeypatch):
    monkeypatch.delenv("PHONIX_API_TOKEN", raising=False)
    monkeypatch.setenv("PHONIX_HOST", "127.0.0.1")
    with pytest.raises(ValueError, match="Non-loopback host '0.0.0.0' requires PHONIX_API_TOKEN"):
        run_server(host="0.0.0.0", port=8000)

    monkeypatch.setenv("PHONIX_API_TOKEN", "secret-token-123")
    with patch("uvicorn.run") as mock_uvicorn:
        run_server(host="0.0.0.0", port=8000)
        assert mock_uvicorn.called


# ---------------------------------------------------------------------------
# 2. HTTP Security Middleware (Host, Origin, X-Phonix-Token)
# ---------------------------------------------------------------------------

def test_middleware_host_header_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("PHONIX_HOST", "127.0.0.1")
    app = create_gateway_app(workspace_root=str(tmp_path), auto_index=False)

    # Valid loopback host headers pass
    client_local = TestClient(app, base_url="http://127.0.0.1:8000")
    resp = client_local.get("/health")
    assert resp.status_code == 200

    client_localhost = TestClient(app, base_url="http://localhost:8000")
    resp = client_localhost.get("/health")
    assert resp.status_code == 200

    # Non-loopback host header while bound to loopback fails with 400
    client_evil = TestClient(app, base_url="http://evil.com")
    resp = client_evil.get("/health")
    assert resp.status_code == 400
    assert "not allowed while gateway is bound to loopback" in resp.json()["detail"]


def test_middleware_origin_header_validation(tmp_path):
    app = create_gateway_app(workspace_root=str(tmp_path), auto_index=False)
    client = TestClient(app)

    # Local origin passes
    resp = client.get("/health", headers={"Origin": "http://127.0.0.1:8000"})
    assert resp.status_code == 200

    resp = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert resp.status_code == 200

    # Non-local origin gets 403
    resp = client.get("/health", headers={"Origin": "http://attacker.com"})
    assert resp.status_code == 403
    assert "not an authorized local origin" in resp.json()["detail"]


def test_middleware_non_loopback_client_token(tmp_path, monkeypatch):
    monkeypatch.setenv("PHONIX_API_TOKEN", "auth-token-xyz")
    app = create_gateway_app(workspace_root=str(tmp_path), auto_index=False)

    # Simulate non-loopback client (192.168.1.100) using TestClient with custom client
    client = TestClient(app, client=("192.168.1.100", 54321))

    # Without token -> 401
    resp = client.get("/health")
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]

    # With invalid token -> 401
    resp = client.get("/health", headers={"X-Phonix-Token": "wrong-token"})
    assert resp.status_code == 401

    # With valid token -> 200
    resp = client.get("/health", headers={"X-Phonix-Token": "auth-token-xyz"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 3. Workspace Authorization (_authorize_workspace)
# ---------------------------------------------------------------------------

def test_workspace_authorization(tmp_path):
    ws_startup = tmp_path / "startup_ws"
    ws_startup.mkdir()
    ws_attached = tmp_path / "attached_ws"
    ws_attached.mkdir()
    ws_unauthorized = tmp_path / "rogue_ws"
    ws_unauthorized.mkdir()

    app = create_gateway_app(workspace_root=str(ws_startup), auto_index=False)
    client = TestClient(app)

    # Startup workspace is authorized
    resp = client.post("/v1/mmu/repo-map", json={"workspace_root": str(ws_startup)})
    assert resp.status_code == 200

    # Default workspace_root (None) authorizes startup workspace
    resp = client.post("/v1/mmu/repo-map", json={})
    assert resp.status_code == 200

    # Unauthorized workspace gets 403 across endpoints
    resp = client.post("/v1/mmu/repo-map", json={"workspace_root": str(ws_unauthorized)})
    assert resp.status_code == 403

    resp = client.post("/v1/mmu/prune", json={"query": "test", "workspace_root": str(ws_unauthorized)})
    assert resp.status_code == 403

    resp = client.post("/v1/mmu/surgical-edit", json={"file_path": "a.txt", "edits": [], "workspace_root": str(ws_unauthorized)})
    assert resp.status_code == 403

    resp = client.post("/v1/workspace/inject-rule", json={"workspace_path": str(ws_unauthorized)})
    assert resp.status_code == 403

    resp = client.post("/v1/workspace/clean-rule", json={"workspace_path": str(ws_unauthorized)})
    assert resp.status_code == 403

    # Attach workspace explicitly
    resp = client.post("/v1/workspace/attach", json={"workspace_path": str(ws_attached)})
    assert resp.status_code == 200

    # Now ws_attached is authorized
    resp = client.post("/v1/mmu/repo-map", json={"workspace_root": str(ws_attached)})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Path Confinement (_resolve_within)
# ---------------------------------------------------------------------------

def test_resolve_within_path_confinement(tmp_path):
    ws_root = tmp_path / "safe_ws"
    ws_root.mkdir()
    sub_dir = ws_root / "subdir"
    sub_dir.mkdir()
    safe_file = sub_dir / "app.py"
    safe_file.write_text("print('safe')")

    outside_file = tmp_path / "secret.env"
    outside_file.write_text("API_SECRET=123")

    # Valid relative and absolute paths within ws_root
    assert _resolve_within(ws_root, "subdir/app.py") == safe_file.resolve()
    assert _resolve_within(ws_root, str(safe_file)) == safe_file.resolve()

    # Path traversal with .. raises PermissionError
    with pytest.raises(PermissionError, match="Path confinement violation"):
        _resolve_within(ws_root, "../secret.env")

    # Absolute path outside ws_root raises PermissionError
    with pytest.raises(PermissionError, match="Path confinement violation"):
        _resolve_within(ws_root, str(outside_file))


def test_surgical_edit_path_confinement(tmp_path):
    ws_root = tmp_path / "ws"
    ws_root.mkdir()
    outside_file = tmp_path / "victim.txt"
    outside_file.write_text("initial")

    server = PhonixMCPServer(workspace_root=str(ws_root))

    # Attempting to surgically edit outside file via traversal raises PermissionError
    with pytest.raises(PermissionError):
        server._tool_surgical_edit(
            file_path="../victim.txt",
            edits=[{"target": "initial", "replacement": "hacked"}],
            workspace_root=str(ws_root),
        )
    assert outside_file.read_text() == "initial"


# ---------------------------------------------------------------------------
# 5. Ambiguous File Path Detection in Surgical Edit
# ---------------------------------------------------------------------------

def test_surgical_edit_ambiguous_matches(tmp_path):
    ws_root = tmp_path / "ws_ambig"
    ws_root.mkdir()
    dir1 = ws_root / "module_a"
    dir1.mkdir()
    file1 = dir1 / "config.json"
    file1.write_text('{"env": "a"}')

    dir2 = ws_root / "module_b"
    dir2.mkdir()
    file2 = dir2 / "config.json"
    file2.write_text('{"env": "b"}')

    server = PhonixMCPServer(workspace_root=str(ws_root))

    # Specifying bare "config.json" should detect multiple matches and raise ValueError
    with pytest.raises(ValueError, match="Ambiguous file path 'config.json': found multiple matches"):
        server._tool_surgical_edit(
            file_path="config.json",
            edits=[{"target": '"env"', "replacement": '"environment"'}],
            workspace_root=str(ws_root),
        )

    # Specifying explicit relative path succeeds
    res = server._tool_surgical_edit(
        file_path="module_a/config.json",
        edits=[{"target": '"env"', "replacement": '"environment"'}],
        workspace_root=str(ws_root),
    )
    assert "Successfully applied" in res
    assert '"environment": "a"' in file1.read_text()


# ---------------------------------------------------------------------------
# 6. Encoding Auto-Repair in Surgical Edit
# ---------------------------------------------------------------------------

def test_surgical_edit_encoding_auto_repair(tmp_path):
    ws_root = tmp_path / "ws_enc"
    ws_root.mkdir()
    target_file = ws_root / "doc.txt"
    # File has smart quotes in utf-8: "“hello”"
    target_file.write_text("Greeting: “hello” world", encoding="utf-8")

    server = PhonixMCPServer(workspace_root=str(ws_root))

    # Simulate client that sent cp1252-decoded target: “hello” in utf-8 is \xe2\x80\x9chello\xe2\x80\x9d
    # If decoded as latin-1 / cp1252, it looks like â€œhelloâ€\x9d
    corrupted_target = "“hello”".encode("utf-8").decode("latin-1")

    res = server._tool_surgical_edit(
        file_path="doc.txt",
        edits=[{"target": f"Greeting: {corrupted_target}", "replacement": "Greeting: 'hi'"}],
        workspace_root=str(ws_root),
    )
    assert "Successfully applied" in res
    assert "encoding auto-repaired edit(s)" in res
    assert target_file.read_text(encoding="utf-8") == "Greeting: 'hi' world"


def test_surgical_edit_encoding_auto_repair_non_unique(tmp_path):
    ws_root = tmp_path / "ws_enc_non_unique"
    ws_root.mkdir()
    target_file = ws_root / "multi.txt"
    # Target appears twice
    target_file.write_text("“hello” and again “hello”", encoding="utf-8")

    server = PhonixMCPServer(workspace_root=str(ws_root))
    corrupted_target = "“hello”".encode("utf-8").decode("latin-1")

    # When repaired target appears multiple times, it must refuse to auto-repair
    with pytest.raises(ValueError, match="target string not found"):
        server._tool_surgical_edit(
            file_path="multi.txt",
            edits=[{"target": corrupted_target, "replacement": "'hi'"}],
            workspace_root=str(ws_root),
        )
