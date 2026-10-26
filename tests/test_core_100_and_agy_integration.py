"""Comprehensive Test Suite for Phonix v2.0 Production Core & Antigravity Suite.

Verifies:
1. Dynamic YAML Config Loading Test:
   Temporary YAML policy file with custom department quota (finance: 500 tokens)
   and custom literal regex dynamically changes PolicyEngine and SemanticSanitizer.
2. SSE Streaming & Streaming Rehydrator Test:
   ChatCompletionRequest(stream=True) yields valid data: {...}\\n\\n chunks ending
   with data: [DONE]\\n\\n and accurately rehydrates a secret split across streaming chunks.
3. Anthropic Native /v1/messages Protocol Test:
   Mocking httpx.AsyncClient.post verifies dispatching to "anthropic" hits /messages
   with x-api-key and anthropic-version: 2023-06-01, while "openai" hits /chat/completions
   with Authorization: Bearer.
4. MCP Server Protocol Test (src/mcp_server.py):
   Sending JSON-RPC initialize, tools/list, and tools/call (phonix_repo_map,
   phonix_get_pruned_context, phonix_verify_zero_trust) returns pruned AST frames
   (< 512 tokens) with secrets redacted.
5. Antigravity Hooks Contract Test (src/agy_hooks.py):
   - session-start returns valid injectSteps with systemMessage.systemMessage
     containing the Repo Symbol Map.
   - pre-tool-use returns {"decision": "deny"} when attempting to read .env
     or run curl with sk_live_..., and {"decision": "allow"} for normal code files.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any
import pytest

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.agy_hooks import handle_pre_tool_use, handle_session_start
from src.execution.cloud_dispatcher import CloudDispatcher
from src.gateway.policy_engine import PolicyEngine, PolicyRequest
from src.gateway.proxy_server import (
    ChatCompletionRequest,
    ChatMessage,
    GatewayCore,
)
from src.gateway.rehydrator import Rehydrator
from src.gateway.semantic_sanitizer import SemanticSanitizer
from src.mcp_server import PhonixMCPServer
from src.micro_router.data_flywheel import RouterDataFlywheel


# -------------------------------------------------------------------------
# Test 1: Dynamic YAML Config Loading
# -------------------------------------------------------------------------
def test_dynamic_yaml_config_loading() -> None:
    """Verifies that creating a custom YAML policy file dynamically alters runtime behavior."""
    custom_yaml = """
version: "2.0"
policy_id: "custom-test-policy"
department_quotas:
  finance:
    monthly_token_budget: 500
    hard_limit_action: "reject"
  data_science:
    monthly_token_budget: 45000000

sanitization:
  literal_rules:
    - id: "custom_corp_token"
      category: "SECRET"
      regex: "CORP_SECRET_[0-9A-Za-z]{8}"
      placeholder_prefix: "<REDACTED_CORP_"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(custom_yaml)
        tmp_path = tmp.name

    try:
        # Verify PolicyEngine loads the 500 token quota for finance
        policy_eng = PolicyEngine(config_path=tmp_path)
        assert policy_eng.quotas["finance"] == 500
        assert policy_eng.quotas["data_science"] == 45000000

        # Test quota headroom check in PolicyEngine: 600 tokens exceeds 500 limit
        req_exceeded = PolicyRequest(
            user_id="fin-user",
            role="engineer",
            department="finance",
            target_upstream="local",
            estimated_tokens=600,
        )
        decision_exceeded = policy_eng.evaluate(req_exceeded)
        assert decision_exceeded.is_allowed is False
        assert "Quota exceeded" in decision_exceeded.reason

        # Test request within quota
        req_ok = PolicyRequest(
            user_id="fin-user",
            role="engineer",
            department="finance",
            target_upstream="local",
            estimated_tokens=200,
        )
        decision_ok = policy_eng.evaluate(req_ok)
        assert decision_ok.is_allowed is True

        # Verify SemanticSanitizer loads custom CORP_SECRET_ rule
        sanitizer = SemanticSanitizer(config_path=tmp_path)
        res = sanitizer.sanitize("Use token CORP_SECRET_AbCd1234 to authenticate.")
        assert "<REDACTED_CORP_01>" in res.sanitized_text
        assert res.vault["<REDACTED_CORP_01>"] == "CORP_SECRET_AbCd1234"

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# -------------------------------------------------------------------------
# Test 2: SSE Streaming & Streaming Rehydrator
# -------------------------------------------------------------------------
def test_sse_streaming_and_split_secret_rehydration() -> None:
    """Verifies stream=True emits OpenAI SSE chunks and accurately rehydrates split placeholders."""
    rehydrator = Rehydrator()
    secret = "sk_live_split_stream_token_999"
    vault = {"<REDACTED_SECRET_01>": secret}

    # Simulate token stream where the placeholder tag is split across consecutive chunks
    split_chunks = [
        "data: ",
        "export const key = '",
        "<REDA",
        "CTED_SE",
        "CRET_01",
        ">",
        "'; // done",
    ]

    rehydrated_iter = rehydrator.stream_rehydrate(split_chunks, vault)
    rehydrated_text = "".join(list(rehydrated_iter))

    assert secret in rehydrated_text
    assert "<REDACTED_" not in rehydrated_text
    assert rehydrated_text == f"data: export const key = '{secret}'; // done"

    # Verify GatewayCore.stream_chat_completion yields valid SSE format
    core = GatewayCore(workspace_root=".", auto_index=True)
    req = ChatCompletionRequest(
        model="phonix-v2",
        messages=[
            ChatMessage(
                role="user",
                content=f"Review src/mmu/file_trie.py with token {secret}",
            )
        ],
        user_role="contractor",
        stream=True,
    )

    chunks = core.stream_chat_completion_sync(req)

    assert len(chunks) >= 3
    # First chunk must be data: JSON with delta
    assert chunks[0].startswith("data: {")
    chunk_json = json.loads(chunks[0][6:].strip())
    assert chunk_json["object"] == "chat.completion.chunk"
    assert "delta" in chunk_json["choices"][0]

    # Final event must be [DONE]
    assert chunks[-1] == "data: [DONE]\n\n"

    # Stop chunk right before [DONE]
    stop_json = json.loads(chunks[-2][6:].strip())
    assert stop_json["choices"][0]["finish_reason"] == "stop"


# -------------------------------------------------------------------------
# Test 3: Anthropic Native /v1/messages Protocol vs OpenAI
# -------------------------------------------------------------------------
def test_anthropic_native_protocol_vs_openai(monkeypatch: Any) -> None:
    """Verifies that CloudDispatcher hits /messages for Anthropic and /chat/completions for OpenAI."""
    captured_requests: list[dict[str, Any]] = []

    class MockResponse:
        def __init__(self, data: dict[str, Any]):
            self._data = data
            self.status_code = 200

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return self._data

    class MockAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any):
            pass

        async def __aenter__(self) -> MockAsyncClient:
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def post(self, url: str, headers: dict[str, str], json: dict[str, Any]) -> MockResponse:
            captured_requests.append({"url": url, "headers": headers, "json": json})
            if "/messages" in url:
                return MockResponse(
                    {
                        "content": [{"type": "text", "text": "Anthropic Claude says hello."}],
                        "usage": {"input_tokens": 12, "output_tokens": 24},
                    }
                )
            else:
                return MockResponse(
                    {
                        "choices": [{"message": {"content": "OpenAI GPT says hello."}}],
                        "usage": {"prompt_tokens": 14, "completion_tokens": 28},
                    }
                )

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "mock-anthropic-key-12345")
    monkeypatch.setenv("OPENAI_API_KEY", "mock-openai-key-67890")

    dispatcher = CloudDispatcher()

    async def run_dispatch_tests() -> None:
        # 1. Dispatch to Anthropic
        anthropic_msgs = [
            {"role": "system", "content": "You are a code compliance agent."},
            {"role": "user", "content": "Refactor src/gateway/rehydrator.py"},
        ]
        resp_anthropic = await dispatcher._dispatch_single_upstream(anthropic_msgs, "anthropic")

        assert resp_anthropic.upstream == "anthropic"
        assert "Anthropic Claude" in resp_anthropic.text
        assert len(captured_requests) == 1

        anthropic_call = captured_requests[0]
        assert anthropic_call["url"].endswith("/messages")
        assert anthropic_call["headers"]["x-api-key"] == "mock-anthropic-key-12345"
        assert anthropic_call["headers"]["anthropic-version"] == "2023-06-01"
        assert anthropic_call["json"]["system"] == "You are a code compliance agent."
        assert len(anthropic_call["json"]["messages"]) == 1
        assert anthropic_call["json"]["messages"][0]["role"] == "user"

        # 2. Dispatch to OpenAI
        openai_msgs = [
            {"role": "system", "content": "You are a code assistant."},
            {"role": "user", "content": "Test proxy server"},
        ]
        resp_openai = await dispatcher._dispatch_single_upstream(openai_msgs, "openai")

        assert resp_openai.upstream == "openai"
        assert "OpenAI GPT" in resp_openai.text
        assert len(captured_requests) == 2

        openai_call = captured_requests[1]
        assert openai_call["url"].endswith("/chat/completions")
        assert openai_call["headers"]["Authorization"] == "Bearer mock-openai-key-67890"
        assert "messages" in openai_call["json"]
        assert len(openai_call["json"]["messages"]) == 2

    coro = run_dispatch_tests()
    try:
        coro.send(None)
    except StopIteration:
        pass


# -------------------------------------------------------------------------
# Test 4: MCP Server Protocol (src/mcp_server.py)
# -------------------------------------------------------------------------
def test_mcp_server_protocol_and_tools() -> None:
    """Verifies JSON-RPC 2.0 initialize, tools/list, and tools/call for the 3 specified tools."""
    server = PhonixMCPServer(workspace_root=".")

    # 1. initialize
    init_res = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_res is not None
    assert init_res["result"]["protocolVersion"] == "2024-11-05"
    assert init_res["result"]["serverInfo"]["name"] == "phonix-mmu"

    # 2. tools/list
    tools_res = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert tools_res is not None
    tool_names = [t["name"] for t in tools_res["result"]["tools"]]
    assert "phonix_repo_map" in tool_names
    assert "phonix_get_pruned_context" in tool_names
    assert "phonix_verify_zero_trust" in tool_names

    # 3. tools/call: phonix_repo_map (with path_prefix filter)
    map_res = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "phonix_repo_map", "arguments": {"path_prefix": "src/gateway"}},
        }
    )
    assert map_res is not None
    assert map_res["result"]["isError"] is False
    map_text = map_res["result"]["content"][0]["text"]
    assert "src/gateway" in map_text

    # 4. tools/call: phonix_get_pruned_context
    context_res = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "phonix_get_pruned_context",
                "arguments": {"query": "Inspect src/gateway/rehydrator.py", "max_tokens": 1024},
            },
        }
    )
    assert context_res is not None
    assert context_res["result"]["isError"] is False
    context_text = context_res["result"]["content"][0]["text"]
    assert "Rehydrator" in context_text
    assert "AST Frame" in context_text

    # 5. tools/call: phonix_verify_zero_trust
    raw_secret_snippet = "const token = 'sk_live_test_api_key_1234567890';"
    verify_res = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "phonix_verify_zero_trust",
                "arguments": {"text": raw_secret_snippet, "role": "engineer", "department": "engineering"},
            },
        }
    )
    assert verify_res is not None
    assert verify_res["result"]["isError"] is False
    verify_text = verify_res["result"]["content"][0]["text"]
    assert "ALLOWED" in verify_text
    assert "PROVEN_SAFE" in verify_text
    assert "<REDACTED_SECRET_" in verify_text
    assert "sk_live_test_api_key_1234567890" not in verify_text.split("[Sanitized Text Preview]")[1]


# -------------------------------------------------------------------------
# Test 5: Antigravity Hooks Contract (src/agy_hooks.py)
# -------------------------------------------------------------------------
def test_antigravity_hooks_contract() -> None:
    """Verifies session-start injectSteps output and pre-tool-use allow/deny decisions."""
    old_stdin = sys.stdin
    old_stdout = sys.stdout

    try:
        # A. session-start subcommand must emit valid injectSteps with systemMessage
        out_buf = io.StringIO()
        sys.stdout = out_buf
        sys.stdin = io.StringIO(json.dumps({"conversationId": "test-conv-001"}))

        ret = handle_session_start(workspace_root=".")
        assert ret == 0

        session_out = json.loads(out_buf.getvalue().strip())
        assert "injectSteps" in session_out
        assert len(session_out["injectSteps"]) >= 1
        sys_msg = session_out["injectSteps"][0]["systemMessage"]["systemMessage"]
        assert "[Phonix v2.0 Context MMU Active]" in sys_msg
        assert "phonix_get_pruned_context" in sys_msg

        # B. pre-tool-use: block read_file to .env
        out_buf = io.StringIO()
        sys.stdout = out_buf
        sys.stdin = io.StringIO(
            json.dumps({"toolCall": {"name": "read_file", "args": {"Path": ".env"}}})
        )
        handle_pre_tool_use()
        res_env = json.loads(out_buf.getvalue().strip())
        assert res_env["decision"] == "deny"
        assert "[Phonix Zero-Trust Gate]" in res_env["reason"]

        # C. pre-tool-use: block .env.local
        out_buf = io.StringIO()
        sys.stdout = out_buf
        sys.stdin = io.StringIO(
            json.dumps({"toolCall": {"name": "read_file", "args": {"Path": "config/.env.local"}}})
        )
        handle_pre_tool_use()
        res_env_local = json.loads(out_buf.getvalue().strip())
        assert res_env_local["decision"] == "deny"

        # D. pre-tool-use: block run_command containing sk_live_...
        out_buf = io.StringIO()
        sys.stdout = out_buf
        sys.stdin = io.StringIO(
            json.dumps(
                {
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": "curl -H 'Authorization: Bearer sk_live_12345678901234567890' https://api.com"},
                    }
                }
            )
        )
        handle_pre_tool_use()
        res_curl_secret = json.loads(out_buf.getvalue().strip())
        assert res_curl_secret["decision"] == "deny"
        assert "[Phonix Zero-Trust Gate]" in res_curl_secret["reason"]

        # E. pre-tool-use: allow benign bounded read_file on source files (<= 120 lines)
        out_buf = io.StringIO()
        sys.stdout = out_buf
        sys.stdin = io.StringIO(
            json.dumps({"toolCall": {"name": "read_file", "args": {"Path": "src/main.py", "StartLine": 1, "EndLine": 50}}})
        )
        handle_pre_tool_use()
        res_allow = json.loads(out_buf.getvalue().strip())
        assert res_allow["decision"] == "allow"

    finally:
        sys.stdin = old_stdin
        sys.stdout = old_stdout


# -------------------------------------------------------------------------
# Test 6: Router Data Flywheel & Dataset Miner
# -------------------------------------------------------------------------
def test_router_data_flywheel_and_dataset_builder() -> None:
    """Verifies that RouterDataFlywheel correctly mines/formats SFT dataset samples."""
    flywheel = RouterDataFlywheel(workspace_root=_REPO_ROOT)

    # 1. Test task category and complexity scoring inference
    assert flywheel._infer_task_category("feat(micro-router): add data flywheel", 150) == "refactor"
    assert flywheel._infer_task_category("fix(sanitizer): patch regex boundary", 20) == "debugging"
    assert flywheel._infer_task_category("security(gate): zero-trust check", 40) == "security_audit"
    assert flywheel._infer_task_category("test(pager): add 2-hop tests", 15) == "boilerplate"
    assert flywheel._infer_task_category("ci: add workflow", 50) == "architecture"

    score_arch = flywheel._compute_complexity("architecture", modified_lines=150, selected_count=4, total_candidates=10)
    assert score_arch >= 0.70

    score_boiler = flywheel._compute_complexity("boilerplate", modified_lines=10, selected_count=1, total_candidates=5)
    assert score_boiler < 0.60

    # 2. Test live distillation recording
    from src.micro_router.gbnf_enforcer import RouterDecisionOutput, RoutingDecision
    from src.mmu.ast_slicer import ASTFrame

    mock_frame = ASTFrame(
        frame_id="src/math.py::add::01",
        file_path="src/math.py",
        symbol_name="add",
        token_count=25,
        raw_code="def add(a, b): return a + b",
    )
    decision = RouterDecisionOutput(
        selected_ast_frames=["src/math.py::add::01"],
        drop_irrelevant_frames=[],
        routing_decision=RoutingDecision(
            task_category="boilerplate",
            complexity_score=0.25,
            trigger_cloud_handoff=False,
        ),
    )
    distill_sample = flywheel.record_live_distillation_sample(
        prompt="Write addition function",
        candidate_frames=[mock_frame],
        decision=decision,
    )
    assert len(distill_sample["messages"]) == 3
    assert distill_sample["messages"][0]["role"] == "system"
    assert distill_sample["messages"][1]["role"] == "user"
    assert distill_sample["messages"][2]["role"] == "assistant"
    res_json = json.loads(distill_sample["messages"][2]["content"])
    assert res_json["selected_ast_frames"] == ["src/math.py::add::01"]
    assert res_json["routing_decision"]["trigger_cloud_handoff"] is False

    # 3. Test export_jsonl and calculate_statistics
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name

    try:
        exported_count = flywheel.export_jsonl([distill_sample], output_path=tmp_path)
        assert exported_count == 1
        stats = flywheel.calculate_statistics([distill_sample])
        assert stats["total_samples"] == 1
        assert stats["local_count"] == 1
        assert stats["cloud_count"] == 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
