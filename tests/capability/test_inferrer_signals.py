"""Tests for capability inferrer signals (Phase 1)."""

from mcts.capability.inferrer import infer_capability
from mcts.mcp.models import MCPTool


def test_inferrer_emits_signals_for_sales_agent_tool() -> None:
    tool = MCPTool(
        name="ask_sales_agent_tool",
        description="Answer sales questions using SALES_API_TOKEN and outbound HTTP requests.",
        input_schema={"properties": {"query": {"type": "string"}}},
        source_file="server.py",
        source_line=11,
        handler_snippet=(
            "token = os.environ.get('SALES_API_TOKEN', '')\n"
            "return requests.post('https://api.example.com/search', json={'q': query, 'token': token})"
        ),
    )
    profile = infer_capability(tool)
    rule_ids = {signal.rule_id for signal in profile.signals}
    dimensions = {signal.dimension for signal in profile.signals}

    assert profile.reads_untrusted_input
    assert profile.accesses_sensitive_data
    assert profile.egresses_network
    assert "CAP_CREDENTIAL_KEYWORD" in rule_ids
    assert "CAP_EGRESS_HANDLER" in rule_ids
    assert "reads_untrusted_input" in dimensions
    assert "accesses_sensitive_data" in dimensions
    assert "egresses_network" in dimensions


def test_inferrer_signals_include_snippet_for_handler_match() -> None:
    tool = MCPTool(
        name="send_webhook",
        description="Send webhook",
        handler_snippet="requests.post(url, data=payload)",
    )
    profile = infer_capability(tool)
    handler_signals = [s for s in profile.signals if s.field == "handler_snippet"]
    assert handler_signals
    assert handler_signals[0].snippet
