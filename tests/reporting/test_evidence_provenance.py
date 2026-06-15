"""Phase 1 evidence provenance on attack-chain findings."""

from pathlib import Path

from mcts.capability.inferrer import infer_capability
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPTool
from mcts.reporting.evidence_provenance import enrich_provenance
from mcts.reporting.finding_validator import ValidationContext, validate_findings
from mcts.reporting.models import Finding, Severity

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_attack_chain_enforce_includes_facts_and_confidence_factors() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    chains = [f for f in report.findings if f.analyzer == "attack_chains"]
    assert chains
    finding = chains[0]
    facts = finding.evidence.get("facts") or []
    assert facts
    assert any(f.get("rule_id") == "CAP_CREDENTIAL_KEYWORD" for f in facts)
    factors = finding.evidence.get("confidence_factors") or []
    assert any("single-tool overlap" in item for item in factors)
    assert finding.rule_stability == "heuristic"
    interpretation = finding.evidence.get("interpretation") or {}
    assert interpretation.get("mcp_context", {}).get("tool_exposed") is True


def test_provenance_enricher_builds_counterfactual_from_tool_signals() -> None:
    tool = MCPTool(
        name="ask_sales_agent_tool",
        description="Uses SALES_API_TOKEN and HTTP requests.",
        input_schema={"properties": {"query": {"type": "string"}}},
        handler_snippet="requests.post('https://example.com', json={'token': token})",
        capability=infer_capability(
            MCPTool(
                name="ask_sales_agent_tool",
                description="Uses SALES_API_TOKEN and HTTP requests.",
                input_schema={"properties": {"query": {"type": "string"}}},
                handler_snippet="requests.post('https://example.com', json={'token': token})",
            )
        ),
    )
    finding = Finding(
        id="chain-credential-theft",
        analyzer="attack_chains",
        title="Credential theft chain possible",
        description="overlap",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={
            "read_tools": ["ask_sales_agent_tool"],
            "credential_tools": ["ask_sales_agent_tool"],
            "exfil_tools": ["ask_sales_agent_tool"],
            "single_tool_overlap": True,
        },
    )
    ctx = ValidationContext(scan_scope="repository", tools=[tool], attack_graph={}, mode="enforce")
    validated = validate_findings([finding], ctx)[0]
    enriched = enrich_provenance([validated], ctx)[0]
    counter = enriched.evidence.get("counterfactual_remediation") or {}
    assert counter.get("triggered_by")
    assert counter.get("actions")


def test_dashboard_payload_exposes_provenance_fields() -> None:
    from mcts.report.data import build_dashboard_payload

    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    payload = build_dashboard_payload(report)
    chain = next(row for row in payload["findings"] if row["analyzer"] == "attack_chains")
    assert chain["has_provenance"]
    assert chain["facts"]
    assert chain["confidence_factors"]
