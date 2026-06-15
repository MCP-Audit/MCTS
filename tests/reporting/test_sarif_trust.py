"""SARIF export with findings trust display fields."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.sarif import build_sarif

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_sarif_level_uses_display_severity_when_capped() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    sarif = build_sarif(report)
    chain_results = [
        r for r in sarif["runs"][0]["results"] if r.get("properties", {}).get("analyzer") == "attack_chains"
    ]
    assert chain_results
    for result in chain_results:
        assert result["level"] == "warning"
        assert result["properties"]["display_severity"] == "medium"
        assert result["properties"]["severity"] == "critical"
        assert result["properties"]["evidence_type"] == "capability_overlap"
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for result in chain_results:
        rule = rules[result["ruleId"]]
        assert rule["properties"]["security-severity"] == "5.0"
