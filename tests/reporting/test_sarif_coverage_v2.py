"""SARIF coverage filter and v2 per-finding metadata."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.sarif import build_sarif


def test_sarif_excludes_compliance_coverage_by_default() -> None:
    report = Scanner(
        ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"), scoring_mode="both")
    ).run()
    sarif = build_sarif(report)
    compliance = [
        r for r in sarif["runs"][0]["results"] if r.get("properties", {}).get("analyzer") == "compliance"
    ]
    assert not compliance
    assert any(f.analyzer == "compliance" for f in report.findings)


def test_sarif_includes_v2_risk_contribution_on_top_findings() -> None:
    report = Scanner(
        ScanConfig(
            target=Path("examples/vulnerable-mcp-server/server.py"),
            scoring_mode="v2",
        )
    ).run()
    sarif = build_sarif(report)
    props = sarif["runs"][0]["properties"]
    assert "mcts/v2TopContributors" in props
    results_with_v2 = [
        r for r in sarif["runs"][0]["results"] if "mcts/v2RiskContribution" in r.get("properties", {})
    ]
    assert results_with_v2


def test_sarif_include_coverage_flag() -> None:
    report = Scanner(ScanConfig(target=Path("examples/vulnerable-mcp-server/server.py"))).run()
    included = build_sarif(report, include_coverage_findings=True)
    compliance = [
        r for r in included["runs"][0]["results"] if r.get("properties", {}).get("analyzer") == "compliance"
    ]
    assert compliance
