"""Scanner integration for findings trust mode."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.models import Severity

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")
VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")


def test_scanner_compliance_gets_rule_stability() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    compliance = [f for f in report.findings if f.analyzer == "compliance"]
    assert compliance
    assert compliance[0].rule_stability == "mature"


def test_scanner_populates_display_summary_when_trust_enforced() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, findings_trust_mode="enforce")).run()
    assert report.summary.critical >= 1
    assert report.display_summary is not None
    assert report.display_summary.total >= 1
    assert all(f.severity.value in {"critical", "high", "medium", "low"} for f in report.findings)


def test_scanner_trust_off_leaves_display_summary_empty() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, findings_trust_mode="off")).run()
    assert report.display_summary is None


def test_single_tool_overlap_fixture_zero_display_critical() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    chains = [f for f in report.findings if f.analyzer == "attack_chains"]
    assert chains, "expected attack chain findings on single-tool overlap fixture"
    assert report.display_summary is not None
    assert report.display_summary.critical == 0
    for finding in chains:
        assert finding.display_severity == Severity.MEDIUM
        assert finding.evidence_type == "capability_overlap"
