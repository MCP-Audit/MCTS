"""Scan gate integration with findings trust display summary."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.scan_gates import evaluate_scan_gate_violations

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_fail_on_critical_passes_with_enforce_on_overlap_fixture() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    assert report.summary.critical >= 1
    assert report.display_summary is not None
    assert report.display_summary.critical == 0

    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_critical=True,
    )
    assert evaluate_scan_gate_violations(report, config) == []


def test_fail_on_critical_fails_without_trust_on_overlap_fixture() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off")).run()
    config = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off", fail_on_critical=True)
    violations = evaluate_scan_gate_violations(report, config)
    assert violations
    assert "critical findings present" in violations[0]
