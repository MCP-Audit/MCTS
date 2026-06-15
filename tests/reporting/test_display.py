"""Tests for findings display helpers."""

from datetime import UTC, datetime
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.display import effective_severity, is_security_finding, summary_for_gates
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis, Severity


def _finding(**kwargs) -> Finding:
    base = {
        "id": "f-1",
        "analyzer": "command_execution",
        "title": "Exec",
        "description": "d",
        "severity": Severity.CRITICAL,
        "recommendation": "fix",
    }
    base.update(kwargs)
    return Finding(**base)


def test_effective_severity_falls_back_to_template() -> None:
    row = _finding(severity=Severity.HIGH)
    assert effective_severity(row) == Severity.HIGH


def test_effective_severity_uses_display_when_set() -> None:
    row = _finding(severity=Severity.CRITICAL, display_severity=Severity.MEDIUM)
    assert effective_severity(row) == Severity.MEDIUM


def test_is_security_finding_excludes_compliance() -> None:
    row = _finding(analyzer="compliance")
    assert is_security_finding(row) is False


def test_scan_summary_from_display_counts_effective_severity() -> None:
    rows = [
        _finding(id="a", severity=Severity.CRITICAL, display_severity=Severity.MEDIUM),
        _finding(id="b", severity=Severity.HIGH),
    ]
    summary = ScanSummary.from_display(rows)
    assert summary.critical == 0
    assert summary.high == 1
    assert summary.medium == 1
    assert summary.total == 2


def test_summary_for_gates_uses_template_by_default() -> None:
    report = ScanReport(
        version="0.0.0",
        target="t",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(),
        findings=[_finding()],
        summary=ScanSummary(critical=1, total=1),
        display_summary=ScanSummary(critical=0, medium=1, total=1),
        score=RiskScore(
            overall=0,
            risk_index=100,
            raw_risk=100,
            penalty=100,
            basis=ScoreBasis(critical=1, high=0, medium=0, low=0, scorable_total=1, excluded_non_scorable=0),
        ),
    )
    config = ScanConfig(target=Path("server.py"), findings_trust_mode="off")
    assert summary_for_gates(report, config).critical == 1


def test_summary_for_gates_uses_display_when_enforced() -> None:
    report = ScanReport(
        version="0.0.0",
        target="t",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(),
        findings=[_finding()],
        summary=ScanSummary(critical=1, total=1),
        display_summary=ScanSummary(critical=0, medium=1, total=1),
        score=RiskScore(
            overall=0,
            risk_index=100,
            raw_risk=100,
            penalty=100,
            basis=ScoreBasis(critical=1, high=0, medium=0, low=0, scorable_total=1, excluded_non_scorable=0),
        ),
    )
    config = ScanConfig(target=Path("server.py"), findings_trust_mode="enforce")
    assert summary_for_gates(report, config).critical == 0


def test_summary_for_gates_uses_template_when_warn() -> None:
    report = ScanReport(
        version="0.0.0",
        target="t",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(),
        findings=[_finding()],
        summary=ScanSummary(critical=1, total=1),
        display_summary=ScanSummary(critical=0, medium=1, total=1),
        findings_trust_mode="warn",
        score=RiskScore(
            overall=0,
            risk_index=100,
            raw_risk=100,
            penalty=100,
            basis=ScoreBasis(critical=1, high=0, medium=0, low=0, scorable_total=1, excluded_non_scorable=0),
        ),
    )
    config = ScanConfig(target=Path("server.py"), findings_trust_mode="warn")
    assert summary_for_gates(report, config).critical == 1
