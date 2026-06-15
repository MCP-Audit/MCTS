"""Inventory scan-all governance gates."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.inventory.models import InventoryEntry
from mcts.inventory.scan_all import (
    _row,
    collect_scan_all_gate_violations,
    scan_all_has_high_severity,
)
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis, Severity


def _report(*, critical: int = 0, target: str = "server.py") -> ScanReport:
    findings = []
    for index in range(critical):
        findings.append(
            Finding(
                id=f"crit-{index}",
                analyzer="command_execution",
                title="Shell",
                description="d",
                severity=Severity.CRITICAL,
                recommendation="fix",
            )
        )
    return ScanReport(
        version="0.0.0",
        target=target,
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=findings,
        summary=ScanSummary(critical=critical, high=0, medium=0, low=0, total=critical),
        score=RiskScore(
            overall=10,
            risk_index=90,
            raw_risk=100,
            penalty=100,
            basis=ScoreBasis(
                critical=critical,
                high=0,
                medium=0,
                low=0,
                scorable_total=critical,
                excluded_non_scorable=0,
            ),
        ),
        scoring_version="legacy",
    )


def test_collect_scan_all_gate_violations_fail_on_critical() -> None:
    report = _report(critical=1)
    entry = InventoryEntry(client="c", server_name="s", config_path="p")
    rows = [_row(entry, report=report.model_dump(mode="json"))]
    config = ScanConfig(target=Path("server.py"), fail_on_critical=True)
    violations = collect_scan_all_gate_violations(config, rows)
    assert any("critical findings present" in item for item in violations)


def test_scan_all_has_high_severity_without_explicit_gate() -> None:
    report = _report(critical=1)
    entry = InventoryEntry(client="c", server_name="s", config_path="p")
    rows = [_row(entry, report=report.model_dump(mode="json"))]
    config = ScanConfig(target=Path("server.py"))
    assert scan_all_has_high_severity(config, rows)
