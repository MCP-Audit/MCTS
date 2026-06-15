"""Machine-wide MCP scanning across local client configs."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.inventory.models import InventoryEntry
from mcts.inventory.runner import run_inventory
from mcts.inventory.targets import entry_to_scan_config
from mcts.reporting.display import summary_for_gates
from mcts.reporting.models import ScanReport


@dataclass
class MachineScanResult:
    entry: InventoryEntry
    report: ScanReport | None = None
    error: str | None = None


@dataclass
class MachineScanSummary:
    scanned: int = 0
    skipped: int = 0
    failed: int = 0
    results: list[MachineScanResult] = field(default_factory=list)
    base_config: ScanConfig | None = None

    @property
    def total_findings(self) -> int:
        return sum(len(row.report.findings) for row in self.results if row.report is not None)

    @property
    def worst_score(self) -> int | None:
        scores = [row.report.score.overall for row in self.results if row.report is not None]
        return min(scores) if scores else None

    @property
    def worst_absolute_risk(self) -> int | None:
        risks = [
            row.report.score_v2.absolute_risk
            for row in self.results
            if row.report is not None and row.report.score_v2 is not None
        ]
        return max(risks) if risks else None

    def _severity_counts(self, report: ScanReport) -> tuple[int, int]:
        """Critical/high counts aligned with trust gates when enforce is active."""
        if self.base_config is not None:
            gate_summary = summary_for_gates(report, self.base_config)
            return gate_summary.critical, gate_summary.high
        if report.findings_trust_mode == "enforce" and report.display_summary is not None:
            return report.display_summary.critical, report.display_summary.high
        return report.summary.critical, report.summary.high

    def has_high_severity(self) -> bool:
        for row in self.results:
            if row.report is None:
                continue
            if row.report.score_v2 is not None:
                if row.report.score_v2.risk_level in {"high", "critical"}:
                    return True
                critical, high = self._severity_counts(row.report)
                if critical or high:
                    return True
                continue
            critical, high = self._severity_counts(row.report)
            if critical or high:
                return True
        return False

    def gate_violations(self) -> list[str]:
        """Merged policy/CLI gate failures across successfully scanned servers."""
        if self.base_config is None:
            return []
        from mcts.governance.gate_violations import collect_gate_violations

        violations: list[str] = []
        for row in self.results:
            if row.report is None:
                continue
            scan_config = self.base_config.model_copy(update={"target": row.report.target})
            violations.extend(collect_gate_violations(row.report, scan_config))
        return violations

    def exit_code(self) -> int:
        if self.scanned == 0:
            return 0
        violations = self.gate_violations()
        if self.base_config is not None:
            from mcts.governance.gate_violations import collect_fleet_absolute_risk_violations

            violations.extend(
                collect_fleet_absolute_risk_violations(self.worst_absolute_risk, self.base_config)
            )
        if violations:
            return 1
        if self.has_high_severity():
            return 1
        return 0

    def to_dict(self) -> dict:
        payload: dict = {
            "scanned": self.scanned,
            "skipped": self.skipped,
            "failed": self.failed,
            "total_findings": self.total_findings,
            "worst_score": self.worst_score,
            "worst_absolute_risk": self.worst_absolute_risk,
            "servers": [],
        }
        for row in self.results:
            critical, high = self._severity_counts(row.report) if row.report is not None else (0, 0)
            server_row: dict = {
                "client": row.entry.client,
                "server_name": row.entry.server_name,
                "config_path": row.entry.config_path,
                "target": str(row.report.target) if row.report else None,
                "score": row.report.score.overall if row.report else None,
                "findings": len(row.report.findings) if row.report else 0,
                "critical": critical,
                "high": high,
                "error": row.error,
                "report": row.report.model_dump(mode="json") if row.report else None,
            }
            if row.report is not None:
                server_row["template_critical"] = row.report.summary.critical
                server_row["template_high"] = row.report.summary.high
                if row.report.display_summary is not None:
                    server_row["display_critical"] = row.report.display_summary.critical
                    server_row["display_high"] = row.report.display_summary.high
            if row.report is not None and row.report.score_v2 is not None:
                server_row["absolute_risk"] = row.report.score_v2.absolute_risk
                server_row["security_score"] = row.report.score_v2.security_score
                server_row["risk_level"] = row.report.score_v2.risk_level
                server_row["scoring_version"] = row.report.scoring_version
            payload["servers"].append(server_row)
        return payload


def run_machine_wide(base_config: ScanConfig) -> MachineScanSummary:
    """Scan every resolvable MCP server from local client inventory."""
    inventory = run_inventory()
    summary = MachineScanSummary(base_config=base_config)

    for entry in inventory.entries:
        scan_config = entry_to_scan_config(entry, base_config)
        if scan_config is None:
            summary.skipped += 1
            summary.results.append(
                MachineScanResult(entry=entry, error="Could not resolve server entrypoint")
            )
            continue

        try:
            report = Scanner(scan_config).run()
        except Exception as exc:  # noqa: BLE001 — collect per-server failures for machine audit
            summary.failed += 1
            summary.results.append(MachineScanResult(entry=entry, error=str(exc)))
            continue

        summary.scanned += 1
        summary.results.append(MachineScanResult(entry=entry, report=report))

    return summary
