"""Inventory batch full-scan helpers."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.inventory.models import InventoryEntry, InventoryReport
from mcts.inventory.runner import run_inventory
from mcts.inventory.targets import entry_to_scan_config
from mcts.output.analysis_dir import resolve_output_path
from mcts.reporting.display import summary_for_gates
from mcts.reporting.models import ScanReport


def run_inventory_scan_all(base_config: ScanConfig) -> tuple[InventoryReport, list[dict]]:
    """Run a full security scan for each resolvable inventory entry."""
    inventory = run_inventory()
    rows: list[dict] = []
    for entry in inventory.entries:
        scan_config = entry_to_scan_config(entry, base_config)
        if scan_config is None:
            rows.append(_row(entry, error="Could not resolve server entrypoint"))
            continue
        try:
            report = Scanner(scan_config, inventory=inventory.entries).run()
        except Exception as exc:  # noqa: BLE001
            rows.append(_row(entry, error=str(exc)))
            continue
        row_payload: dict = {
            "score": report.score.overall,
            "findings": len(report.findings),
            "scoring_version": report.scoring_version,
            "report": report.model_dump(mode="json"),
        }
        if report.score_v2 is not None:
            row_payload["absolute_risk"] = report.score_v2.absolute_risk
            row_payload["security_score"] = report.score_v2.security_score
            row_payload["risk_level"] = report.score_v2.risk_level
        rows.append(_row(entry, **row_payload))
    return inventory, rows


def collect_scan_all_gate_violations(base_config: ScanConfig, rows: list[dict]) -> list[str]:
    """Policy/CLI gate failures across inventory scan-all rows."""
    from mcts.governance.gate_violations import (
        collect_fleet_absolute_risk_violations,
        collect_gate_violations,
    )

    violations: list[str] = []
    worst_risk: int | None = None
    for row in rows:
        report_data = row.get("report")
        if not report_data or row.get("error"):
            continue
        report = ScanReport.model_validate(report_data)
        scan_config = base_config.model_copy(update={"target": report.target})
        violations.extend(collect_gate_violations(report, scan_config))
        if report.score_v2 is not None:
            ar = report.score_v2.absolute_risk
            worst_risk = ar if worst_risk is None else max(worst_risk, ar)
        elif row.get("absolute_risk") is not None:
            ar = int(row["absolute_risk"])
            worst_risk = ar if worst_risk is None else max(worst_risk, ar)
    violations.extend(collect_fleet_absolute_risk_violations(worst_risk, base_config))
    return violations


def scan_all_has_high_severity(base_config: ScanConfig, rows: list[dict]) -> bool:
    """Critical/high heuristic when no explicit gate fired (aligned with machine-wide)."""
    for row in rows:
        report_data = row.get("report")
        if not report_data or row.get("error"):
            continue
        report = ScanReport.model_validate(report_data)
        scan_config = base_config.model_copy(update={"target": report.target})
        if report.score_v2 is not None and report.score_v2.risk_level in {"high", "critical"}:
            return True
        gate_summary = summary_for_gates(report, scan_config)
        if gate_summary.critical or gate_summary.high:
            return True
    return False


def write_inventory_scan_all(path: Path, inventory: InventoryReport, rows: list[dict]) -> None:
    payload = {
        "clients_scanned": inventory.clients_scanned,
        "config_files_found": inventory.config_files_found,
        "entries": [entry.model_dump() for entry in inventory.entries],
        "scan_results": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def default_output_path(output: Path | None) -> Path:
    return resolve_output_path(output, "inventory-scan-all.json")


def _row(entry: InventoryEntry, **payload) -> dict:
    row = {
        "client": entry.client,
        "server_name": entry.server_name,
        "config_path": entry.config_path,
    }
    row.update(payload)
    return row
