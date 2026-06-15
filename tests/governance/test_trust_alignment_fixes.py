"""Tests for trust-layer alignment fixes (category gates, breakdown, policy, machine-wide)."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.policy import GovernancePolicy, merge_scan_config_with_policy
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.inventory.models import InventoryEntry, InventoryReport
from mcts.report.data import category_gate_failures
from mcts.scan.machine_wide import run_machine_wide

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_category_gates_use_display_when_enforce() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    template_failures = category_gate_failures(report.findings, {"attack_chains": 0}, use_display=False)
    display_failures = category_gate_failures(report.findings, {"attack_chains": 10}, use_display=True)
    assert template_failures
    assert not display_failures


def test_fail_on_category_gate_passes_under_enforce_on_overlap_fixture() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_category={"attack_chains": 10},
    )
    assert evaluate_scan_gate_violations(report, config) == []


def test_score_breakdown_aligns_with_enforce_basis() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    assert report.score_breakdown is not None
    assert report.score.basis.critical == 0
    assert report.score_breakdown.mcp_surface == report.score.overall


def test_explicit_findings_trust_mode_off_overrides_policy_enforce() -> None:
    policy = GovernancePolicy(findings_trust_mode="enforce")
    merged = merge_scan_config_with_policy(
        ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off", findings_trust_mode_explicit=True),
        policy,
    )
    assert merged.findings_trust_mode == "off"


def test_ignore_policy_skips_merge() -> None:
    policy = GovernancePolicy(findings_trust_mode="enforce", max_critical=0)
    merged = merge_scan_config_with_policy(
        ScanConfig(target=SINGLE_TOOL, ignore_policy=True),
        policy,
    )
    assert merged.findings_trust_mode == "off"
    assert merged.max_critical is None


def test_policy_bool_explicit_false_not_overridden() -> None:
    policy = GovernancePolicy(enforce_bronze_facts=True, collapse_template_severity=True)
    merged = merge_scan_config_with_policy(
        ScanConfig(
            target=SINGLE_TOOL,
            enforce_bronze_facts=False,
            collapse_template_severity=False,
        ),
        policy,
    )
    assert merged.enforce_bronze_facts is False
    assert merged.collapse_template_severity is False


def test_auxiliary_explicit_off_overrides_policy_enforce() -> None:
    from mcts.reporting.trust_apply import merge_scan_config_defaults

    policy = GovernancePolicy(findings_trust_mode="enforce")
    config = merge_scan_config_defaults(ScanConfig(target=Path(".")), findings_trust_mode="off")
    merged = merge_scan_config_with_policy(config, policy)
    assert merged.findings_trust_mode == "off"
    assert merged.findings_trust_mode_explicit is True


def test_auxiliary_unset_trust_inherits_policy() -> None:
    from mcts.reporting.trust_apply import merge_scan_config_defaults

    policy = GovernancePolicy(findings_trust_mode="enforce")
    config = merge_scan_config_defaults(ScanConfig(target=Path(".")), findings_trust_mode=None)
    merged = merge_scan_config_with_policy(config, policy)
    assert merged.findings_trust_mode == "enforce"
    assert merged.findings_trust_mode_explicit is False


def test_machine_wide_uses_display_severity_under_enforce(monkeypatch) -> None:
    entry = InventoryEntry(
        client="cursor",
        config_path="mcp.json",
        server_name="demo",
        command="python",
        args=[str(SINGLE_TOOL)],
    )
    monkeypatch.setattr(
        "mcts.scan.machine_wide.run_inventory",
        lambda: InventoryReport(entries=[entry], clients_scanned=["cursor"], config_files_found=1),
    )

    def _entry_config(entry: InventoryEntry, base: ScanConfig) -> ScanConfig:
        return base.model_copy(update={"target": SINGLE_TOOL})

    monkeypatch.setattr("mcts.scan.machine_wide.entry_to_scan_config", _entry_config)

    summary = run_machine_wide(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce"))
    assert summary.scanned == 1
    report = summary.results[0].report
    assert report is not None
    assert report.display_summary is not None
    assert report.display_summary.critical == 0
    assert not summary.has_high_severity()
    exported = summary.to_dict()["servers"][0]
    assert exported["critical"] == 0
    assert exported["template_critical"] >= 1


def test_machine_wide_exit_code_uses_gate_violations(monkeypatch) -> None:
    entry = InventoryEntry(
        client="cursor",
        config_path="mcp.json",
        server_name="demo",
        command="python",
        args=[str(SINGLE_TOOL)],
    )
    monkeypatch.setattr(
        "mcts.scan.machine_wide.run_inventory",
        lambda: InventoryReport(entries=[entry], clients_scanned=["cursor"], config_files_found=1),
    )

    def _entry_config(entry: InventoryEntry, base: ScanConfig) -> ScanConfig:
        return base.model_copy(update={"target": SINGLE_TOOL})

    monkeypatch.setattr("mcts.scan.machine_wide.entry_to_scan_config", _entry_config)

    base = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_critical=True,
    )
    summary = run_machine_wide(base)
    assert summary.exit_code() == 0
    assert summary.gate_violations() == []


def test_machine_wide_v2_medium_still_checks_template_counts() -> None:
    from mcts.scan.machine_wide import MachineScanResult, MachineScanSummary
    from mcts.scoring.models import RiskScoreV2, ScoreV2Basis

    real_report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off")).run()
    report = real_report.model_copy(
        update={
            "score_v2": RiskScoreV2(
                absolute_risk=200,
                security_score=60,
                risk_level="medium",
                legacy_overall=real_report.score.overall,
                basis=ScoreV2Basis(scorable_count=5, excluded_non_scorable=0),
            ),
        }
    )
    entry = InventoryEntry(
        client="cursor",
        config_path="mcp.json",
        server_name="demo",
        command="python",
        args=[str(SINGLE_TOOL)],
    )
    summary = MachineScanSummary(
        scanned=1,
        base_config=ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off"),
        results=[MachineScanResult(entry=entry, report=report)],
    )
    assert report.summary.critical >= 1
    assert summary.has_high_severity()


def test_collect_findings_gate_violations_enforce_overlap_passes() -> None:
    from mcts.governance.gate_violations import collect_findings_gate_violations

    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        max_critical=0,
        ignore_policy=True,
    )
    violations = collect_findings_gate_violations(
        report.findings,
        config,
        target=str(SINGLE_TOOL),
        scan_scope="repository",
    )
    assert violations == []


def test_collect_findings_gate_violations_scores_v2_for_policy_gates() -> None:
    from mcts.core.scanner import Scanner
    from mcts.governance.gate_violations import collect_findings_gate_violations

    vulnerable = Path("examples/vulnerable-mcp-server/server.py")
    report = Scanner(ScanConfig(target=vulnerable, scoring_mode="both")).run()
    config = ScanConfig(
        target=vulnerable,
        scoring_mode="both",
        min_security_score=99,
        ignore_policy=True,
    )
    violations = collect_findings_gate_violations(
        report.findings,
        config,
        target=str(vulnerable),
        scan_scope="repository",
    )
    assert violations
    assert any("security_score" in item for item in violations)
    assert not any("v2 gate requires" in item for item in violations)


def test_collect_fleet_absolute_risk_violation() -> None:
    from mcts.governance.gate_violations import collect_fleet_absolute_risk_violations

    config = ScanConfig(target=SINGLE_TOOL, max_worst_absolute_risk=100, ignore_policy=True)
    assert collect_fleet_absolute_risk_violations(150, config) == [
        "worst absolute_risk 150 exceeds maximum 100"
    ]
    assert collect_fleet_absolute_risk_violations(50, config) == []
    assert collect_fleet_absolute_risk_violations(None, config) == []
