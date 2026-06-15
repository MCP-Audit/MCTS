"""Governance policy merge into scan config."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.policy import GovernancePolicy, load_policy, merge_scan_config_with_policy
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.reporting.display import summary_for_gates

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")
VULNERABLE = Path("examples/vulnerable-mcp-server/server.py")
POLICY_EXAMPLE = Path(".mcts/policy.yaml.example")


def test_merge_policy_applies_trust_mode_when_cli_default() -> None:
    policy = load_policy(POLICY_EXAMPLE)
    base = ScanConfig(target=SINGLE_TOOL)
    merged = merge_scan_config_with_policy(base, policy)
    assert merged.findings_trust_mode == "enforce"
    assert merged.max_critical == 0
    assert merged.max_high == 5
    assert merged.min_score == 70


def test_merge_policy_applies_boolean_flags_when_cli_default() -> None:
    policy = GovernancePolicy(
        findings_trust_mode="enforce",
        enforce_bronze_facts=True,
        collapse_template_severity=True,
        require_auth_env_for_sensitive=True,
    )
    merged = merge_scan_config_with_policy(ScanConfig(target=SINGLE_TOOL), policy)
    assert merged.enforce_bronze_facts is True
    assert merged.collapse_template_severity is True
    assert merged.require_auth_env_for_sensitive is True


def test_merge_policy_explicit_false_preserves_cli_bool() -> None:
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


def test_merge_policy_does_not_override_explicit_cli() -> None:
    policy = GovernancePolicy(findings_trust_mode="enforce", max_critical=0)
    base = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="warn",
        fail_on_priority_min=50,
    )
    merged = merge_scan_config_with_policy(base, policy)
    assert merged.findings_trust_mode == "warn"
    assert merged.fail_on_priority_min == 50


def test_merged_policy_enables_trust_on_scan() -> None:
    policy = load_policy(POLICY_EXAMPLE)
    config = merge_scan_config_with_policy(ScanConfig(target=SINGLE_TOOL), policy)
    report = Scanner(config).run()
    assert report.findings_trust_mode == "enforce"
    assert report.display_summary is not None
    assert report.display_summary.critical == 0
    gate_summary = summary_for_gates(report, config)
    assert gate_summary.critical == 0


def test_max_high_gate_uses_display_counts_under_enforce() -> None:
    report = Scanner(ScanConfig(target=VULNERABLE, findings_trust_mode="enforce")).run()
    config = ScanConfig(target=VULNERABLE, findings_trust_mode="enforce", max_high=0)
    violations = evaluate_scan_gate_violations(report, config)
    assert any("high findings" in item for item in violations)
