"""Priority gate and FindingBuilder tests (Phase 2 / 1.5)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, RiskScore, ScanSummary, ScoreBasis, Severity
from mcts.reporting.rule_stability import apply_rule_stability, default_rule_stability
from mcts.reporting.trust_gates import (
    findings_over_priority_threshold,
    normalize_evidence_strength,
    priority_gate_violations,
)

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_finding_builder_requires_bronze_fact() -> None:
    builder = FindingBuilder(
        finding_id="demo-1",
        analyzer="prompt_injection",
        title="Injection",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
    )
    try:
        builder.build()
        raised = False
    except ValueError:
        raised = True
    assert raised
    finding = builder.fact(rule_id="RULE_X", match="eval", field="handler_snippet").build()
    assert finding.evidence["facts"]
    assert finding.rule_stability == "mature"


def test_rule_stability_defaults_by_analyzer() -> None:
    assert default_rule_stability("attack_chains") == "heuristic"
    assert default_rule_stability("prompt_injection") == "mature"
    row = apply_rule_stability(
        Finding(
            id="x",
            analyzer="attack_chains",
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            recommendation="r",
        )
    )
    assert row.rule_stability == "heuristic"


def test_non_chain_security_findings_get_priority_score_on_fixture() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    security = [
        f
        for f in report.findings
        if f.analyzer not in ("attack_chains", "compliance", "live_discovery", "static_discovery")
    ]
    assert security
    assert all(f.priority_score is not None for f in security)


def test_priority_gate_ignores_weak_overlap_on_fixture() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_priority_min=80,
        min_evidence_strength="strong",
    )
    assert priority_gate_violations(report, config) == []


def test_priority_gate_fails_when_threshold_low() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_priority_min=10,
    )
    violations = evaluate_scan_gate_violations(report, config)
    assert violations
    assert "priority 10" in violations[-1]


def test_policy_priority_gate() -> None:
    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="Shell",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="fix",
        priority_score=90,
        evidence_strength="strong",
        finding_kind="security",
    )
    report = SimpleNamespace(
        findings=[finding],
        score=RiskScore(
            overall=90,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(
                critical=0,
                high=0,
                medium=0,
                low=0,
                scorable_total=0,
                excluded_non_scorable=0,
            ),
        ),
        display_summary=None,
    )
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_priority_min=80,
        min_evidence_strength="strong",
    )
    violations = evaluate_scan_gate_violations(report, config)
    assert any("priority 80" in item for item in violations)


def test_policy_priority_gate_inactive_without_enforce() -> None:
    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="Shell",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="fix",
        priority_score=90,
        evidence_strength="strong",
        finding_kind="security",
    )
    report = SimpleNamespace(
        findings=[finding],
        score=RiskScore(
            overall=90,
            risk_index=0,
            raw_risk=0,
            penalty=0,
            basis=ScoreBasis(
                critical=0,
                high=0,
                medium=0,
                low=0,
                scorable_total=0,
                excluded_non_scorable=0,
            ),
        ),
        summary=ScanSummary(critical=0, high=1, medium=0, low=0),
    )
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="warn",
        fail_on_priority_min=80,
    )
    violations = evaluate_scan_gate_violations(report, config)
    assert not any("priority 80" in item for item in violations)


def test_bronze_gate_inactive_in_warn_mode() -> None:
    from types import SimpleNamespace

    from mcts.core.config import ScanConfig
    from mcts.reporting.trust_gates import bronze_gate_violations

    finding = Finding(
        id="judge-1",
        analyzer="llm_judge",
        title="Judge flagged issue",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
        rule_stability="experimental",
        finding_kind="security",
    )
    config = ScanConfig(target="demo", findings_trust_mode="warn", enforce_bronze_facts=True)
    assert bronze_gate_violations(SimpleNamespace(findings=[finding]), config) == []


def test_priority_gate_inactive_in_warn_mode() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="warn")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="warn",
        fail_on_priority_min=1,
    )
    assert priority_gate_violations(report, config) == []


def test_normalize_evidence_strength_rejects_unknown() -> None:
    try:
        normalize_evidence_strength("bogus")
        rejected = False
    except ValueError:
        rejected = True
    assert rejected


def test_findings_over_priority_respects_strength_filter() -> None:
    rows = [
        Finding(
            id="a",
            analyzer="command_execution",
            title="A",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
            priority_score=90,
            evidence_strength="weak",
            finding_kind="security",
        ),
        Finding(
            id="b",
            analyzer="command_execution",
            title="B",
            description="d",
            severity=Severity.HIGH,
            recommendation="r",
            priority_score=90,
            evidence_strength="strong",
            finding_kind="security",
        ),
    ]
    matched = findings_over_priority_threshold(rows, minimum_priority=80, minimum_evidence_strength="strong")
    assert len(matched) == 1
    assert matched[0].id == "b"


def test_bronze_gate_flags_experimental_without_facts() -> None:
    from types import SimpleNamespace

    from mcts.core.config import ScanConfig
    from mcts.reporting.trust_gates import bronze_gate_violations, findings_missing_bronze_facts

    finding = Finding(
        id="judge-1",
        analyzer="llm_judge",
        title="Judge flagged issue",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
        rule_stability="experimental",
        finding_kind="security",
    )
    assert findings_missing_bronze_facts([finding])
    config = ScanConfig(target="demo", findings_trust_mode="enforce", enforce_bronze_facts=True)
    violations = bronze_gate_violations(SimpleNamespace(findings=[finding]), config)
    assert violations
    assert "bronze facts" in violations[0]


def test_bronze_gate_passes_when_experimental_has_facts() -> None:
    from types import SimpleNamespace

    from mcts.core.config import ScanConfig
    from mcts.reporting.trust_gates import bronze_gate_violations, findings_missing_bronze_facts

    finding = Finding(
        id="judge-1",
        analyzer="llm_judge",
        title="Judge flagged issue",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
        rule_stability="experimental",
        finding_kind="security",
        evidence={"facts": [{"rule_id": "RULE_X", "match": "y", "field": "z"}]},
    )
    assert not findings_missing_bronze_facts([finding])
    config = ScanConfig(target="demo", findings_trust_mode="enforce", enforce_bronze_facts=True)
    assert bronze_gate_violations(SimpleNamespace(findings=[finding]), config) == []
