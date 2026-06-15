"""Vet findings trust adapter tests."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.reporting.models import Severity
from mcts.reporting.vet_trust import (
    apply_trust_to_vet_report,
    vet_finding_to_finding,
    vet_severity_label,
)
from mcts.vet.models import VetFinding, VetReport


def _sample_report() -> VetReport:
    return VetReport(
        ecosystem="pypi",
        package="demo-package",
        version="1.0.0",
        verdict="fail",
        findings=[
            VetFinding(
                id="vet-yanked",
                title="Yanked release",
                description="This release was yanked on PyPI.",
                severity=Severity.HIGH,
                recommendation="Pick a non-yanked version.",
                evidence={"yanked": True},
            )
        ],
    )


def test_vet_finding_to_finding_sets_hygiene_kind() -> None:
    row = _sample_report().findings[0]
    finding = vet_finding_to_finding(row)
    assert finding.analyzer == "vet"
    assert finding.finding_kind == "hygiene"
    assert finding.evidence.get("facts")


def test_apply_trust_off_is_noop() -> None:
    report = _sample_report()
    config = ScanConfig(target=".", findings_trust_mode="off")
    updated = apply_trust_to_vet_report(report, config)
    assert updated.findings[0].display_severity is None


def test_apply_trust_enforce_populates_display_fields() -> None:
    report = _sample_report()
    config = ScanConfig(target=".", findings_trust_mode="enforce")
    updated = apply_trust_to_vet_report(report, config)
    finding = updated.findings[0]
    assert finding.display_severity is not None
    assert finding.rule_stability is not None


def test_vet_severity_label_uses_display_when_trust_on() -> None:
    report = apply_trust_to_vet_report(
        _sample_report(),
        ScanConfig(target=".", findings_trust_mode="enforce"),
    )
    config = ScanConfig(target=".", findings_trust_mode="enforce")
    label = vet_severity_label(report.findings[0], config)
    assert label == report.findings[0].display_severity.value
