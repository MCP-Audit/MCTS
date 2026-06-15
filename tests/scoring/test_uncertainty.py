"""Uncertainty helpers for scoring v2."""

from mcts.reporting.models import Finding, Severity
from mcts.scoring.uncertainty import analyzer_disagreement_factor


def test_analyzer_disagreement_factor_defaults_without_conflict() -> None:
    findings = [
        Finding(
            id="a",
            analyzer="prompt_injection",
            title="t",
            description="d",
            severity=Severity.HIGH,
            recommendation="fix",
            tool="read_file",
        )
    ]
    assert analyzer_disagreement_factor(findings) == 1.0


def test_analyzer_disagreement_factor_uses_display_when_requested() -> None:
    findings = [
        Finding(
            id="a",
            analyzer="prompt_injection",
            title="t",
            description="d",
            severity=Severity.HIGH,
            display_severity=Severity.MEDIUM,
            recommendation="fix",
            tool="read_file",
        ),
        Finding(
            id="b",
            analyzer="data_leakage",
            title="t",
            description="d",
            severity=Severity.LOW,
            display_severity=Severity.MEDIUM,
            recommendation="fix",
            tool="read_file",
        ),
    ]
    assert analyzer_disagreement_factor(findings) == 1.4
    assert analyzer_disagreement_factor(findings, use_display=True) == 1.0
