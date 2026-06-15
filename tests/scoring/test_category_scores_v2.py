"""Tests for OWASP category_scores_v2 tiles."""

from __future__ import annotations

from mcts.report.data import (
    assign_category_v2,
    category_scores_v2,
    category_scores_v2_gate_failures,
    parse_min_category_score_v2,
)
from mcts.reporting.models import Finding, Severity, SourceLocation


def _finding(analyzer: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"{analyzer}-1",
        analyzer=analyzer,
        severity=severity,
        title="test",
        description="test",
        recommendation="fix",
        location=SourceLocation(file="x.py"),
    )


def test_assign_category_first_match() -> None:
    assert assign_category_v2("prompt_injection") == "injection"
    assert assign_category_v2("permission_analyzer") == "privilege"
    assert assign_category_v2("unknown_analyzer") is None


def test_category_scores_v2_polarity_100_good() -> None:
    rows = category_scores_v2([])
    assert all(row["score"] == 100 for row in rows)
    assert all(row["passed"] for row in rows)
    assert all("benchmark" in row for row in rows)

    rows = category_scores_v2([_finding("prompt_injection", Severity.CRITICAL)])
    injection = next(row for row in rows if row["key"] == "injection")
    assert injection["score"] < 100
    assert injection["findings_count"] == 1


def test_min_category_score_v2_gate_fails_below_minimum() -> None:
    findings = [_finding("prompt_injection", Severity.CRITICAL)]
    failures = category_scores_v2_gate_failures(findings, {"injection": 80})
    assert failures
    assert "below minimum 80" in failures[0]


def test_parse_min_category_score_v2() -> None:
    gates = parse_min_category_score_v2(["injection:80", "privilege:70"])
    assert gates == {"injection": 80, "privilege": 70}
