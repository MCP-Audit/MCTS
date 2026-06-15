"""FindingBuilder helpers for mature analyzers (bronze fact contract)."""

from __future__ import annotations

from typing import Any

from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity, SourceLocation


def build_analyzer_finding(
    *,
    finding_id: str,
    analyzer: str,
    title: str,
    description: str,
    severity: Severity,
    recommendation: str,
    rule_id: str,
    match: str,
    field: str,
    tool: str | None = None,
    location: SourceLocation | None = None,
    technique_id: str | None = None,
    confidence: float = 0.7,
    snippet: str | None = None,
    extra_evidence: dict[str, Any] | None = None,
) -> Finding:
    builder = FindingBuilder(
        finding_id=finding_id,
        analyzer=analyzer,
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
    ).confidence(confidence)
    if tool:
        builder = builder.tool(tool)
    if location and location.file:
        builder = builder.location(location.file, location.line)
    if technique_id:
        builder = builder.technique(technique_id)
    fact_kwargs: dict[str, Any] = {"rule_id": rule_id, "match": match, "field": field}
    if tool:
        fact_kwargs["tool"] = tool
    if location and location.file:
        fact_kwargs["file"] = location.file
    if location and location.line is not None:
        fact_kwargs["line"] = location.line
    if snippet:
        fact_kwargs["snippet"] = snippet
    builder = builder.fact(**fact_kwargs)
    if extra_evidence:
        builder = builder.evidence(**extra_evidence)
    return builder.build()


def build_hygiene_finding(
    *,
    finding_id: str,
    analyzer: str,
    title: str,
    description: str,
    severity: Severity,
    recommendation: str,
    rule_id: str,
    match: str,
    field: str,
    tool: str | None = None,
    technique_id: str | None = None,
    confidence: float = 0.7,
    extra_evidence: dict[str, Any] | None = None,
    finding_kind: str | None = None,
) -> Finding:
    """Hygiene/readiness/meta row with bronze facts (R6 migration path)."""
    builder = FindingBuilder(
        finding_id=finding_id,
        analyzer=analyzer,
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
    ).confidence(confidence)
    if tool:
        builder = builder.tool(tool)
    if technique_id:
        builder = builder.technique(technique_id)
    fact_kwargs: dict[str, Any] = {"rule_id": rule_id, "match": match, "field": field}
    if tool:
        fact_kwargs["tool"] = tool
    builder = builder.fact(**fact_kwargs)
    if extra_evidence:
        builder = builder.evidence(**extra_evidence)
    row = builder.build()
    if finding_kind:
        return row.model_copy(update={"finding_kind": finding_kind})
    return row


def build_skip_finding(
    *,
    finding_id: str,
    analyzer: str,
    title: str,
    description: str,
    recommendation: str,
    severity: Severity = Severity.LOW,
) -> Finding:
    """Coverage/hygiene row when an optional analyzer cannot run (no bronze facts)."""
    return (
        FindingBuilder(
            finding_id=finding_id,
            analyzer=analyzer,
            title=title,
            description=description,
            severity=severity,
            recommendation=recommendation,
        )
        .confidence(1.0)
        .evidence(skipped=True, reason=description)
        .build(require_fact=False)
    )
