"""FindingBuilder SDK — Bronze/Silver evidence tiers for new analyzers (Phase 1.5)."""

from __future__ import annotations

from typing import Any

from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.reporting.rule_stability import VALID_STABILITY, default_rule_stability


class FindingBuilder:
    """Construct findings with minimum provenance fields."""

    def __init__(
        self,
        *,
        finding_id: str,
        analyzer: str,
        title: str,
        description: str,
        severity: Severity,
        recommendation: str,
        rule_stability: str | None = None,
    ) -> None:
        self._finding_id = finding_id
        self._analyzer = analyzer
        self._title = title
        self._description = description
        self._severity = severity
        self._recommendation = recommendation
        self._rule_stability = rule_stability or default_rule_stability(analyzer)
        if self._rule_stability not in VALID_STABILITY:
            raise ValueError(f"rule_stability must be one of: {', '.join(sorted(VALID_STABILITY))}")
        self._facts: list[dict[str, Any]] = []
        self._tool: str | None = None
        self._location: SourceLocation | None = None
        self._technique_id: str | None = None
        self._confidence: float = 1.0
        self._extra_evidence: dict[str, Any] = {}

    def fact(
        self,
        *,
        rule_id: str,
        match: str,
        field: str,
        file: str | None = None,
        line: int | None = None,
        snippet: str | None = None,
        tool: str | None = None,
    ) -> FindingBuilder:
        row: dict[str, Any] = {"rule_id": rule_id, "match": match, "field": field}
        if file:
            row["file"] = file
        if line is not None:
            row["line"] = line
        if snippet:
            row["snippet"] = snippet
        if tool:
            row["tool"] = tool
        self._facts.append(row)
        return self

    def tool(self, name: str) -> FindingBuilder:
        self._tool = name
        return self

    def location(self, file: str, line: int | None = None) -> FindingBuilder:
        self._location = SourceLocation(file=file, line=line)
        return self

    def technique(self, technique_id: str) -> FindingBuilder:
        self._technique_id = technique_id
        return self

    def confidence(self, value: float) -> FindingBuilder:
        self._confidence = value
        return self

    def evidence(self, **fields: Any) -> FindingBuilder:
        self._extra_evidence.update(fields)
        return self

    def build(self, *, require_fact: bool = True) -> Finding:
        if require_fact and not self._facts:
            raise ValueError(
                f"Finding {self._finding_id!r} requires at least one fact (Bronze tier). "
                "Call .fact(...) or pass require_fact=False for coverage/hygiene rows."
            )
        evidence = dict(self._extra_evidence)
        if self._facts:
            evidence["facts"] = list(self._facts)
            evidence["evidence_tier"] = (
                "silver" if any(row.get("snippet") for row in self._facts) else "bronze"
            )
        return Finding(
            id=self._finding_id,
            analyzer=self._analyzer,
            title=self._title,
            description=self._description,
            severity=self._severity,
            recommendation=self._recommendation,
            tool=self._tool,
            location=self._location,
            technique_id=self._technique_id,
            confidence=self._confidence,
            evidence=evidence,
            rule_stability=self._rule_stability,
        )
