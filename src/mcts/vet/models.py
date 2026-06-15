"""Package vetting report models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from mcts.reporting.models import Severity


class VetFinding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: dict = Field(default_factory=dict)
    display_severity: Severity | None = None
    priority_score: int | None = Field(default=None, ge=0, le=100)
    evidence_strength: str | None = None
    rule_stability: str | None = None


class VetReport(BaseModel):
    ecosystem: str
    package: str
    version: str | None = None
    verdict: str
    findings: list[VetFinding] = Field(default_factory=list)

    def compute_risk_score(self, *, use_display: bool = False) -> int:
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
        }
        total = 0
        for finding in self.findings:
            severity = (
                finding.display_severity
                if use_display and finding.display_severity is not None
                else finding.severity
            )
            total += weights.get(severity, 0)
        return min(100, total)

    @property
    def risk_score(self) -> int:
        return self.compute_risk_score(use_display=False)
