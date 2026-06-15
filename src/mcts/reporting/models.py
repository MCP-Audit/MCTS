"""Report data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from mcts.mcp.models import MCPServerInfo
from mcts.scoring.models import RiskScoreV2


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
        }[self]


class SourceLocation(BaseModel):
    file: str
    line: int | None = None


class Finding(BaseModel):
    id: str
    analyzer: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    tool: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    technique_id: str | None = None
    mitigation_ids: list[str] = Field(default_factory=list)
    cwe_id: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    location: SourceLocation | None = None
    # Trust layer (Phase A) — optional until validator populates them
    impact: Severity | None = None
    evidence_strength: str | None = None
    display_severity: Severity | None = None
    priority_score: int | None = Field(default=None, ge=0, le=100)
    finding_type: str | None = None
    evidence_type: str | None = None
    chain_level: int | None = Field(default=None, ge=0, le=3)
    finding_kind: str | None = None
    rule_stability: str | None = None


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        counts = {s: 0 for s in Severity}
        for finding in findings:
            counts[finding.severity] += 1
        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            total=len(findings),
        )

    @classmethod
    def from_display(cls, findings: list[Finding], *, security_only: bool = False) -> ScanSummary:
        """Count findings by effective (display) severity."""
        from mcts.reporting.display import effective_severity, is_security_finding

        rows = [f for f in findings if is_security_finding(f)] if security_only else list(findings)
        counts = {s: 0 for s in Severity}
        for finding in rows:
            counts[effective_severity(finding)] += 1
        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            total=len(rows),
        )


class ScoreBasis(BaseModel):
    """Severity counts used to compute the score (auditable, not hardcoded)."""

    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    scorable_total: int = Field(ge=0)
    excluded_non_scorable: int = Field(
        ge=0,
        description="Findings excluded from scoring (e.g. compliance meta-checks)",
    )


class RiskScore(BaseModel):
    """overall: security score (100 = best). risk_index: inverted risk (100 = worst)."""

    overall: int = Field(ge=0, le=100, description="Security score; higher is better")
    risk_index: int = Field(ge=0, le=100, description="Risk index; higher is worse")
    raw_risk: int = Field(ge=0, description="Uncapped weighted risk points")
    penalty: int = Field(ge=0, description="Deprecated alias for raw_risk")
    basis: ScoreBasis = Field(description="Finding counts used for this score")


class ScoreBreakdown(BaseModel):
    """Decomposed scores across MCP surface, supply chain, and dependency hygiene."""

    mcp_surface: int = Field(ge=0, le=100)
    supply_chain: int = Field(ge=0, le=100)
    dependency_hygiene: int = Field(ge=0, le=100)
    composite: int = Field(ge=0, le=100, description="Weighted composite across buckets")


class ScanReport(BaseModel):
    version: str
    target: str
    scanned_at: datetime
    server: MCPServerInfo
    findings: list[Finding]
    summary: ScanSummary
    display_summary: ScanSummary | None = None
    findings_trust_mode: str = "off"
    score: RiskScore
    score_v2: RiskScoreV2 | None = None
    scoring_version: str = "legacy"
    attack_graph: dict[str, Any] = Field(default_factory=dict)
    scan_scope: str = "repository"
    scan_notes: list[str] = Field(default_factory=list)
    score_breakdown: ScoreBreakdown | None = None
    tool_discovery_notice: str | None = None
    analyzers_executed: list[str] = Field(default_factory=list)
    scan_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Prior scan scores for this target (embedded for trend charts)",
    )
