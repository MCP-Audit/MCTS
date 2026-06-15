"""Partitioned risk scoring across MCP surface, supply chain, and dependency hygiene."""

from __future__ import annotations

from mcts.reporting.models import Finding, RiskScore, ScoreBreakdown
from mcts.scoring.categories import ScoreBucket, bucket_for_finding
from mcts.scoring.engine import RiskScoringEngine

_COMPOSITE_WEIGHTS: dict[ScoreBucket, float] = {
    ScoreBucket.MCP_SURFACE: 0.6,
    ScoreBucket.SUPPLY_CHAIN: 0.25,
    ScoreBucket.DEPENDENCY_HYGIENE: 0.15,
}


def partition_findings(findings: list[Finding]) -> dict[ScoreBucket, list[Finding]]:
    """Split findings into disjoint buckets (each finding in exactly one)."""
    buckets: dict[ScoreBucket, list[Finding]] = {bucket: [] for bucket in ScoreBucket}
    for finding in findings:
        buckets[bucket_for_finding(finding)].append(finding)
    return buckets


def score_partitioned(findings: list[Finding], *, use_display: bool = False) -> ScoreBreakdown:
    """Compute per-bucket scores and a weighted composite."""
    engine = RiskScoringEngine()
    buckets = partition_findings(findings)
    scores: dict[ScoreBucket, RiskScore] = {
        bucket: engine.score(rows, use_display=use_display) for bucket, rows in buckets.items()
    }
    composite = round(sum(_COMPOSITE_WEIGHTS[bucket] * scores[bucket].overall for bucket in ScoreBucket))
    composite = max(0, min(100, composite))
    return ScoreBreakdown(
        mcp_surface=scores[ScoreBucket.MCP_SURFACE].overall,
        supply_chain=scores[ScoreBucket.SUPPLY_CHAIN].overall,
        dependency_hygiene=scores[ScoreBucket.DEPENDENCY_HYGIENE].overall,
        composite=composite,
    )
