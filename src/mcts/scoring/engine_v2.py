"""Risk scoring engine v2 — multi-factor absolute risk."""

from __future__ import annotations

import math
from dataclasses import replace
from typing import Any

from mcts.reporting.models import Finding
from mcts.scoring.context import scorable_findings_v2
from mcts.scoring.engine import NON_SCORING_ANALYZERS
from mcts.scoring.factors import ScoringContext, bracket, build_factor_vector
from mcts.scoring.levels import risk_level_from_absolute
from mcts.scoring.models import (
    FACTOR_DIMENSIONS,
    RiskScoreV2,
    ScoreV2Basis,
    ScoringWeights,
    TopContributor,
)
from mcts.scoring.normalize import security_score_from_absolute
from mcts.scoring.uncertainty import (
    compute_risk_range,
    confidence_score,
    effective_confidence,
    factor_breakdown_dict,
)

NON_SCORING_V2 = NON_SCORING_ANALYZERS | frozenset({"attack_chains"})


def base_risk(finding: Finding, factors, weights: ScoringWeights, *, use_display: bool = False) -> int:
    from mcts.reporting.display import severity_for_scoring

    severity = severity_for_scoring(finding, use_display=use_display)
    severity_w = weights.severity[severity.value]
    return round(severity_w * bracket(factors))


def finding_risk(finding: Finding, ctx: ScoringContext) -> int:
    factors = build_factor_vector(finding, ctx)
    base = base_risk(finding, factors, ctx.weights, use_display=ctx.use_display_severity)
    chain_factor = ctx.chain_factors.get(finding.id, 1.0)
    return math.floor(base * chain_factor + 0.5)


def dimension_raw_sums(findings: list[Finding], ctx: ScoringContext) -> dict[str, float]:
    """Per-axis raw factor sums for scorable findings (pre-normalization)."""
    dim_raw: dict[str, float] = {d: 0.0 for d in FACTOR_DIMENSIONS}
    for finding in scorable_findings_v2(findings):
        factors = build_factor_vector(finding, ctx)
        for name in FACTOR_DIMENSIONS:
            dim_raw[name] += getattr(factors, name)
    return dim_raw


def compute_dimension_scores(findings: list[Finding], ctx: ScoringContext) -> dict[str, int]:
    """Relative factor load per axis on this scan (0–100; highest axis = 100)."""
    dim_raw = dimension_raw_sums(findings, ctx)
    return {dim: normalize_dim(dim_raw[dim], dim_raw) for dim in FACTOR_DIMENSIONS}


def normalize_dim(raw: float, dim_raw: dict[str, float]) -> int:
    if raw <= 0:
        return 0
    max_raw = max(dim_raw.values()) if dim_raw else 0.0
    if max_raw <= 0:
        return 0
    return min(100, round(100 * raw / max_raw))


def build_top_contributors(
    ctx: ScoringContext,
    findings: list[Finding],
    per_finding_risks: list[int],
    limit: int = 10,
) -> list[TopContributor]:
    from mcts.scoring.chains import hop_factor_for

    rows: list[TopContributor] = []
    ranked = sorted(
        zip(findings, per_finding_risks, strict=True),
        key=lambda x: x[1],
        reverse=True,
    )
    for finding, risk in ranked[:9]:
        if finding.analyzer in NON_SCORING_V2 or risk <= 0:
            continue
        rows.append(
            TopContributor(
                type="finding",
                finding_id=finding.id,
                risk_contribution=risk,
                confidence=round(100 * effective_confidence(finding)),
                chain_factor=ctx.chain_factors.get(finding.id, 1.0),
                factors=factor_breakdown_dict(finding, ctx),
            )
        )
    paths = sorted(
        ctx.attack_graph.get("paths", []),
        key=lambda p: p.get("hop_count", 0),
        reverse=True,
    )
    if paths and len(rows) < limit and _paths_are_proven(paths):
        path = paths[0]
        rows.append(
            TopContributor(
                type="attack_chain",
                path_id=path.get("id"),
                hop_count=path.get("hop_count"),
                nodes=path.get("nodes") or path.get("tools_on_path"),
                in_chain_findings=path.get("finding_ids"),
                chain_factor=hop_factor_for(path.get("hop_count", 0)),
            )
        )
    return rows[:limit]


def _paths_are_proven(paths: list[dict[str, Any]]) -> bool:
    """Suppress overlap-only paths (hop_count < 2) from top contributors."""
    from mcts.scoring.chains import path_is_proven

    return any(path_is_proven(path) for path in paths)


class RiskScoringEngineV2:
    """Computes absolute risk and explainable v2 score from a ScoringContext."""

    def score(self, ctx: ScoringContext, *, legacy_overall: int) -> RiskScoreV2:
        core = self._compute_core(ctx)
        security_score: int | None = None
        risk_percentile: int | None = None
        if ctx.corpus_stats:
            security_score, risk_percentile = security_score_from_absolute(
                core.absolute_risk, ctx.corpus_stats
            )
        return RiskScoreV2(
            absolute_risk=core.absolute_risk,
            risk_range=core.risk_range,
            risk_range_confidence=core.risk_range_confidence,
            risk_level=core.risk_level,
            security_score=security_score,
            risk_percentile=risk_percentile,
            legacy_overall=legacy_overall,
            confidence_score=core.confidence_score,
            weights_profile=ctx.weights.version,
            benchmark_corpus_version=ctx.corpus_stats.version if ctx.corpus_stats else None,
            chain_factor_mode=ctx.chain_factor_mode,
            dimension_scores=core.dimension_scores,
            top_contributors=core.top_contributors,
            basis=core.basis,
        )

    @classmethod
    def verify(cls, ctx: ScoringContext, score: RiskScoreV2) -> bool:
        recomputed = cls._compute_core(ctx)
        return (
            recomputed.absolute_risk == score.absolute_risk
            and recomputed.risk_range == score.risk_range
            and recomputed.basis.weights_hash == score.basis.weights_hash
        )

    @classmethod
    def _compute_core(cls, ctx: ScoringContext) -> RiskScoreV2:
        scorable = scorable_findings_v2(ctx.findings)
        risks = [finding_risk(f, ctx) for f in scorable]
        absolute_risk = sum(risks)
        risk_range, risk_range_confidence = compute_risk_range(
            absolute_risk, scorable, risks, use_display=ctx.use_display_severity
        )
        conf = confidence_score(scorable, risks)
        contributors = build_top_contributors(ctx, scorable, risks)
        ctx_with_risk = replace(ctx, last_absolute_risk=absolute_risk)
        dimension_scores = compute_dimension_scores(ctx.findings, ctx_with_risk)
        severity_counts: dict[str, int] = {}
        for finding in scorable:
            from mcts.reporting.display import severity_for_scoring

            key = severity_for_scoring(finding, use_display=ctx.use_display_severity).value
            severity_counts[key] = severity_counts.get(key, 0) + 1
        excluded = len(ctx.findings) - len(scorable)
        basis = ScoreV2Basis(
            scorable_count=len(scorable),
            excluded_non_scorable=excluded,
            severity_counts=severity_counts,
            weights_hash=ctx.weights_hash,
            weights_profile=ctx.weights.version,
        )
        return RiskScoreV2(
            absolute_risk=absolute_risk,
            risk_range=risk_range,
            risk_range_confidence=risk_range_confidence,
            risk_level=risk_level_from_absolute(absolute_risk, ctx.corpus_stats),
            confidence_score=conf,
            weights_profile=ctx.weights.version,
            chain_factor_mode=ctx.chain_factor_mode,
            dimension_scores=dimension_scores,
            top_contributors=contributors,
            basis=basis,
            legacy_overall=0,
        )
