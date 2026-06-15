"""Build ScoringContext for v2 engine."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, ScanReport
from mcts.scoring.asset import load_assets
from mcts.scoring.chains import resolve_chain_factors
from mcts.scoring.corpus import load_corpus_stats
from mcts.scoring.factors import ScoringContext
from mcts.scoring.graph import canonical_attack_graph_from_scan
from mcts.scoring.weights import load_weights, weights_hash


def scorable_findings_v2(findings: list[Finding]) -> list[Finding]:
    from mcts.scoring.engine import NON_SCORING_ANALYZERS

    excluded = NON_SCORING_ANALYZERS | frozenset({"attack_chains"})
    return [f for f in findings if f.analyzer not in excluded]


def build_scoring_context(
    *,
    findings: list[Finding],
    server: MCPServerInfo,
    attack_graph: dict,
    scan_scope: str,
    config: ScanConfig,
    chain_factor_mode: str,
) -> ScoringContext:
    weights = load_weights(config.weights_profile)
    w_hash = weights_hash(weights)
    graph = canonical_attack_graph_from_scan(attack_graph, findings, server.tools)
    scorable = scorable_findings_v2(findings)
    use_display = config.findings_trust_mode == "enforce"
    chain_factors = (
        resolve_chain_factors(scorable, graph, use_display=use_display)
        if chain_factor_mode == "paths_v1"
        else {}
    )
    corpus = None
    if config.corpus_stats_path:
        corpus = load_corpus_stats(Path(config.corpus_stats_path))
    else:
        corpus = load_corpus_stats()
    return ScoringContext(
        findings=findings,
        tools=server.tools,
        attack_graph=graph,
        scan_scope=scan_scope,
        weights=weights,
        corpus_stats=corpus,
        assets=load_assets(config.assets_path),
        chain_factors=chain_factors,
        chain_factor_mode=chain_factor_mode,
        last_absolute_risk=None,
        weights_hash=w_hash,
        use_display_severity=use_display,
    )


def rebuild_scoring_context_from_report(report: ScanReport, config: ScanConfig) -> ScoringContext:
    """Rebuild v2 context from a completed scan (corpus stats refresh)."""
    chain_factor_mode = "paths_v1" if config.enable_attack_chains else "disabled"
    merged = config.model_copy(
        update={
            "findings_trust_mode": report.findings_trust_mode or config.findings_trust_mode,
        }
    )
    return build_scoring_context(
        findings=report.findings,
        server=report.server,
        attack_graph=report.attack_graph,
        scan_scope=report.scan_scope,
        config=merged,
        chain_factor_mode=chain_factor_mode,
    )
