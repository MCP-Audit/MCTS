"""V2 scoring alignment with findings trust (Phase B2)."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.reporting.models import Finding, Severity
from mcts.scoring.chains import path_is_proven, resolve_chain_factors
from mcts.scoring.context import build_scoring_context, scorable_findings_v2
from mcts.scoring.engine_v2 import RiskScoringEngineV2, base_risk
from mcts.scoring.factors import classify_business_impact
from mcts.scoring.models import RiskFactorVector
from mcts.scoring.weights import load_weights

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_path_is_proven_requires_multi_hop() -> None:
    assert not path_is_proven({"hop_count": 1, "nodes": ["a", "b"]})
    assert path_is_proven({"hop_count": 2, "nodes": ["a", "b", "c"]})
    assert path_is_proven({"nodes": ["a", "b", "c"]})


def test_resolve_chain_factors_skips_unproven_paths_when_display() -> None:
    finding = Finding(
        id="exec-1",
        analyzer="command_execution",
        title="Exec",
        description="d",
        severity=Severity.CRITICAL,
        display_severity=Severity.MEDIUM,
        recommendation="fix",
        tool="ask_sales_agent_tool",
    )
    graph = {
        "paths": [
            {"hop_count": 1, "tools_on_path": ["ask_sales_agent_tool"], "nodes": ["ask_sales_agent_tool"]},
        ]
    }
    scorable = scorable_findings_v2([finding])
    template_factors = resolve_chain_factors(scorable, graph, use_display=False)
    display_factors = resolve_chain_factors(scorable, graph, use_display=True)
    assert template_factors.get("exec-1") == 1.0
    assert "exec-1" not in display_factors


def test_v2_base_risk_uses_display_severity() -> None:
    weights = load_weights("manual_v1")
    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="Exec",
        description="d",
        severity=Severity.CRITICAL,
        display_severity=Severity.MEDIUM,
        recommendation="fix",
    )
    factors = RiskFactorVector(exploitability=0.5)
    template = base_risk(finding, factors, weights, use_display=False)
    display = base_risk(finding, factors, weights, use_display=True)
    assert display < template


def test_business_impact_follows_display_severity() -> None:
    weights = load_weights("manual_v1")
    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="Exec",
        description="d",
        severity=Severity.CRITICAL,
        display_severity=Severity.LOW,
        recommendation="fix",
    )
    template_impact = classify_business_impact(finding, weights, use_display=False)
    display_impact = classify_business_impact(finding, weights, use_display=True)
    assert template_impact > display_impact


def test_scanner_v2_verify_with_enforce_context() -> None:
    config = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce", scoring_mode="v2")
    report = Scanner(config).run()
    assert report.score_v2 is not None
    ctx = build_scoring_context(
        findings=report.findings,
        server=report.server,
        attack_graph=report.attack_graph,
        scan_scope=report.scan_scope,
        config=config,
        chain_factor_mode="paths_v1",
    )
    assert ctx.use_display_severity is True
    assert RiskScoringEngineV2.verify(ctx, report.score_v2)
