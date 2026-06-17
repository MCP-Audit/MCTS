"""Phase 3b template hardening: ELICIT_PHISH and SSRF_RESOURCE policy edges."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, GraphEdge, GraphLayer, NodeKind
from mcts.scoring.attack_graph_policy import (
    DEFAULT_RESOURCE_ACCESS_PROBABILITY,
    apply_policy_edges,
)
from mcts.scoring.graph_matcher import match_template
from mcts.scoring.graph_templates import load_templates

MONOREPO_MINI = Path("tests/fixtures/monorepo-mini")
REGRESSION = Path("tests/fixtures/regression")


def test_resource_access_probability() -> None:
    """Policy RESOURCE_READABLE_BY_CONTEXT edges use default access_probability."""
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.merge_edge(
        GraphEdge(
            id="edge-write-resource",
            kind=EdgeKind.WRITES,
            from_node="tool:gzip-file-as-resource",
            to_node="resource:session/staged",
            layer=GraphLayer.DATAFLOW,
        )
    )
    apply_policy_edges(graph, MCPServerInfo(), [])
    readable = [e for e in graph.edges.values() if e.kind == EdgeKind.RESOURCE_READABLE_BY_CONTEXT]
    assert readable
    edge = readable[0]
    assert edge.reachability == DEFAULT_RESOURCE_ACCESS_PROBABILITY
    assert edge.access_probability == DEFAULT_RESOURCE_ACCESS_PROBABILITY
    assert edge.to_node == "sink:model_context"


def test_elicit_phish_matches_synthetic_graph() -> None:
    template = next(t for t in load_templates() if t.id == "ELICIT_PHISH")
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "trigger-url-elicitation", label="trigger-url-elicitation")
    graph.add_node(NodeKind.CAPABILITY, "elicitation", label="elicitation")
    graph.merge_edge(
        GraphEdge(
            id="edge-triggers-elicitation",
            kind=EdgeKind.TRIGGERS,
            from_node="tool:trigger-url-elicitation",
            to_node="capability:elicitation",
            layer=GraphLayer.TRUST_BOUNDARY,
            confidence=0.75,
            reachability=0.8,
        )
    )
    matches = match_template(template, graph)
    assert matches
    assert matches[0].template_id == "ELICIT_PHISH"
    assert "trigger-url-elicitation" in matches[0].path.tool_names_on_path()


def test_elicit_phish_r23_fixture() -> None:
    spec = json.loads((REGRESSION / "R-23-elicitation-phish" / "expected.json").read_text())
    target = MONOREPO_MINI / spec["servers_path"]
    report = Scanner(ScanConfig(target=str(target), surface_depth="full")).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert "ELICIT_PHISH" in matched


def test_read_exec_r24_fixture() -> None:
    spec = json.loads((REGRESSION / "R-24-read-exec" / "expected.json").read_text())
    target = MONOREPO_MINI / spec["servers_path"]
    report = Scanner(ScanConfig(target=str(target), surface_depth="full")).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert "READ_EXEC" in matched


def test_cred_theft_r25_fixture() -> None:
    spec = json.loads((REGRESSION / "R-25-cred-theft" / "expected.json").read_text())
    target = MONOREPO_MINI / spec["servers_path"]
    report = Scanner(ScanConfig(target=str(target), surface_depth="full")).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert "CRED_THEFT" in matched
