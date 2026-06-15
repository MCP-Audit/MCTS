"""Chain factor resolution for tool-attributed findings."""

from __future__ import annotations

from typing import Any

from mcts.reporting.display import severity_for_scoring
from mcts.reporting.models import Finding, Severity

CHAIN_ELIGIBLE_SEVERITIES = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})


def hop_factor_for(hop_count: int) -> float:
    if hop_count <= 1:
        return 1.0
    if hop_count == 2:
        return 1.15
    if hop_count == 3:
        return 1.35
    return 1.50


def path_is_proven(path: dict[str, Any]) -> bool:
    """True when a graph path has multi-hop evidence (not overlap-only)."""
    hop_count = path.get("hop_count")
    if isinstance(hop_count, int) and hop_count >= 2:
        return True
    nodes = path.get("nodes") or path.get("tools_on_path") or []
    return isinstance(nodes, list) and len(nodes) >= 3


def resolve_chain_factors(
    scorable_findings: list[Finding],
    attack_graph: dict[str, Any],
    *,
    use_display: bool = False,
) -> dict[str, float]:
    factors: dict[str, float] = {}
    for path in attack_graph.get("paths", []):
        if use_display and not path_is_proven(path):
            continue
        hop_factor = hop_factor_for(path.get("hop_count", 0))
        tools_on_path = set(path.get("tools_on_path", path.get("nodes", [])))
        for finding in scorable_findings:
            if finding.analyzer == "attack_chains":
                continue
            tool = finding.tool or finding.evidence.get("tool")
            if not tool and finding.evidence.get("affected_tools"):
                affected = finding.evidence.get("affected_tools")
                if isinstance(affected, list) and affected:
                    tool = affected[0]
            if not tool or tool not in tools_on_path:
                continue
            severity = severity_for_scoring(finding, use_display=use_display)
            if severity not in CHAIN_ELIGIBLE_SEVERITIES:
                continue
            factors[finding.id] = max(factors.get(finding.id, 1.0), hop_factor)
    return factors
