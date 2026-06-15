"""Factor classifiers for scoring v2."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from mcts.mcp.models import MCPTool
from mcts.reporting.models import Finding
from mcts.scoring.asset import resolve_asset_value
from mcts.scoring.exposure import apply_reachability_exposure_dedup, classify_exposure
from mcts.scoring.models import RiskFactorVector, ScoringWeights
from mcts.scoring.preconditions import classify_preconditions
from mcts.scoring.reachability import classify_reachability

_ANALYZER_EXPLOIT: dict[str, str] = {
    "command_execution": "command_execution",
    "prompt_injection": "prompt_injection",
    "data_leakage": "data_exfiltration",
    "tool_abuse": "prompt_injection",
    "behavioral_static": "behavioral_static",
    "path_validation": "metadata",
    "permission_analyzer": "permission",
    "jailbreak": "prompt_injection",
    "discovery_meta": "hygiene",
    "live_discovery": "hygiene",
    "static_discovery": "hygiene",
}


def compute_blast_radius(finding: Finding, tools: list[MCPTool]) -> float:
    total = len(tools)
    if total == 0:
        return 0.0
    affected = 1 if finding.tool else total
    path_tools = finding.evidence.get("tools_on_path")
    if path_tools:
        affected = len(set(path_tools))
    return math.log(affected + 1) / math.log(total + 1)


def classify_exploitability(finding: Finding, weights: ScoringWeights) -> float:
    table = weights.classifiers.get("exploitability", {})
    evidence = finding.evidence or {}
    key = str(evidence.get("exploitability_class") or _ANALYZER_EXPLOIT.get(finding.analyzer, "default"))
    return table.get(key, table.get("default", 0.05))


_CIAFC_HINT_WEIGHTS = {
    "confidentiality": 0.15,
    "integrity": 0.12,
    "availability": 0.10,
}


def classify_business_impact(
    finding: Finding, weights: ScoringWeights, *, use_display: bool = False
) -> float:
    table = weights.classifiers.get("business_impact", {})
    evidence = finding.evidence or {}
    explicit = evidence.get("business_impact")
    if explicit:
        return table.get(str(explicit), table.get("default", 0.20))
    hints = evidence.get("ciafc_hints") or []
    if hints:
        aggregate = sum(_CIAFC_HINT_WEIGHTS.get(str(hint), 0.08) for hint in hints)
        if aggregate >= 0.24:
            return table.get("high", 0.40)
        if aggregate >= 0.12:
            return table.get("medium", 0.25)
        return table.get("default", 0.20)
    from mcts.reporting.display import severity_for_scoring

    severity = severity_for_scoring(finding, use_display=use_display)
    if severity.value in {"critical", "high"}:
        return table.get("high", 0.40)
    if severity.value == "medium":
        return table.get("medium", 0.25)
    return table.get("default", 0.20)


def classify_threat_maturity(finding: Finding, weights: ScoringWeights) -> float:
    table = weights.classifiers.get("threat_maturity", {})
    evidence = finding.evidence or {}
    tag = evidence.get("threat_maturity")
    if tag:
        return table.get(str(tag), table.get("default", 0.10))
    if finding.analyzer == "jailbreak":
        return table.get("poc", 0.30)
    return table.get("default", 0.10)


@dataclass
class ScoringContext:
    findings: list[Finding]
    tools: list[MCPTool]
    attack_graph: dict[str, Any]
    scan_scope: str
    weights: ScoringWeights
    chain_factors: dict[str, float] = field(default_factory=dict)
    corpus_stats: Any | None = None
    assets: Any | None = None
    chain_factor_mode: str = "paths_v1"
    last_absolute_risk: int | None = None
    weights_hash: str = ""
    use_display_severity: bool = False


def _evidence_tags(finding: Finding) -> list[str]:
    evidence = finding.evidence or {}
    tags: list[str] = []
    for key in (
        "reachability_tag",
        "exposure_tag",
        "exploitability_class",
        "precondition_level",
        "threat_maturity",
        "analysis_mode",
    ):
        if evidence.get(key):
            tags.append(f"{key}:{evidence[key]}")
    for hint in evidence.get("ciafc_hints") or []:
        tags.append(f"ciafc:{hint}")
    return tags


def build_factor_vector(finding: Finding, ctx: ScoringContext) -> RiskFactorVector:
    reachability = classify_reachability(finding, ctx.scan_scope, ctx.weights)
    exposure = classify_exposure(finding, ctx.weights)
    exposure = apply_reachability_exposure_dedup(reachability, exposure, finding.evidence or {})
    return RiskFactorVector(
        exploitability=classify_exploitability(finding, ctx.weights),
        reachability=reachability,
        exposure=exposure,
        blast_radius=compute_blast_radius(finding, ctx.tools),
        business_impact=classify_business_impact(finding, ctx.weights, use_display=ctx.use_display_severity),
        asset_value=resolve_asset_value(finding, ctx.weights, ctx.assets),
        attack_preconditions=classify_preconditions(finding, ctx.scan_scope, ctx.weights),
        threat_maturity=classify_threat_maturity(finding, ctx.weights),
        evidence_tags=_evidence_tags(finding),
    )


def bracket(factors: RiskFactorVector) -> float:
    return 1.0 + sum(
        getattr(factors, name)
        for name in (
            "exploitability",
            "reachability",
            "exposure",
            "blast_radius",
            "business_impact",
            "asset_value",
            "threat_maturity",
            "attack_preconditions",
        )
    )
