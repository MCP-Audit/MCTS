"""Confidence and risk range for scoring v2."""

from __future__ import annotations

from mcts.reporting.models import Finding
from mcts.scoring.factors import ScoringContext, build_factor_vector
from mcts.scoring.models import ADDITIVE_FACTORS

ANALYZER_CONFIDENCE_CAP: dict[str, float] = {
    "permission_analyzer": 0.75,
    "attack_chains": 0.70,
    "tool_abuse": 0.70,
    "cross_server": 0.70,
    "prompt_injection": 0.85,
    "schema_surface": 0.85,
    "jailbreak": 0.80,
    "command_execution": 0.85,
    "data_leakage": 0.85,
    "behavioral_static": 0.70,
}
DEFAULT_CONFIDENCE = 0.60


def effective_confidence(finding: Finding) -> float:
    raw = finding.confidence
    cap = ANALYZER_CONFIDENCE_CAP.get(finding.analyzer)
    if cap is not None and raw >= 0.99:
        return cap
    return raw if raw is not None else DEFAULT_CONFIDENCE


def confidence_score(findings: list[Finding], per_finding_risks: list[int]) -> int:
    pairs = [(r, f) for f, r in zip(findings, per_finding_risks, strict=True) if r > 0]
    if not pairs:
        return 100
    total_w = sum(r for r, _ in pairs)
    weighted = sum(effective_confidence(f) * r for r, f in pairs)
    return max(0, min(100, round(100 * weighted / total_w)))


def evidence_quality_factor(findings: list[Finding]) -> float:
    tags = {t for f in findings for t in ((f.evidence or {}).get("risk_tags") or [])}
    if {"live_probe", "handler_traced"} <= tags:
        return 0.8
    for finding in findings:
        if finding.finding_type != "validated":
            continue
        validation = (finding.evidence or {}).get("runtime_validation")
        if validation in {"live_probe", "live_proxy"}:
            return 0.8
        if validation == "taint_param_sink":
            facts = (finding.evidence or {}).get("facts") or []
            if any(isinstance(row, dict) and row.get("snippet") for row in facts):
                return 0.8
    return 1.2


def analyzer_disagreement_factor(findings: list[Finding], *, use_display: bool = False) -> float:
    from mcts.reporting.display import effective_severity

    severities_by_tool: dict[str, set[str]] = {}
    for finding in findings:
        tool = finding.tool
        if not tool:
            affected = finding.evidence.get("affected_tools")
            if isinstance(affected, list) and affected:
                tool = str(affected[0])
        if not tool:
            continue
        severity = effective_severity(finding) if use_display else finding.severity
        severities_by_tool.setdefault(tool, set()).add(severity.value)
    if any(len(values) > 1 for values in severities_by_tool.values()):
        return 1.4
    return 1.0


def compute_risk_range(
    absolute_risk: int,
    findings: list[Finding],
    per_finding_risks: list[int],
    *,
    use_display: bool = False,
) -> tuple[tuple[int, int], str]:
    if absolute_risk == 0:
        return (0, 0), "high"
    pairs = [(r, f) for f, r in zip(findings, per_finding_risks, strict=True) if r > 0]
    mean_conf = (
        sum(effective_confidence(f) * r for r, f in pairs) / sum(r for r, _ in pairs) if pairs else 1.0
    )
    base_spread = absolute_risk * (1 - mean_conf) * 0.35
    spread = (
        base_spread
        * evidence_quality_factor(findings)
        * analyzer_disagreement_factor(findings, use_display=use_display)
    )
    low = max(0, round(absolute_risk - spread))
    high = round(absolute_risk + spread)
    label = "high" if mean_conf >= 0.85 else "medium" if mean_conf >= 0.65 else "low"
    return (low, high), label


def factor_breakdown_dict(finding: Finding, ctx: ScoringContext) -> dict[str, float]:
    vector = build_factor_vector(finding, ctx)
    return {name: getattr(vector, name) for name in ADDITIVE_FACTORS}
