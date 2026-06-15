"""Post-scan findings validation for trust layer (Phase A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcts.mcp.models import MCPTool
from mcts.reporting.models import Finding, Severity

DISPLAY_TITLES_ENFORCE: dict[str, str] = {
    "chain-credential-theft": "Potential capability overlap (credential + egress signals)",
    "chain-read-exfil": "Potential capability overlap (read + egress signals)",
    "chain-read-exec": "Potential capability overlap (read + execution signals)",
}

_IMPACT_POINTS: dict[Severity, int] = {
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 100,
}

_STRENGTH_MULT: dict[str, float] = {
    "weak": 0.35,
    "moderate": 0.6,
    "strong": 0.85,
    "verified": 1.0,
}

_CHAIN_MULT: dict[int, float] = {0: 0.4, 1: 0.7, 2: 0.9, 3: 1.0}

_HYGIENE_ANALYZERS = frozenset({"live_discovery", "static_discovery"})
_HEURISTIC_ANALYZERS = frozenset(
    {"attack_chains", "behavioral_static", "jailbreak", "llm_judge", "llm_metadata_triage"}
)


@dataclass
class ValidationContext:
    scan_scope: str
    tools: list[MCPTool]
    attack_graph: dict[str, Any]
    mode: str  # off | warn | enforce


def validate_findings(findings: list[Finding], ctx: ValidationContext) -> list[Finding]:
    """Populate trust fields; optionally cap display severity and rewrite titles."""
    if ctx.mode == "off":
        return findings
    from mcts.reporting.rule_stability import apply_rule_stability

    return [apply_rule_stability(_validate_one(finding, ctx)) for finding in findings]


def _validate_one(finding: Finding, ctx: ValidationContext) -> Finding:
    updates: dict[str, Any] = {}
    updates["finding_kind"] = _classify_kind(finding)
    updates["finding_type"] = _default_finding_type(finding)

    if finding.analyzer == "attack_chains":
        _validate_attack_chain(finding, ctx, updates)
    elif updates["finding_kind"] == "security":
        impact = finding.impact or finding.severity
        strength = finding.evidence_strength or _default_evidence_strength(finding)
        display = finding.display_severity or finding.severity
        if strength == "weak":
            display = _cap_display_severity(finding.severity, Severity.MEDIUM)
        updates.update(
            {
                "impact": impact,
                "evidence_strength": strength,
                "display_severity": display,
                "chain_level": 0,
                "priority_score": _priority_score(impact, strength, 0),
            }
        )
    else:
        if finding.impact is None:
            updates["impact"] = finding.severity
        strength = finding.evidence_strength
        display = finding.display_severity or finding.severity
        if strength == "weak":
            display = _cap_display_severity(finding.severity, Severity.MEDIUM)
        updates["display_severity"] = display

    return finding.model_copy(update=updates)


def _validate_attack_chain(finding: Finding, ctx: ValidationContext, updates: dict[str, Any]) -> None:
    proven_path = _has_proven_path(finding, ctx.attack_graph)
    overlap_single, _ = _single_tool_overlap(finding.evidence)

    if proven_path:
        chain_level = _chain_level_from_path(finding.id, finding.evidence, ctx.attack_graph)
        impact = finding.impact or finding.severity
        evidence = dict(finding.evidence or {})
        evidence["path_status"] = "proven"
        evidence.pop("single_tool_overlap", None)
        updates.update(
            {
                "evidence_type": "graph_path",
                "chain_level": chain_level,
                "evidence_strength": "moderate",
                "finding_type": "inferred",
                "impact": impact,
                "display_severity": finding.display_severity or finding.severity,
                "priority_score": _priority_score(impact, "moderate", chain_level),
                "evidence": evidence,
            }
        )
        return

    impact = finding.impact or finding.severity
    evidence = dict(finding.evidence or {})
    evidence["path_status"] = "unproven"
    evidence.pop("hop_count", None)
    evidence.pop("path", None)
    if overlap_single:
        evidence["single_tool_overlap"] = True

    updates.update(
        {
            "evidence_type": "capability_overlap",
            "chain_level": 0,
            "evidence_strength": "weak",
            "finding_type": "heuristic",
            "impact": impact,
            "display_severity": _cap_display_severity(finding.severity, Severity.MEDIUM),
            "priority_score": _priority_score(impact, "weak", 0),
            "evidence": evidence,
        }
    )
    if ctx.mode == "enforce" and finding.id in DISPLAY_TITLES_ENFORCE:
        updates["title"] = DISPLAY_TITLES_ENFORCE[finding.id]


def _classify_kind(finding: Finding) -> str:
    if finding.finding_kind:
        return finding.finding_kind
    if finding.analyzer == "compliance":
        return "coverage"
    if finding.analyzer in _HYGIENE_ANALYZERS or finding.analyzer in {"readiness", "vet"}:
        return "hygiene"
    return "security"


def _default_finding_type(finding: Finding) -> str:
    if finding.finding_type:
        return finding.finding_type
    if finding.analyzer == "attack_chains":
        return "heuristic"
    return "inferred"


def _single_tool_overlap(evidence: dict[str, Any]) -> tuple[bool, list[str]]:
    names: list[str] = []
    for key in ("read_tools", "credential_tools", "exfil_tools", "exec_tools"):
        raw = evidence.get(key, [])
        if isinstance(raw, list):
            names.extend(str(item) for item in raw)
    unique = set(names)
    return len(unique) == 1 and len(unique) > 0, sorted(unique)


def _has_proven_path(finding: Finding, attack_graph: dict[str, Any]) -> bool:
    for path in attack_graph.get("paths") or []:
        if not isinstance(path, dict):
            continue
        finding_ids = path.get("finding_ids")
        if not isinstance(finding_ids, list):
            continue
        if not finding_ids or finding.id not in finding_ids:
            continue
        hop_count = path.get("hop_count")
        if isinstance(hop_count, int) and hop_count >= 2:
            return True
        nodes = path.get("nodes") or path.get("tools_on_path") or []
        if isinstance(nodes, list) and len(nodes) >= 3:
            return True
    return False


def _chain_level_from_path(
    finding_id: str,
    evidence: dict[str, Any],
    attack_graph: dict[str, Any],
) -> int:
    hop = evidence.get("hop_count")
    if isinstance(hop, int) and hop > 0:
        return min(hop, 3)
    for path in attack_graph.get("paths") or []:
        if not isinstance(path, dict):
            continue
        finding_ids = path.get("finding_ids")
        if isinstance(finding_ids, list) and finding_id not in finding_ids:
            continue
        hop_count = path.get("hop_count")
        if isinstance(hop_count, int) and hop_count > 0:
            return min(hop_count, 3)
    return 1


def _cap_display_severity(template: Severity, cap: Severity) -> Severity:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if order.index(template) > order.index(cap):
        return cap
    return template


def _default_evidence_strength(finding: Finding) -> str:
    evidence = finding.evidence or {}
    facts = evidence.get("facts")
    if isinstance(facts, list) and facts:
        if any(isinstance(row, dict) and row.get("snippet") for row in facts):
            return "strong"
        return "moderate"
    if finding.analyzer in _HEURISTIC_ANALYZERS:
        return "weak"
    has_location = finding.location is not None and bool(getattr(finding.location, "file", None))
    has_line_evidence = bool(evidence.get("line") or evidence.get("snippet"))
    confidence = finding.confidence if finding.confidence is not None else 0.75
    if not has_location and not has_line_evidence and confidence < 0.72:
        return "weak"
    if confidence < 0.55:
        return "weak"
    return "moderate"


def compute_priority_score(impact: Severity, strength: str, chain_level: int) -> int:
    """Public priority model (impact × strength × chain level). Used by validator and runtime boost."""
    base = _IMPACT_POINTS.get(impact, 50)
    mult = _STRENGTH_MULT.get(strength, 0.6)
    chain = _CHAIN_MULT.get(chain_level, 0.4)
    return max(0, min(100, round(base * mult * chain)))


def _priority_score(impact: Severity, strength: str, chain_level: int) -> int:
    return compute_priority_score(impact, strength, chain_level)
