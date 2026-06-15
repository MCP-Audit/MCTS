"""V2 scoring evidence tag helpers for analyzers (PR-4b)."""

from __future__ import annotations

from typing import Any

from mcts.reporting.models import Finding

V2_EVIDENCE_KEYS = frozenset(
    {
        "precondition_level",
        "confidence",
        "reachability_tag",
        "exposure_tag",
        "exploitability_class",
        "ciafc_hints",
        "threat_maturity",
        "analysis_mode",
        "path",
        "hop_count",
        "risk_tags",
    }
)

V2_COMMAND_EXECUTION = {
    "exploitability_class": "command_execution",
    "ciafc_hints": ["integrity", "availability"],
}
V2_DATA_LEAKAGE = {
    "exploitability_class": "data_exfiltration",
    "ciafc_hints": ["confidentiality"],
}
V2_TOOL_ABUSE = {"reachability_tag": "default"}
V2_CROSS_SERVER = {"reachability_tag": "network_exposed"}
V2_BEHAVIORAL_STATIC = {
    "exploitability_class": "behavioral_static",
    "reachability_tag": "default",
    "threat_maturity": "default",
}
V2_PATH_VALIDATION = {"exploitability_class": "metadata"}
V2_DISCOVERY_META = {
    "exploitability_class": "hygiene",
    "reachability_tag": "default",
    "threat_maturity": "theoretical",
}
V2_STATIC_DISCOVERY = {
    "exploitability_class": "hygiene",
    "reachability_tag": "default",
    "threat_maturity": "default",
}


def merge_evidence(base: dict[str, Any] | None, tags: dict[str, Any]) -> dict[str, Any]:
    out = dict(base or {})
    for key, value in tags.items():
        out.setdefault(key, value)
    return out


def reachability_for_scope(scan_scope: str) -> str:
    return "network_exposed" if scan_scope == "live" else "default"


def has_v2_evidence(finding: Finding) -> bool:
    evidence = finding.evidence or {}
    return any(key in evidence for key in V2_EVIDENCE_KEYS)


def has_non_default_v2_evidence(finding: Finding) -> bool:
    """True when analyzer-emitted v2 evidence tags are present on the finding."""
    evidence = finding.evidence or {}
    explicit_keys = (
        "exploitability_class",
        "reachability_tag",
        "exposure_tag",
        "precondition_level",
        "threat_maturity",
        "ciafc_hints",
        "path",
        "hop_count",
        "risk_tags",
        "analysis_mode",
    )
    return any(key in evidence for key in explicit_keys)


def tag_permission_finding(finding: Finding) -> Finding:
    evidence = dict(finding.evidence or {})
    if "destructive" in finding.id:
        evidence = merge_evidence(evidence, {"precondition_level": "some"})
        default_confidence = 0.75
    else:
        evidence = merge_evidence(evidence, {"precondition_level": "default"})
        default_confidence = 0.70
    confidence = finding.confidence if finding.confidence is not None else default_confidence
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_prompt_injection_finding(finding: Finding, *, scan_scope: str = "repository") -> Finding:
    evidence = merge_evidence(
        finding.evidence,
        {
            "reachability_tag": reachability_for_scope(scan_scope),
            "exposure_tag": "public_endpoint",
            "risk_tags": ["reachability_tag", "exposure_tag"],
        },
    )
    confidence = finding.confidence if finding.confidence is not None else 0.85
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_schema_surface_finding(finding: Finding, *, scan_scope: str = "repository") -> Finding:
    return tag_prompt_injection_finding(finding, scan_scope=scan_scope)


def tag_jailbreak_finding(finding: Finding) -> Finding:
    evidence = dict(finding.evidence or {})
    if "live" in finding.id:
        evidence = merge_evidence(evidence, {"threat_maturity": "poc"})
    else:
        evidence = merge_evidence(evidence, {"threat_maturity": "default"})
    evidence.setdefault("analysis_mode", "static_heuristic")
    confidence = finding.confidence if finding.confidence is not None else 0.80
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_command_execution_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_COMMAND_EXECUTION)
    confidence = max(finding.confidence or 0.0, 0.85)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_data_leakage_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_DATA_LEAKAGE)
    confidence = max(finding.confidence or 0.0, 0.85)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_tool_abuse_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_TOOL_ABUSE)
    confidence = max(finding.confidence or 0.0, 0.70)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_cross_server_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_CROSS_SERVER)
    confidence = max(finding.confidence or 0.0, 0.70)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_path_validation_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_PATH_VALIDATION)
    confidence = max(finding.confidence or 0.0, 0.70)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_behavioral_static_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_BEHAVIORAL_STATIC)
    confidence = max(finding.confidence or 0.0, 0.70)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_live_discovery_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_DISCOVERY_META)
    confidence = finding.confidence if finding.confidence is not None else 0.70
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_static_discovery_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(finding.evidence, V2_STATIC_DISCOVERY)
    confidence = max(finding.confidence or 0.0, 0.70)
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def tag_attack_chain_finding(finding: Finding) -> Finding:
    evidence = merge_evidence(
        finding.evidence,
        {"confidence": 0.70, "analysis_mode": "static_heuristic"},
    )
    confidence = finding.confidence if finding.confidence is not None else 0.70
    return finding.model_copy(update={"evidence": evidence, "confidence": confidence})


def enrich_graph_dependent_evidence(
    findings: list[Finding],
    *,
    attack_graph: dict[str, Any] | None = None,
    scan_scope: str = "repository",
) -> list[Finding]:
    """Post-scan enrichment for tags that need graph context or scan scope."""
    graph = attack_graph or {}
    paths = graph.get("paths") or []
    out: list[Finding] = []
    for finding in findings:
        if finding.analyzer == "attack_chains":
            evidence = dict(finding.evidence or {})
            for path in paths:
                finding_ids = path.get("finding_ids") or []
                normalized = {str(x).replace("-", "_") for x in finding_ids}
                if finding.id in finding_ids or finding.id.replace("-", "_") in normalized:
                    evidence.setdefault("path", path.get("nodes") or path.get("tools_on_path"))
                    evidence.setdefault("hop_count", path.get("hop_count", 0))
                    break
            if "path" not in evidence and evidence.get("read_tools"):
                evidence["path_status"] = "unproven"
            finding = finding.model_copy(update={"evidence": evidence})
        elif finding.analyzer in {"prompt_injection", "schema_surface"}:
            evidence = dict(finding.evidence or {})
            evidence["reachability_tag"] = reachability_for_scope(scan_scope)
            evidence.setdefault("exposure_tag", "public_endpoint")
            evidence.setdefault("risk_tags", ["reachability_tag", "exposure_tag"])
            finding = finding.model_copy(update={"evidence": evidence})
        out.append(finding)
    return out
