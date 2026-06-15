"""Phase 3 runtime and taint-flow evidence validation."""

from __future__ import annotations

from typing import Any

from mcts.reporting.finding_validator import compute_priority_score
from mcts.reporting.models import Finding

_RUNTIME_PRIORITY_BOOST: dict[str, int] = {
    "taint_param_sink": 15,
    "live_probe": 12,
    "live_proxy": 12,
    "description_mismatch": 10,
}


def validate_runtime_evidence(findings: list[Finding]) -> list[Finding]:
    """Tag validated taint/live findings and set evidence tier when trust is active."""
    return [_boost_runtime_priority(_validate_runtime_one(finding)) for finding in findings]


def _boost_runtime_priority(finding: Finding) -> Finding:
    if finding.finding_type != "validated":
        return finding
    evidence = finding.evidence or {}
    tag = evidence.get("runtime_validation")
    if not tag:
        return finding
    boost = _RUNTIME_PRIORITY_BOOST.get(str(tag), 8)
    impact = finding.impact or finding.severity
    strength = finding.evidence_strength or "moderate"
    chain_level = finding.chain_level or 0
    if tag in {"taint_param_sink", "live_probe", "live_proxy"} and strength in {"weak", "moderate"}:
        strength = "strong"
    base = (
        finding.priority_score
        if finding.priority_score is not None
        else compute_priority_score(impact, strength, chain_level)
    )
    updates: dict[str, object] = {
        "priority_score": min(100, base + boost),
        "evidence_strength": strength,
    }
    return finding.model_copy(update=updates)


def _has_handler_snippet(facts: object) -> bool:
    if not isinstance(facts, list):
        return False
    return any(isinstance(row, dict) and row.get("snippet") for row in facts)


def _merge_runtime_scoring_tags(
    evidence: dict[str, Any], validation_tag: str, *, has_handler_snippet: bool
) -> None:
    """Align Phase 3 tags with v2 scoring (`risk_tags` / evidence_quality_factor)."""
    tags = set(evidence.get("risk_tags") or [])
    if validation_tag in {"live_probe", "live_proxy"}:
        tags.add("live_probe")
    if validation_tag == "taint_param_sink" and has_handler_snippet:
        tags.add("handler_traced")
    if validation_tag in {"live_probe", "live_proxy"} and has_handler_snippet:
        tags.add("handler_traced")
    if tags:
        evidence["risk_tags"] = sorted(tags)


def _validate_runtime_one(finding: Finding) -> Finding:
    evidence = dict(finding.evidence or {})
    facts = evidence.get("facts")
    has_facts = isinstance(facts, list) and bool(facts)
    has_snippet = _has_handler_snippet(facts)

    if finding.analyzer == "behavioral_static" and evidence.get("tainted_params") and evidence.get("sinks"):
        evidence["runtime_validation"] = "taint_param_sink"
        evidence["evidence_tier"] = "silver" if has_facts and has_snippet else "bronze"
        _merge_runtime_scoring_tags(evidence, "taint_param_sink", has_handler_snippet=has_snippet)
        updates: dict[str, object] = {"evidence": evidence}
        if evidence.get("tainted_params"):
            updates["finding_type"] = "validated"
            if finding.confidence is not None and finding.confidence < 0.78:
                updates["confidence"] = 0.78
        return finding.model_copy(update=updates)

    if (
        finding.analyzer == "behavioral_static"
        and finding.id.startswith("behavioral-mismatch")
        and evidence.get("sinks")
    ):
        evidence["runtime_validation"] = "description_mismatch"
        evidence["evidence_tier"] = "silver" if has_facts and has_snippet else "bronze"
        return finding.model_copy(update={"evidence": evidence, "finding_type": "validated"})

    if finding.analyzer == "jailbreak" and evidence.get("analysis_mode") == "live_probe":
        evidence["runtime_validation"] = "live_probe"
        evidence["evidence_tier"] = "silver" if has_facts else "bronze"
        _merge_runtime_scoring_tags(evidence, "live_probe", has_handler_snippet=has_snippet)
        return finding.model_copy(
            update={
                "evidence": evidence,
                "finding_type": "validated",
            }
        )

    if finding.analyzer == "runtime_events" and _is_live_runtime_finding(finding, evidence):
        evidence["runtime_validation"] = "live_proxy"
        evidence["evidence_tier"] = "silver" if has_facts and has_snippet else "bronze"
        _merge_runtime_scoring_tags(evidence, "live_proxy", has_handler_snippet=has_snippet)
        return finding.model_copy(
            update={
                "evidence": evidence,
                "finding_type": "validated",
            }
        )

    return finding


def _is_live_runtime_finding(finding: Finding, evidence: dict[str, object]) -> bool:
    if finding.id.startswith("schema-"):
        return False
    if "event_index" in evidence or "event_count" in evidence:
        return True
    return finding.id.startswith("runtime-")
