"""Trust-layer CI gates (priority score, evidence strength)."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.reporting.display import is_security_finding
from mcts.reporting.models import Finding, ScanReport

EVIDENCE_STRENGTH_ORDER: dict[str, int] = {
    "weak": 0,
    "moderate": 1,
    "strong": 2,
    "verified": 3,
}

VALID_EVIDENCE_STRENGTHS = frozenset(EVIDENCE_STRENGTH_ORDER)


def normalize_evidence_strength(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.lower().strip()
    if normalized not in VALID_EVIDENCE_STRENGTHS:
        raise ValueError(
            f"min_evidence_strength must be one of: {', '.join(sorted(VALID_EVIDENCE_STRENGTHS))}"
        )
    return normalized


def meets_evidence_strength(actual: str | None, minimum: str | None) -> bool:
    if minimum is None:
        return True
    if actual is None:
        return False
    return EVIDENCE_STRENGTH_ORDER.get(actual.lower(), -1) >= EVIDENCE_STRENGTH_ORDER.get(minimum, 0)


def findings_over_priority_threshold(
    findings: list[Finding],
    *,
    minimum_priority: int,
    minimum_evidence_strength: str | None = None,
) -> list[Finding]:
    matched: list[Finding] = []
    for finding in findings:
        if not is_security_finding(finding):
            continue
        if finding.priority_score is None:
            continue
        if finding.priority_score < minimum_priority:
            continue
        if not meets_evidence_strength(finding.evidence_strength, minimum_evidence_strength):
            continue
        matched.append(finding)
    matched.sort(key=lambda row: (-(row.priority_score or 0), row.title))
    return matched


def findings_missing_bronze_facts(findings: list[Finding]) -> list[Finding]:
    """Experimental analyzers must emit at least one structured fact (Phase 1.5 contract)."""
    from mcts.reporting.rule_stability import default_rule_stability

    missing: list[Finding] = []
    for finding in findings:
        if not is_security_finding(finding):
            continue
        stability = finding.rule_stability or default_rule_stability(finding.analyzer)
        if stability != "experimental":
            continue
        facts = (finding.evidence or {}).get("facts")
        if isinstance(facts, list) and facts:
            continue
        missing.append(finding)
    missing.sort(key=lambda row: (row.analyzer, row.title))
    return missing


def bronze_gate_violations(report: ScanReport, config: ScanConfig) -> list[str]:
    if not (config.enforce_bronze_facts or False) or config.findings_trust_mode != "enforce":
        return []
    missing = findings_missing_bronze_facts(report.findings)
    if not missing:
        return []
    sample = missing[0]
    return [
        (
            f"{len(missing)} experimental finding(s) missing bronze facts "
            f"(evidence.facts); first: {sample.analyzer}/{sample.id!r}"
        )
    ]


def priority_gate_violations(report: ScanReport, config: ScanConfig) -> list[str]:
    """Fail when security findings exceed priority threshold (Option B CI).

    Active only under ``findings_trust_mode=enforce`` — same contract as severity gates.
    """
    if config.fail_on_priority_min is None or config.findings_trust_mode != "enforce":
        return []
    matched = findings_over_priority_threshold(
        report.findings,
        minimum_priority=config.fail_on_priority_min,
        minimum_evidence_strength=config.min_evidence_strength,
    )
    if not matched:
        return []
    strength_note = (
        f" with evidence_strength>={config.min_evidence_strength}" if config.min_evidence_strength else ""
    )
    top = matched[0]
    return [
        (
            f"{len(matched)} finding(s) at or above priority {config.fail_on_priority_min}{strength_note} "
            f"(highest: {top.title!r} priority={top.priority_score})"
        )
    ]
