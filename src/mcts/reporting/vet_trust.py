"""Bridge VetFinding models through the findings trust pipeline."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.reporting.models import Finding
from mcts.reporting.trust_apply import apply_config_trust_layer
from mcts.vet.models import VetFinding, VetReport


def vet_finding_to_finding(row: VetFinding) -> Finding:
    evidence = dict(row.evidence)
    if "facts" not in evidence:
        evidence.setdefault(
            "facts",
            [
                {
                    "rule_id": "RULE_VET_HEURISTIC",
                    "match": row.id,
                    "field": "vet_report",
                    "tool": row.id,
                }
            ],
        )
    return Finding(
        id=row.id,
        analyzer="vet",
        title=row.title,
        description=row.description,
        severity=row.severity,
        recommendation=row.recommendation,
        evidence=evidence,
        finding_kind="hygiene",
        display_severity=row.display_severity,
        priority_score=row.priority_score,
        evidence_strength=row.evidence_strength,
        rule_stability=row.rule_stability,
    )


def finding_to_vet_finding(original: VetFinding, trusted: Finding) -> VetFinding:
    return original.model_copy(
        update={
            "display_severity": trusted.display_severity,
            "priority_score": trusted.priority_score,
            "evidence_strength": trusted.evidence_strength,
            "evidence": trusted.evidence or original.evidence,
            "rule_stability": trusted.rule_stability,
        }
    )


def apply_trust_to_vet_report(report: VetReport, config: ScanConfig) -> VetReport:
    if config.findings_trust_mode == "off" or not report.findings:
        return report
    trusted_rows = apply_config_trust_layer(
        [vet_finding_to_finding(row) for row in report.findings],
        config,
        scan_scope="vet",
    )
    findings = [
        finding_to_vet_finding(original, trusted)
        for original, trusted in zip(report.findings, trusted_rows, strict=True)
    ]
    return report.model_copy(update={"findings": findings})


def vet_severity_label(row: VetFinding, config: ScanConfig) -> str:
    if config.findings_trust_mode == "off":
        return row.severity.value
    if row.display_severity is not None:
        return row.display_severity.value
    return row.severity.value


def vet_effective_severity(row: VetFinding) -> str:
    if row.display_severity is not None:
        return row.display_severity.value
    return row.severity.value
