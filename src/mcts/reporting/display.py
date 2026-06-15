"""Display helpers for findings trust layer (Phase A).

No imports from scanner, report/data, or other pipeline modules.
"""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity

NON_SECURITY_ANALYZERS = frozenset({"compliance", "live_discovery", "static_discovery"})


def effective_severity(finding: Finding) -> Severity:
    """User-facing severity; falls back to template severity when unset."""
    return finding.display_severity or finding.severity


def effective_impact(finding: Finding) -> Severity:
    """Potential impact; falls back to template severity when unset."""
    return finding.impact or finding.severity


def is_security_finding(finding: Finding) -> bool:
    """True for findings that belong in default security counts/views."""
    if finding.finding_kind in ("coverage", "hygiene"):
        return False
    return finding.analyzer not in NON_SECURITY_ANALYZERS


def summary_for_gates(report: ScanReport, config: ScanConfig) -> ScanSummary:
    """Route CI/governance to display summary when trust enforcement is active."""
    if config.findings_trust_mode != "enforce":
        return report.summary
    if report.display_summary is not None:
        return report.display_summary
    return ScanSummary.from_display(report.findings, security_only=True)


def report_trust_enforced(report: ScanReport) -> bool:
    """True when the scan used findings trust enforcement."""
    return report.findings_trust_mode == "enforce"


def severity_for_scoring(finding: Finding, *, use_display: bool) -> Severity:
    """Severity input for v1/v2 scoring when trust enforcement is active."""
    return effective_severity(finding) if use_display else finding.severity
