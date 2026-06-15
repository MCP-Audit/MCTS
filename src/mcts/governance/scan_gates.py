"""Evaluate CI/policy scan gates without exiting the process."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.report.data import category_gate_failures, category_scores_v2_gate_failures
from mcts.reporting.display import summary_for_gates
from mcts.reporting.models import ScanReport
from mcts.reporting.trust_gates import bronze_gate_violations, priority_gate_violations

_LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _gate_use_display(config: ScanConfig) -> bool:
    return config.findings_trust_mode == "enforce"


def _level_exceeds(actual: str, maximum: str) -> bool:
    return _LEVEL_ORDER.get(actual, 0) > _LEVEL_ORDER.get(maximum, 0)


def _any_v2_gate(config: ScanConfig) -> bool:
    return any(
        value is not None
        for value in (
            config.min_security_score,
            config.max_absolute_risk,
            config.max_risk_level,
        )
    ) or bool(config.min_category_score_v2)


def evaluate_scan_gate_violations(report: ScanReport, config: ScanConfig) -> list[str]:
    """Return human-readable gate violations for CLI, API, and GitHub Action consumers."""
    violations: list[str] = []
    gate_summary = summary_for_gates(report, config)

    if config.fail_on_critical and gate_summary.critical > 0:
        violations.append(f"critical findings present ({gate_summary.critical})")

    if config.min_score is not None and report.score.overall < config.min_score:
        violations.append(f"legacy overall score {report.score.overall}/100 below minimum {config.min_score}")

    if _any_v2_gate(config):
        if report.score_v2 is None:
            violations.append("v2 gate requires scoring_mode v2 or both")
        elif report.score_v2 is not None:
            if config.min_security_score is not None:
                if report.score_v2.security_score is None:
                    violations.append("min_security_score requires packaged corpus stats")
                elif report.score_v2.security_score < config.min_security_score:
                    violations.append(
                        f"security_score {report.score_v2.security_score} "
                        f"below minimum {config.min_security_score}"
                    )
            if (
                config.max_absolute_risk is not None
                and report.score_v2.absolute_risk > config.max_absolute_risk
            ):
                violations.append(
                    f"absolute_risk {report.score_v2.absolute_risk} "
                    f"exceeds maximum {config.max_absolute_risk}"
                )
            if config.max_risk_level is not None and _level_exceeds(
                report.score_v2.risk_level, config.max_risk_level
            ):
                violations.append(
                    f"risk_level {report.score_v2.risk_level} exceeds maximum {config.max_risk_level}"
                )

    if config.max_critical is not None and gate_summary.critical > config.max_critical:
        violations.append(
            f"critical findings ({gate_summary.critical}) exceed maximum ({config.max_critical})"
        )

    if config.max_high is not None and gate_summary.high > config.max_high:
        violations.append(f"high findings ({gate_summary.high}) exceed max {config.max_high}")

    violations.extend(
        category_gate_failures(
            report.findings,
            config.fail_on_category,
            use_display=_gate_use_display(config),
        )
    )
    if config.min_category_score_v2 and report.score_v2 is not None:
        violations.extend(
            category_scores_v2_gate_failures(
                report.findings,
                config.min_category_score_v2,
                use_display=_gate_use_display(config),
            )
        )
    violations.extend(priority_gate_violations(report, config))
    violations.extend(bronze_gate_violations(report, config))
    return violations
