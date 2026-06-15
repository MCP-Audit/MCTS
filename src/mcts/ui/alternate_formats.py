"""Alternate terminal report layouts."""

from __future__ import annotations

from collections import defaultdict

from rich.console import Console
from rich.table import Table

from mcts.reporting.display import effective_severity, report_trust_enforced
from mcts.reporting.models import Finding, ScanReport, Severity


def render_report(
    report: ScanReport,
    fmt: str,
    console: Console,
    *,
    severity_filter: set[Severity] | None = None,
    tool_filter: set[str] | None = None,
    analyzer_filter: set[str] | None = None,
    hide_safe: bool = False,
) -> None:
    findings = _filter_findings(
        report,
        severity_filter,
        tool_filter,
        analyzer_filter,
        hide_safe,
    )
    fmt = fmt.lower()
    if fmt == "table":
        _render_table(findings, console, use_display=report_trust_enforced(report))
    elif fmt == "by_tool":
        _render_grouped(
            findings,
            console,
            key=lambda f: f.tool or "(no tool)",
            use_display=report_trust_enforced(report),
        )
    elif fmt == "by_analyzer":
        _render_grouped(
            findings,
            console,
            key=lambda f: f.analyzer,
            use_display=report_trust_enforced(report),
        )
    elif fmt == "by_severity":
        _render_grouped(
            findings,
            console,
            key=lambda f: effective_severity(f).value if report_trust_enforced(report) else f.severity.value,
            use_display=report_trust_enforced(report),
        )
    elif fmt == "summary":
        _render_summary(report, findings, console)
    else:
        raise ValueError(f"Unknown terminal format: {fmt}")


def _filter_findings(
    report: ScanReport,
    severity_filter: set[Severity] | None,
    tool_filter: set[str] | None,
    analyzer_filter: set[str] | None,
    hide_safe: bool,
) -> list[Finding]:
    rows = report.findings
    use_display_filter = report.findings_trust_mode == "enforce"
    if severity_filter:
        if use_display_filter:
            rows = [f for f in rows if effective_severity(f) in severity_filter]
        else:
            rows = [f for f in rows if f.severity in severity_filter]
    if tool_filter:
        rows = [f for f in rows if f.tool and f.tool in tool_filter]
    if analyzer_filter:
        rows = [f for f in rows if f.analyzer in analyzer_filter]
    if hide_safe and not rows:
        return rows
    return rows


def _severity_label(finding: Finding, *, use_display: bool) -> str:
    return effective_severity(finding).value if use_display else finding.severity.value


def _render_table(findings: list[Finding], console: Console, *, use_display: bool) -> None:
    table = Table(title="MCTS Findings")
    table.add_column("Severity")
    table.add_column("Analyzer")
    table.add_column("Tool")
    table.add_column("Title")
    for f in findings:
        table.add_row(_severity_label(f, use_display=use_display), f.analyzer, f.tool or "-", f.title)
    console.print(table)


def _render_grouped(
    findings: list[Finding],
    console: Console,
    key,
    *,
    use_display: bool,
) -> None:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[key(f)].append(f)
    for group, items in sorted(groups.items()):
        console.print(f"\n[bold]{group}[/bold] ({len(items)})")
        for f in items:
            console.print(f"  [{_severity_label(f, use_display=use_display)}] {f.title}")


def _render_summary(report: ScanReport, findings: list[Finding], console: Console) -> None:
    use_display = report_trust_enforced(report)
    active = (report.display_summary or report.summary) if use_display else report.summary
    line = f"Legacy score: {report.score.overall}/100 — {len(findings)} finding(s)"
    if use_display:
        line += f" (display critical {active.critical}, high {active.high})"
    if report.score_v2 is not None:
        line += f" | absolute_risk {report.score_v2.absolute_risk} ({report.score_v2.risk_level})"
        if report.score_v2.security_score is not None:
            line += f" | security_score {report.score_v2.security_score}/100"
    console.print(line)
    for f in findings[:10]:
        console.print(f"  [{_severity_label(f, use_display=use_display)}] {f.title}")
