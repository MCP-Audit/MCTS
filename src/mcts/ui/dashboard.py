"""Dashboard layout components for scan reports."""

from __future__ import annotations

from dataclasses import dataclass

from rich import box
from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcts.report.data import category_scores
from mcts.reporting.display import effective_severity, report_trust_enforced
from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity
from mcts.ui.layout import FINDINGS_PANEL_MIN_WIDTH, SEVERITY_PANEL_WIDTH, content_width
from mcts.ui.theme import SEVERITY_ORDER, Theme

OWASP_CATALOG: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("LLM01", "Prompt Injection", ("prompt_injection",)),
    ("LLM02", "Sensitive Information Disclosure", ("data_leakage",)),
    ("LLM04", "Model Denial of Service", ("tool_abuse",)),
    ("LLM06", "Excessive Agency", ("attack_chains", "permission_analyzer", "compliance")),
    ("LLM07", "System Prompt Leakage", ("jailbreak",)),
    ("LLM08", "Vector and Embedding Weaknesses", ()),
)

TOP_FINDINGS_LIMIT = 8


@dataclass(frozen=True)
class ScanDisplayMeta:
    """Metadata for terminal dashboard rendering."""

    command: str
    duration_seconds: float
    analyzers_run: int


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by display severity when set (stable order within same severity)."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[effective_severity(f)], f.title))


def compute_owasp_counts(findings: list[Finding]) -> list[tuple[str, str, int]]:
    """Map findings to OWASP LLM categories with counts."""
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for owasp_id, label, analyzers in OWASP_CATALOG:
        labels[owasp_id] = label
        matched = sum(1 for f in findings if f.analyzer in analyzers)
        if matched:
            counts[owasp_id] = matched

    return [
        (owasp_id, labels[owasp_id], count)
        for owasp_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def build_scan_status(meta: ScanDisplayMeta, report: ScanReport, theme: Theme) -> Table:
    """Build scan complete status block with aligned metrics."""
    p = theme.palette
    grid = Table.grid(padding=(0, 1))
    grid.add_column(
        style=theme.style(p.grey),
        justify="left",
        no_wrap=True,
        width=18,
    )
    grid.add_column(style=theme.style(p.white), justify="left", overflow="fold")

    grid.add_row(
        Text("✓ Scan Complete", style=theme.style(p.green, bold=True)),
        "",
    )
    grid.add_row("Target:", report.target)
    grid.add_row("Scan Time:", f"{max(meta.duration_seconds, 0.01):.2f}s")
    grid.add_row("Tools Discovered:", str(len(report.server.tools)))
    grid.add_row("Analyzers Run:", str(meta.analyzers_run))
    if getattr(report, "scan_scope", None):
        grid.add_row("Scan Scope:", str(report.scan_scope))
    if _needs_tool_notice(report):
        grid.add_row(
            "",
            Text(
                "Static scan — tools/list was not called. Use --live, --snapshot, or scan an entrypoint.",
                style=theme.style(p.yellow),
            ),
        )
    for note in getattr(report, "scan_notes", []) or []:
        grid.add_row(
            "",
            Text(note, style=theme.style(p.cyan)),
        )
    return grid


def _needs_tool_notice(report: ScanReport) -> bool:
    if report.server.tools:
        return False
    mode = report.server.discovery_mode or "static"
    if mode in ("live", "static-json"):
        return False
    return report.scan_scope not in ("live", "snapshot")


REPORT_DIVIDER = "=" * 20 + " MCTS Security Report " + "=" * 20


def build_report_divider(theme: Theme) -> Text:
    """Security report divider (fixed width for consistent screenshots)."""
    return Text(REPORT_DIVIDER, style=theme.style(theme.palette.white, bold=True))


def build_score_block(report: ScanReport, theme: Theme) -> Table:
    """Security score and risk index derived from report findings."""
    p = theme.palette
    basis = report.score.basis
    rating, score_color = theme.score_rating(report.score.overall)
    risk_color = theme.risk_index_color(report.score.risk_index)
    v2_first = report.score_v2 is not None and report.scoring_version == "both"

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style=theme.style(p.white, bold=True), width=16, no_wrap=True)
    grid.add_column(justify="left")

    if v2_first:
        v2 = report.score_v2
        grid.add_row(
            "Absolute Risk:",
            Text(
                f"{v2.absolute_risk} ({v2.risk_level})",
                style=theme.style(p.orange, bold=True),
            ),
        )
        if v2.security_score is not None:
            grid.add_row(
                "Security Score:",
                Text(f"{v2.security_score}/100", style=theme.style(p.yellow, bold=True)),
            )

    grid.add_row(
        "Overall Score:",
        Text(f"{report.score.overall}/100 ({rating})", style=theme.style(score_color, bold=True)),
    )
    grid.add_row(
        "Risk Index:",
        Text(f"{report.score.risk_index}/100", style=theme.style(risk_color, bold=True)),
    )
    grid.add_row(
        "Scoring basis:",
        Text(
            f"{basis.critical} Critical, {basis.high} High, "
            f"{basis.medium} Medium, {basis.low} Low "
            f"({basis.scorable_total} scorable findings)",
            style=theme.style(p.white),
        ),
    )
    if report.score_v2 is not None and report.scoring_version in {"v2", "both"} and not v2_first:
        v2 = report.score_v2
        grid.add_row(
            "Absolute Risk:",
            Text(
                f"{v2.absolute_risk} ({v2.risk_level})",
                style=theme.style(p.orange, bold=True),
            ),
        )
        if v2.security_score is not None:
            grid.add_row(
                "Security Score:",
                Text(f"{v2.security_score}/100", style=theme.style(p.yellow, bold=True)),
            )
    if basis.excluded_non_scorable:
        grid.add_row(
            "",
            Text(
                f"{basis.excluded_non_scorable} compliance meta-finding(s) "
                "shown in report but excluded from score",
                style=theme.style(p.grey, dim=True),
            ),
        )
    breakdown = getattr(report, "score_breakdown", None)
    if breakdown is not None:
        grid.add_row(
            "MCP Surface:",
            Text(f"{breakdown.mcp_surface}/100", style=theme.style(p.white)),
        )
        grid.add_row(
            "Supply Chain:",
            Text(f"{breakdown.supply_chain}/100", style=theme.style(p.white)),
        )
        grid.add_row(
            "Dependency Hygiene:",
            Text(f"{breakdown.dependency_hygiene}/100", style=theme.style(p.white)),
        )
        grid.add_row(
            "Composite:",
            Text(f"{breakdown.composite}/100", style=theme.style(p.cyan, bold=True)),
        )
    return grid


def build_category_breakdown(report: ScanReport, theme: Theme) -> Table:
    """Risk category breakdown aligned with the HTML dashboard."""
    p = theme.palette
    table = Table(
        title="Risk Category Breakdown",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style=theme.style(p.cyan, bold=True),
        title_style=theme.style(p.white, bold=True),
        border_style=theme.style(p.panel_border),
        padding=(0, 1),
    )
    table.add_column("Category", style=theme.style(p.white))
    table.add_column("Score", justify="right", style=theme.style(p.yellow, bold=True))
    table.add_column("Findings", justify="right", style=theme.style(p.muted))

    use_display = report_trust_enforced(report)
    for row in category_scores(report.findings, use_display=use_display):
        table.add_row(row["label"], row["display"], str(row["findings_count"]))
    return table


def build_severity_panel(summary: ScanSummary, theme: Theme) -> Panel:
    """Left panel: severity breakdown with colored bullets."""
    p = theme.palette
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=theme.style(p.grey, bold=True),
        border_style=p.panel_border,
        expand=False,
        padding=(0, 1),
    )
    table.add_column("Severity", width=14, no_wrap=True)
    table.add_column("Count", width=5, justify="right")

    rows = [
        (Severity.CRITICAL, summary.critical, "● Critical"),
        (Severity.HIGH, summary.high, "● High"),
        (Severity.MEDIUM, summary.medium, "● Medium"),
        (Severity.LOW, summary.low, "● Low"),
    ]
    for severity, count, label in rows:
        color = theme.severity_color(severity)
        table.add_row(
            Text(label, style=theme.style(color, bold=True)),
            str(count),
        )

    return Panel(
        table,
        title=f"[bold {p.cyan}]Severity Summary[/]",
        title_align="left",
        border_style=p.panel_border,
        width=SEVERITY_PANEL_WIDTH,
        padding=(0, 1),
    )


def _format_finding_line(index: int, finding: Finding, theme: Theme, wrap_width: int) -> Text:
    """Format a single top finding entry with optional title wrap."""
    p = theme.palette
    sev_color = theme.severity_color(effective_severity(finding))
    sev_label = theme.severity_label(effective_severity(finding))
    indent = " " * 12
    first_line_budget = max(wrap_width - 12, 20)
    title = finding.title

    line = Text()
    line.append(f"[{index}] ", style=theme.style(p.grey, dim=True))
    line.append(f"{sev_label:<8}", style=theme.style(sev_color, bold=True))

    if len(title) <= first_line_budget:
        line.append(f" {title}", style=theme.style(p.white))
        return line

    split_at = title.rfind(" ", 0, first_line_budget)
    if split_at <= 0:
        split_at = first_line_budget
    line.append(f" {title[:split_at]}", style=theme.style(p.white))
    remainder = title[split_at:].lstrip()
    if remainder:
        line.append("\n")
        line.append(f"{indent}{remainder}", style=theme.style(p.white))
    return line


def build_top_findings_panel(findings: list[Finding], theme: Theme, panel_width: int) -> Panel:
    """Right panel: ranked top findings."""
    p = theme.palette
    sorted_findings = sort_findings(findings)
    shown = sorted_findings[:TOP_FINDINGS_LIMIT]
    wrap_width = max(28, panel_width - 6)

    body = Text()
    for idx, finding in enumerate(shown, start=1):
        if idx > 1:
            body.append("\n")
        body.append_text(_format_finding_line(idx, finding, theme, wrap_width))

    remaining = len(sorted_findings) - len(shown)
    if remaining > 0:
        body.append("\n")
        body.append(f"\n...and {remaining} more findings", style=theme.style(p.grey, dim=True))

    return Panel(
        body if shown else Text("No findings detected.", style=theme.style(p.green)),
        title=f"[bold {p.cyan}]Top Findings[/]",
        title_align="left",
        border_style=p.panel_border,
        width=panel_width,
        padding=(0, 1),
    )


def build_owasp_section(findings: list[Finding], theme: Theme) -> RenderableType:
    """OWASP LLM Top 10 mapping block."""
    p = theme.palette
    owasp_counts = compute_owasp_counts(findings)
    if not owasp_counts:
        return Text("No OWASP mappings available.", style=theme.style(p.grey, dim=True))

    max_count = max(count for _, _, count in owasp_counts)
    header = Text("OWASP LLM Top 10 Mapping\n", style=theme.style(p.blue, bold=True))

    lines = Text()
    for owasp_id, label, count in owasp_counts:
        short_label = label.replace(" Disclosure", "")
        if len(short_label) > 28:
            short_label = short_label[:25] + "..."
        count_color = theme.owasp_count_color(count, max_count)
        lines.append("• ", style=theme.style(p.cyan))
        lines.append(f"{owasp_id}: {short_label:<28}", style=theme.style(p.white))
        lines.append(f" ({count})\n", style=theme.style(count_color, bold=True))

    return Group(header, lines)


def build_footer_tip(theme: Theme) -> RenderableType:
    """Footer tip with command hints."""
    p = theme.palette
    tip = Text()
    tip.append("💡 ", style=theme.style(p.tip_icon))
    tip.append("Tip: ", style=theme.style(p.grey, bold=True))
    tip.append("Reports saved under ", style=theme.style(p.muted))
    tip.append("mcts_analysis/", style=theme.style(p.command, bold=True))
    tip.append(" (JSON + HTML + SARIF; trend builds across runs)", style=theme.style(p.muted))
    return tip


def build_dashboard(
    report: ScanReport,
    meta: ScanDisplayMeta,
    theme: Theme,
    *,
    terminal_width: int,
) -> RenderableType:
    """Assemble full dashboard as a single fixed-width renderable."""
    width = content_width(terminal_width)
    findings_width = max(FINDINGS_PANEL_MIN_WIDTH, width - SEVERITY_PANEL_WIDTH - 2)

    blocks: list[RenderableType] = [
        build_scan_status(meta, report, theme),
        build_report_divider(theme),
        build_score_block(report, theme),
        build_category_breakdown(report, theme),
    ]

    severity_summary = report.display_summary or report.summary

    if width >= 90:
        blocks.append(
            Columns(
                [
                    build_severity_panel(severity_summary, theme),
                    build_top_findings_panel(report.findings, theme, findings_width),
                ],
                width=width,
                expand=False,
                equal=False,
                padding=0,
            )
        )
    else:
        blocks.extend(
            [
                build_severity_panel(severity_summary, theme),
                build_top_findings_panel(report.findings, theme, width - 4),
            ]
        )

    blocks.extend(
        [
            Panel(
                build_owasp_section(report.findings, theme),
                border_style=theme.palette.panel_border,
                width=width,
                padding=(0, 1),
            ),
            build_report_divider(theme),
            build_footer_tip(theme),
        ]
    )

    return Group(*blocks)
