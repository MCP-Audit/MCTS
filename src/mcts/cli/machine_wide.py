"""CLI helpers for machine-wide scanning."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from mcts.core.config import ScanConfig
from mcts.output.analysis_dir import resolve_output_path
from mcts.scan.machine_wide import run_machine_wide
from mcts.ui.report_renderer import ReportRenderer


def run_machine_wide_cli(
    base_config: ScanConfig,
    *,
    output: Path | None,
    no_save: bool,
    console: Console,
    renderer: ReportRenderer,
) -> int:
    """Execute machine-wide scan and print summary. Returns CLI exit code."""
    summary = run_machine_wide(base_config)

    console.print(f"[bold]Machine-wide scan[/bold] — {summary.scanned} scanned, {summary.skipped} skipped")
    if summary.failed:
        console.print(f"[yellow]{summary.failed} server(s) failed to scan[/yellow]")

    for row in summary.results:
        label = f"[{row.entry.client}] {row.entry.server_name}"
        if row.report is not None:
            line = f"  {label} — score {row.report.score.overall}/100"
            if row.report.score_v2 is not None:
                line += f", absolute_risk {row.report.score_v2.absolute_risk}"
                if row.report.score_v2.security_score is not None:
                    line += f", security_score {row.report.score_v2.security_score}/100"
            line += f", {len(row.report.findings)} finding(s)"
            console.print(line)
        elif row.error:
            console.print(f"  {label} — [dim]skipped: {row.error}[/dim]")

    if not no_save:
        output_path = resolve_output_path(output, "machine-scan-report.json")
        output_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        renderer.render_saved_notice(str(output_path))

    if summary.scanned == 0:
        console.print("[yellow]No scannable MCP servers found in local client configs.[/yellow]")
        return 0
    violations = summary.gate_violations()
    if violations:
        console.print("[red]Machine-wide gate failures:[/red]")
        for item in violations:
            console.print(f"  • {item}")
    return summary.exit_code()
