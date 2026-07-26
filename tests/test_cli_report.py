"""Tests for mcts report CLI validation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.reporting.models import Finding, RiskScore, ScanReport, ScanSummary, ScoreBasis, Severity

runner = CliRunner()


def _minimal_report() -> ScanReport:
    from datetime import UTC, datetime

    from mcts.mcp.models import MCPServerInfo

    return ScanReport(
        version="0.0.0",
        target="server.py",
        scanned_at=datetime.now(UTC),
        server=MCPServerInfo(name="demo"),
        findings=[
            Finding(
                id="f1",
                analyzer="prompt_injection",
                title="test",
                description="d",
                severity=Severity.LOW,
                recommendation="r",
            )
        ],
        summary=ScanSummary(low=1, total=1),
        score=RiskScore(
            overall=95,
            risk_index=5,
            raw_risk=5,
            penalty=5,
            basis=ScoreBasis(
                critical=0,
                high=0,
                medium=0,
                low=1,
                scorable_total=1,
                excluded_non_scorable=0,
            ),
        ),
    )


def test_report_rejects_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", str(tmp_path), "-o", str(tmp_path / "out.html")])
    assert result.exit_code == 2
    assert "not a directory" in result.stdout or "JSON file" in result.stdout


def test_report_missing_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["report", str(missing)])
    assert result.exit_code == 2
    assert "not found" in result.stdout.lower()


def test_scan_scoring_both_prints_v2_summary(example_server_path: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(example_server_path), "--scoring", "both", "--no-progress", "--no-save"],
    )
    assert result.exit_code in (0, 1), result.stdout
    assert "absolute_risk" in result.stdout.lower() or "Absolute Risk" in result.stdout


def test_scan_help_explains_config_static_vs_live() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    output = " ".join(result.stdout.replace("│", " ").split())

    assert result.exit_code == 0
    assert "static mode reads metadata only and does not execute launch args" in output
    assert "add --live for per-server runtime analysis" in output
    assert "with --config, uses its command and args" in output


def test_config_static_scan_warns_in_console_and_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "prod": {
                        "command": "definitely-not-a-real-command",
                        "args": ["--sso-env", "prod"],
                    }
                }
            }
        )
    )
    (tmp_path / "app.py").write_text("x = 1\n")
    output_path = tmp_path / "scan-report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--config",
            str(config),
            "--server",
            "prod",
            "--no-progress",
            "--output",
            str(output_path),
        ],
    )
    console_output = " ".join(result.stdout.split())

    assert result.exit_code == 0, result.stdout
    assert "did not execute the server command or args" in console_output
    assert "All config servers may share the same score until --live is used" in console_output

    payload = json.loads(output_path.read_text())
    scan_notes = " ".join(payload["scan_notes"])
    assert "did not execute the server command or args" in scan_notes
    assert "server=prod" in scan_notes


def test_report_valid_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_minimal_report().model_dump_json())
    out = tmp_path / "out.html"
    result = runner.invoke(app, ["report", str(report_path), "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
