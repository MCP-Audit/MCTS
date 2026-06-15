"""Tests for SARIF reporting and CI gates."""

import json
from pathlib import Path

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME
from mcts.reporting.sarif import build_sarif, write_sarif_report

runner = CliRunner()


def test_sarif_includes_mcts_metadata(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text('{"mcpServers":{"demo":{"command":"python","args":[]}}}')
    (tmp_path / "main.py").write_text("print(1)\n")
    report = Scanner(ScanConfig(target=tmp_path, config_path=config, config_server="demo")).run()
    sarif = build_sarif(report)
    props = sarif["runs"][0]["properties"]
    assert props["mcts/scanMode"] == "config-static"
    assert props.get("mcts/scanNotes")
    assert props.get("mcts/scoreBreakdown") is not None


def test_sarif_report_structure(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    sarif = build_sarif(report)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "MCTS"
    exportable = [f for f in report.findings if (f.finding_kind or "security") != "coverage"]
    assert len(sarif["runs"][0]["results"]) == len(exportable)
    assert sarif["runs"][0]["properties"]["securityScore"] == report.score.overall
    assert "taxa" not in sarif["runs"][0]
    for result in sarif["runs"][0]["results"]:
        for taxon in result.get("taxa", []):
            assert isinstance(taxon, dict)
        assert result.get("locations"), "GitHub Code Scanning requires at least one location per result"
        assert "security-severity" not in result.get("properties", {})
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        severity = rule.get("properties", {}).get("security-severity")
        assert severity is not None
        assert float(severity) > 0


def test_write_sarif_report_is_valid_json(example_server_path: Path) -> None:
    report = Scanner(ScanConfig(target=example_server_path)).run()
    payload = write_sarif_report(report)
    parsed = json.loads(payload)
    assert parsed["runs"][0]["results"]


def test_cli_sarif_output(example_server_path: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        [
            "scan",
            str(example_server_path),
            "--output",
            str(out),
            "--format",
            "sarif",
            "--no-progress",
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert (tmp_path / ANALYSIS_DIR_NAME / "scan-report.json").exists()
    assert (tmp_path / ANALYSIS_DIR_NAME / "scan-report.html").exists()


def test_min_score_gate_fails(example_server_path: Path) -> None:
    result = runner.invoke(
        app,
        ["scan", str(example_server_path), "--min-score", "99", "--no-progress", "--no-save"],
    )
    assert result.exit_code == 1
    assert "CI gate failed" in result.stdout
    assert "Score breakdown:" in result.stdout
    assert "MCP Surface:" in result.stdout
    assert "Supply Chain:" in result.stdout
    assert "Dependency Hygiene:" in result.stdout
    assert "primary failure driver" in result.stdout


def test_min_score_gate_passes_on_baseline_server() -> None:
    baseline = Path(__file__).parent.parent / "examples" / "baseline-mcp-server" / "server.py"
    result = runner.invoke(
        app,
        ["scan", str(baseline), "--min-score", "90", "--no-progress", "--no-save"],
    )
    assert result.exit_code == 0, result.output
