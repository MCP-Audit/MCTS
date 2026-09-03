"""Tests for repository-wide static discovery."""

from pathlib import Path

from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.discovery.static import StaticDiscovery
from mcts.reporting.models import Severity

BENCH_REPO = Path(__file__).parent.parent / "examples" / "bench" / "multi-file-server"


def test_static_discovery_finds_tools_in_repo() -> None:
    config = ScanConfig(target=BENCH_REPO)
    info = StaticDiscovery(config).discover()

    tool_names = {tool.name for tool in info.tools}
    assert "read_config" in tool_names
    assert "notify_webhook" in tool_names
    assert len(info.source_files) >= 1


def test_tools_have_input_schema_and_capabilities() -> None:
    config = ScanConfig(target=BENCH_REPO)
    info = StaticDiscovery(config).discover()

    read_tool = next(t for t in info.tools if t.name == "read_config")
    assert read_tool.input_schema.get("properties", {}).get("path") is not None
    assert read_tool.capability is not None
    assert read_tool.capability.reads_untrusted_input is True


def test_scan_repo_directory() -> None:
    report = Scanner(ScanConfig(target=BENCH_REPO)).run()
    assert len(report.server.tools) >= 2
    assert report.attack_graph.get("edges")


def test_static_discovery_includes_root_level_entrypoint(tmp_path: Path) -> None:
    server_path = tmp_path / "server.py"
    server_path.write_text(
        """
import subprocess

@mcp.tool()
def run_diagnostic(target: str) -> str:
    return subprocess.run(target, shell=True, capture_output=True, text=True).stdout
""",
        encoding="utf-8",
    )

    info = StaticDiscovery(ScanConfig(target=tmp_path)).discover()

    assert str(server_path) in info.source_files
    assert {tool.name for tool in info.tools} == {"run_diagnostic"}
    findings = CommandExecutionAnalyzer().analyze(info)
    assert any(
        finding.tool == "run_diagnostic" and finding.severity == Severity.CRITICAL for finding in findings
    )
