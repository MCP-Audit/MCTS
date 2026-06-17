"""Scanner integration for attack graph v3."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo, MCPTool

MONOREPO_MINI = Path("tests/fixtures/monorepo-mini")
REGRESSION = Path("tests/fixtures/regression")

MVP_TEMPLATE_FIXTURES = {
    "R-01-net-fetch": "SSRF_EXFIL",
    "R-06-transport-everything": "HTTP_TAKEOVER",
    "R-11-memory-readme": "MEMORY_POISON",
    "R-19-memory-poison": "MEMORY_POISON",
}

PHASE_3B_TEMPLATE_FIXTURES = {
    "R-15-gzip-resource": "SSRF_RESOURCE",
    "R-02-dual-fetch": "PROMPT_BYPASS",
    "R-04-git-scoping": "GIT_UNSCOPED",
    "R-05-git-log": "GIT_UNSCOPED",
    "R-20-git-readme": "GIT_UNSCOPED",
    "R-09-toctou-test": "TOCTOU_READ",
    "R-10-symlink-listing": "TOCTOU_READ",
    "R-07-get-env": "ENV_SAMPLING",
    "R-23-elicitation-phish": "ELICIT_PHISH",
    "R-24-read-exec": "READ_EXEC",
    "R-25-cred-theft": "CRED_THEFT",
}


def test_scanner_emits_v3_attack_graph(tmp_path: Path) -> None:
    server_py = tmp_path / "server.py"
    content = "import httpx\nasync def fetch(url):\n    return httpx.get(url, follow_redirects=True)\n"
    server_py.write_text(content, encoding="utf-8")
    config = ScanConfig(target=tmp_path, attack_graph_version=3)
    scanner = Scanner(config)
    server = MCPServerInfo(
        name="fetch",
        source_files={"server.py": content},
        tools=[MCPTool(name="fetch", description="fetch", handler_snippet=content)],
    )
    report = scanner.analyze_server(server)
    assert report.attack_graph.get("version") == 3
    assert report.attack_graph.get("edges")


def test_v3_config_enables_graph_builder() -> None:
    config = ScanConfig(target=".")
    assert config.attack_graph_version == 3


@pytest.mark.parametrize(("fixture_id", "template_id"), MVP_TEMPLATE_FIXTURES.items())
def test_mvp_template_matches_regression_fixture(fixture_id: str, template_id: str) -> None:
    spec = json.loads((REGRESSION / fixture_id / "expected.json").read_text(encoding="utf-8"))
    target = MONOREPO_MINI / spec["servers_path"]
    config = ScanConfig(
        target=str(target),
        surface_depth="full",
        attack_graph_version=3,
    )
    report = Scanner(config).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert template_id in matched


@pytest.mark.parametrize(("fixture_id", "template_id"), PHASE_3B_TEMPLATE_FIXTURES.items())
def test_phase_3b_template_matches_regression_fixture(fixture_id: str, template_id: str) -> None:
    spec = json.loads((REGRESSION / fixture_id / "expected.json").read_text(encoding="utf-8"))
    target = MONOREPO_MINI / spec["servers_path"]
    config = ScanConfig(
        target=str(target),
        surface_depth="full",
        attack_graph_version=3,
    )
    report = Scanner(config).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert template_id in matched
