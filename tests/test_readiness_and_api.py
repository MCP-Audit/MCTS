"""Tests for readiness heuristics, MIME filtering, and API routes."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcts.analyzers.surface_context import scan_surfaces
from mcts.cli.main import app
from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPResource, MCPServerInfo, MCPTool, SurfaceScanOptions
from mcts.readiness.heuristics import check_tool_readiness, readiness_score
from mcts.readiness.runner import run_readiness
from mcts.sast.typescript.sinks import detect_typescript_sinks

runner = CliRunner()


def test_readiness_heur_001_missing_timeout():
    tool = MCPTool(name="fetch", description="Fetch remote data from an external API service")
    findings = check_tool_readiness(tool)
    assert any(f.evidence.get("readiness_rule") == "HEUR-001" for f in findings)


def test_readiness_heur_009_short_description():
    tool = MCPTool(name="x", description="short")
    findings = check_tool_readiness(tool)
    assert any(f.evidence.get("readiness_rule") == "HEUR-009" for f in findings)


def test_readiness_score_deductions():
    tool = MCPTool(name="x", description="short")
    findings = check_tool_readiness(tool)
    assert readiness_score(findings) < 100


def test_readiness_warns_when_opa_requested_but_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mcts.readiness.runner.Scanner", _FakeScanner)
    monkeypatch.setattr("mcts.readiness.runner.OpaProvider.is_available", lambda self: False)
    report = run_readiness(ScanConfig(target=".", readiness_opa=True))
    assert any(f.id == "readiness-opa-unavailable" for f in report.findings)


def test_readiness_warns_when_llm_requested_but_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MCTS_LLM_API_KEY", raising=False)
    monkeypatch.setattr("mcts.readiness.runner.Scanner", _FakeScanner)
    report = run_readiness(ScanConfig(target=".", readiness_llm=True))
    assert any(f.id == "readiness-llm-unavailable" for f in report.findings)


class _FakeScanner:
    def __init__(self, *_args, **_kwargs) -> None:
        self.client = self

    def discover(self) -> MCPServerInfo:
        return MCPServerInfo(
            name="demo",
            tools=[MCPTool(name="echo", description="Echo user input back to the caller safely.")],
        )


def test_readiness_fails_when_no_tools_discovered(tmp_path: Path) -> None:
    skill = tmp_path / "skills" / "deploy"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Deploy\nRun the deployment workflow.\n", encoding="utf-8")
    report = run_readiness(ScanConfig(target=tmp_path, discover_instructions=True))
    assert report.tools_checked == 0
    assert not report.production_ready
    assert any(f.id == "readiness-no-tools-discovered" for f in report.findings)


def test_readiness_passes_when_tools_discovered(tmp_path: Path) -> None:
    server_py = tmp_path / "server.py"
    server_py.write_text(
        "from mcp.server import Server\n"
        "server = Server('demo')\n"
        "@server.tool()\n"
        "def greet(name: str) -> str:\n"
        '    """Say hello to the user with a friendly greeting message."""\n'
        "    return name\n",
        encoding="utf-8",
    )
    report = run_readiness(ScanConfig(target=server_py))
    assert report.tools_checked >= 1
    assert not any(f.id == "readiness-no-tools-discovered" for f in report.findings)


def test_readiness_cli_exits_one_only_when_no_tools(tmp_path: Path) -> None:
    skill = tmp_path / "skills" / "deploy"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Deploy\nRun the deployment workflow.\n", encoding="utf-8")
    no_tools = runner.invoke(app, ["readiness", str(tmp_path)])
    assert no_tools.exit_code == 1

    server_py = tmp_path / "server.py"
    server_py.write_text(
        "from mcp.server import Server\n"
        "server = Server('demo')\n"
        "@server.tool()\n"
        "def greet(name: str) -> str:\n"
        '    """Say hello to the user with a friendly greeting message."""\n'
        "    return name\n",
        encoding="utf-8",
    )
    with_tools = runner.invoke(app, ["readiness", str(server_py)])
    assert with_tools.exit_code == 0


def test_resource_mime_allowlist_filters_surfaces():
    server = MCPServerInfo(
        resources=[
            MCPResource(uri="a", name="text", mime_type="text/plain", description="ok"),
            MCPResource(uri="b", name="img", mime_type="image/png", description="binary"),
        ],
        surface_scan=SurfaceScanOptions(
            surfaces=["resource"],
            resource_mime_allowlist=["text/plain"],
        ),
    )
    surfaces = scan_surfaces(server)
    assert len(surfaces) == 1
    assert surfaces[0].mime_type == "text/plain"


def test_typescript_sink_detection():
    source = "import { exec } from 'child_process';\nexport function run(cmd: string) { exec(cmd); }\n"
    assert "child_process" in detect_typescript_sinks(source)


def test_api_health_and_readiness_endpoints():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    response = client.post("/readiness", json={"target": "."})
    assert response.status_code == 200
    payload = response.json()
    assert "readiness_score" in payload
    assert "findings" in payload


def test_api_readiness_explicit_off_overrides_policy(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from pathlib import Path as PathType

    from fastapi.testclient import TestClient

    from mcts.api.app import _merge_policy, app
    from mcts.core.config import ScanConfig

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("findings_trust_mode: enforce\n", encoding="utf-8")
    config = _merge_policy(
        ScanConfig(
            target=PathType("."),
            findings_trust_mode="off",
            findings_trust_mode_explicit=True,
            governance_policy=policy_path,
        )
    )
    assert config.findings_trust_mode == "off"

    client = TestClient(app)
    response = client.post(
        "/readiness",
        json={
            "target": ".",
            "findings_trust_mode": "off",
            "findings_trust_mode_explicit": True,
            "governance_policy": str(policy_path),
        },
    )
    assert response.status_code == 200


def test_api_readiness_ignore_policy_skips_merge(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from pathlib import Path as PathType

    from fastapi.testclient import TestClient

    from mcts.api.app import _merge_policy, app
    from mcts.core.config import ScanConfig

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("findings_trust_mode: enforce\nmax_critical: 0\n", encoding="utf-8")
    config = _merge_policy(
        ScanConfig(
            target=PathType("."),
            ignore_policy=True,
            governance_policy=policy_path,
        )
    )
    assert config.findings_trust_mode == "off"
    assert config.max_critical is None

    client = TestClient(app)
    response = client.post(
        "/readiness",
        json={
            "target": ".",
            "ignore_policy": True,
            "governance_policy": str(policy_path),
        },
    )
    assert response.status_code == 200


def test_api_requires_key_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from mcts.api.app import app

    monkeypatch.setenv("MCTS_API_KEY", "secret-token")
    client = TestClient(app)
    denied = client.post("/scan", json={"target": "."})
    assert denied.status_code == 401
    allowed = client.post("/scan", json={"target": "."}, headers={"X-API-Key": "secret-token"})
    assert allowed.status_code == 200
