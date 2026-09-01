"""Tests for source-aware analyzers."""

import json
from pathlib import Path

import pytest

from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.core.config import ScanConfig
from mcts.discovery.static import StaticDiscovery
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Severity


def test_command_execution_detects_subprocess(example_server_path: Path) -> None:
    config = ScanConfig(target=example_server_path)
    server = StaticDiscovery(config).discover()
    findings = CommandExecutionAnalyzer().analyze(server)

    assert any(f.tool == "run_shell" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any(f.technique_id == "MCTS-T-1003" for f in findings)


def test_data_leakage_scans_source_files(example_server_path: Path) -> None:
    from mcts.core.scanner import Scanner

    report = Scanner(ScanConfig(target=example_server_path)).run()
    source_findings = [f for f in report.findings if f.analyzer == "data_leakage" and f.location]
    assert source_findings or any(f.analyzer == "data_leakage" for f in report.findings)


def test_data_leakage_ignores_loopback_urls_in_log_messages() -> None:
    server = MCPServerInfo(
        name="perseus",
        source_files={
            "mcp.py": "\n".join(
                [
                    "print(f'Perseus MCP SSE server listening on http://127.0.0.1:{port}')",
                    "print(f' SSE endpoint: http://127.0.0.1:{port}/sse')",
                    "logger.info('Server card: http://localhost:9000/.well-known/mcp/server-card.json')",
                    "callback_url = 'http://127.0.0.1:9000/message'",
                ]
            )
        },
    )

    findings = DataLeakageAnalyzer().analyze(server)

    assert len(findings) == 1
    assert findings[0].location
    assert findings[0].location.line == 4


@pytest.mark.parametrize(
    ("source", "secret"),
    [
        ("ANTHROPIC_API_KEY='sk-ant-" + "a" * 30 + "'", "sk-ant-" + "a" * 30),
        ("token = 'hf_" + "b" * 30 + "'", "hf_" + "b" * 30),
        ('{"apiKey": "super-secret-value"}', "super-secret-value"),
        ("DB_PASSWORD: database-password", "database-password"),
        ("refreshToken: refresh-value-123", "refresh-value-123"),
        ("Authorization: Bearer bearer-value-12345", "bearer-value-12345"),
        ("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"),
    ],
)
def test_data_leakage_detects_and_redacts_common_secret_formats(source: str, secret: str) -> None:
    server = MCPServerInfo(name="secret-fixture", source_files={"config.txt": source})

    findings = DataLeakageAnalyzer().analyze(server)

    assert findings
    evidence = json.dumps([finding.evidence for finding in findings])
    assert secret not in evidence
    assert "[REDACTED]" in evidence


def test_data_leakage_redacts_multiple_secrets_from_the_same_line() -> None:
    anthropic_key = "sk-ant-" + "a" * 30
    huggingface_token = "hf_" + "b" * 30
    server = MCPServerInfo(
        name="two-secrets",
        source_files={"config.txt": f"primary={anthropic_key} backup={huggingface_token}"},
    )

    findings = DataLeakageAnalyzer().analyze(server)

    evidence = json.dumps([finding.evidence for finding in findings])
    assert anthropic_key not in evidence
    assert huggingface_token not in evidence


@pytest.mark.parametrize(
    "source",
    [
        'api_key = "YOUR_API_KEY"',
        'token = "REPLACE_WITH_TOKEN"',
        'password = "INSERT_KEY_HERE"',
    ],
)
def test_data_leakage_ignores_explicit_template_secrets(source: str) -> None:
    server = MCPServerInfo(name="template-fixture", source_files={"server.py": source})

    assert DataLeakageAnalyzer().analyze(server) == []


def test_data_leakage_does_not_hide_secret_near_template_comment() -> None:
    secret = "real-secret-value"
    server = MCPServerInfo(
        name="secret-with-guidance",
        source_files={"server.py": f'api_key = "{secret}"  # replace with YOUR_API_KEY'},
    )

    findings = DataLeakageAnalyzer().analyze(server)

    assert findings
    assert secret not in json.dumps([finding.evidence for finding in findings])


def test_docker_dedupe_dockerfile_and_containerfile(tmp_path: Path) -> None:
    """Dockerfile + Containerfile with same FROM → only 1 HIGH finding."""
    from mcts.analyzers.supply_chain import SupplyChainAnalyzer

    (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
    (tmp_path / "Containerfile").write_text("FROM python:latest\n")
    findings = SupplyChainAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    docker_highs = [f for f in findings if "Docker base" in f.title]
    assert len(docker_highs) == 1


def test_docker_dedupe_same_file_not_scanned_twice(tmp_path: Path) -> None:
    """Same Dockerfile must not produce duplicate findings."""
    from mcts.analyzers.supply_chain import SupplyChainAnalyzer

    (tmp_path / "Dockerfile").write_text("FROM python:latest\n")
    findings = SupplyChainAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    docker_highs = [f for f in findings if "Docker base" in f.title]
    assert len(docker_highs) == 1


def test_docker_dedupe_multistage_same_image(tmp_path: Path) -> None:
    """Multi-stage build with same FROM → only 1 HIGH finding."""
    from mcts.analyzers.supply_chain import SupplyChainAnalyzer

    (tmp_path / "Dockerfile").write_text("FROM node:latest AS builder\nFROM node:latest AS runtime\n")
    findings = SupplyChainAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    docker_highs = [f for f in findings if "Docker base" in f.title]
    assert len(docker_highs) == 1


def test_docker_digest_pinned_not_flagged(tmp_path: Path) -> None:
    """Digest-pinned images must never be flagged."""
    from mcts.analyzers.supply_chain import SupplyChainAnalyzer

    (tmp_path / "Dockerfile").write_text("FROM python:3.11@sha256:abcdef1234567890\n")
    findings = SupplyChainAnalyzer(tmp_path).analyze(MCPServerInfo(name="x"))
    docker_highs = [f for f in findings if "Docker base" in f.title]
    assert len(docker_highs) == 0
