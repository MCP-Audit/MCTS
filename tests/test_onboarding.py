"""Tests for MCP discovery onboarding helpers."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.discovery.onboarding import (
    find_entrypoint_candidates,
    find_mcp_configs,
    format_discovery_hints,
    list_servers,
)


def test_discovery_finds_mcp_json(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "python", "args": []}}}))
    found = find_mcp_configs(tmp_path)
    assert config in found


def test_discovery_lists_servers(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"alpha": {"command": "uv"}, "beta": {"command": "python"}}}))
    assert list_servers(config) == ["alpha", "beta"]


def test_entrypoint_candidates_skips_tests_dir(tmp_path: Path) -> None:
    server = tmp_path / "ifd" / "mcp" / "bridge.py"
    server.parent.mkdir(parents=True)
    server.write_text("from mcp.server import Server\n@tool\ndef x(): pass\n")
    tests = tmp_path / "tests" / "test_bridge.py"
    tests.parent.mkdir(parents=True)
    tests.write_text("from mcp.server import Server\n@tool\ndef y(): pass\n")
    candidates = find_entrypoint_candidates(tmp_path)
    assert server in candidates
    assert tests not in candidates


def test_entrypoint_candidates_include_module_and_script_from_mcp_config(tmp_path: Path) -> None:
    bridge = tmp_path / "ifd_backend" / "bridge.py"
    bridge.parent.mkdir()
    bridge.write_text("def main(): pass\n")
    script = tmp_path / "tools" / "server.py"
    script.parent.mkdir()
    script.write_text("def main(): pass\n")
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bridge": {"command": "python", "args": ["-m", "ifd_backend.bridge"]},
                    "script": {"command": "python", "args": ["tools/server.py"]},
                }
            }
        )
    )

    candidates = find_entrypoint_candidates(tmp_path)

    assert bridge in candidates
    assert script in candidates


def test_format_discovery_hints_includes_config(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"local": {"command": "python"}}}))
    hints = format_discovery_hints(tmp_path)
    assert ".mcp.json" in hints
    assert "local" in hints
