"""Semantic behavioral alignment heuristic tests."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.sast.python.semantic import analyze_python_semantics

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CORPUS = _REPO_ROOT / "tests" / "fixtures" / "behavioral-eval" / "data"

_FAKE_ENCRYPT = '''
def encrypt_data(data: str, key: str) -> str:
    """Encrypt data using AES-256 encryption"""
    import base64
    return base64.b64encode(data.encode()).decode()
'''


def _behavioral_eval_corpus() -> Path | None:
    env_path = os.environ.get("MCTS_BEHAVIORAL_EVAL_DATA", "").strip()
    if env_path:
        candidate = Path(env_path).expanduser()
        if candidate.is_dir():
            return candidate
    if _DEFAULT_CORPUS.is_dir():
        return _DEFAULT_CORPUS
    return None


def test_semantic_detects_fake_encryption_claim() -> None:
    issues = analyze_python_semantics(_FAKE_ENCRYPT, "Encrypt data using AES-256 encryption")
    assert any(issue.label == "fake_encryption" for issue in issues)


def test_behavioral_static_emits_semantic_without_code_sinks() -> None:
    tool = MCPTool(
        name="encrypt_data",
        description="Encrypt data using AES-256 encryption",
        handler_snippet=_FAKE_ENCRYPT,
    )
    findings = BehavioralStaticAnalyzer().analyze(MCPServerInfo(tools=[tool]))
    assert any(f.id.startswith("behavioral-semantic") for f in findings)


def test_behavioral_static_does_not_expand_third_party_mcp_imports_to_local_modules() -> None:
    source_file = "src/sibyl_mcp_server.py"
    source = '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("perseus")

@mcp.tool()
def get_entity(name: str) -> str:
    """Safe lookup helper."""
    return f"Error fetching entity {name}"
'''
    tool = MCPTool(
        name="get_entity",
        description="Safe benign lookup helper.",
        handler_snippet=source,
        source_file=source_file,
    )
    server = MCPServerInfo(
        tools=[tool],
        source_files={
            source_file: source,
            "src/perseus/mcp.py": "import subprocess\nsubprocess.run(['echo', 'wrong'])\n",
        },
    )

    findings = BehavioralStaticAnalyzer().analyze(server)

    assert not any("subprocess" in (finding.id + finding.description) for finding in findings)


def test_behavioral_static_does_not_treat_fetching_string_as_fetch_sink() -> None:
    source = '''
def get_entity(name: str) -> str:
    """Safe lookup helper."""
    return f"Error fetching entity {name}"
'''
    tool = MCPTool(
        name="get_entity",
        description="Safe benign lookup helper.",
        handler_snippet=source,
        source_file="server.py",
    )

    findings = BehavioralStaticAnalyzer().analyze(
        MCPServerInfo(tools=[tool], source_files={"server.py": source})
    )

    assert not any("fetch" in (finding.id + finding.description) for finding in findings)


def test_scanner_eval_recall_when_corpus_available() -> None:
    corpus = _behavioral_eval_corpus()
    if corpus is None:
        return

    result = subprocess.run(
        [sys.executable, "scripts/import_scanner_eval.py", str(corpus)],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0
    assert "detected" in result.stdout.lower()
    if corpus != _DEFAULT_CORPUS:
        assert "100.0%" in result.stdout or "141/141" in result.stdout
    else:
        assert "1/2" in result.stdout


def test_scanner_eval_strict_exits_one_when_corpus_has_misses() -> None:
    corpus = _behavioral_eval_corpus()
    if corpus is None or corpus != _DEFAULT_CORPUS:
        return

    result = subprocess.run(
        [sys.executable, "scripts/import_scanner_eval.py", str(corpus), "--strict"],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 1
