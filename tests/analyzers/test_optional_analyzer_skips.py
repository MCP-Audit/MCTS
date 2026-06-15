"""Skip findings when optional analyzers cannot run."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.cloud_inspect import CloudInspectAnalyzer
from mcts.analyzers.npm_audit import NpmAuditAnalyzer
from mcts.analyzers.virustotal import VirusTotalAnalyzer
from mcts.analyzers.yara_metadata import YaraMetadataAnalyzer
from mcts.mcp.models import MCPServerInfo


def test_npm_audit_skip_when_npm_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("mcts.analyzers.npm_audit.shutil.which", lambda _: None)
    findings = NpmAuditAnalyzer(tmp_path).analyze(MCPServerInfo())
    assert len(findings) == 1
    assert findings[0].analyzer == "npm_audit"
    assert (findings[0].evidence or {}).get("skipped") is True


def test_yara_skip_when_rules_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(YaraMetadataAnalyzer, "_load_rules", lambda self: None)
    findings = YaraMetadataAnalyzer().analyze(MCPServerInfo())
    assert len(findings) == 1
    assert findings[0].id == "yara-skipped"


def test_cloud_inspect_skip_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("MCTS_CLOUD_API_KEY", raising=False)
    findings = CloudInspectAnalyzer().analyze(MCPServerInfo())
    assert len(findings) == 1
    assert findings[0].id == "cloud-inspect-skipped"


def test_llm_judge_skip_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("MCTS_LLM_API_KEY", raising=False)
    from mcts.analyzers.llm_judge import LlmJudgeAnalyzer

    findings = LlmJudgeAnalyzer().analyze(MCPServerInfo())
    assert len(findings) == 1
    assert findings[0].id == "llm-judge-skipped"


def test_virustotal_skip_without_api_key(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("MCTS_VT_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    findings = VirusTotalAnalyzer(tmp_path).analyze(MCPServerInfo())
    assert len(findings) == 1
    assert findings[0].id == "virustotal-skipped"
