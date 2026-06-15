"""Combined scan + governance gate collection."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.gate_violations import collect_gate_violations

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_collect_gate_violations_includes_policy_allowlist(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("allowed_servers:\n  - demo-only\n", encoding="utf-8")
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        governance_policy=policy_path,
    )
    violations = collect_gate_violations(report, config)
    assert any("allowlist" in item for item in violations)


def test_collect_gate_violations_includes_policy_blocklist(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    target = str(SINGLE_TOOL)
    policy_path.write_text(f"blocked_servers:\n  - {target}\n", encoding="utf-8")
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        governance_policy=policy_path,
    )
    violations = collect_gate_violations(report, config)
    assert any("blocked server" in item for item in violations)


def test_collect_gate_violations_allowlist_matches_server_name(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    server_name = report.server.name
    assert server_name
    policy_path.write_text(f"allowed_servers:\n  - {server_name}\n", encoding="utf-8")
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        governance_policy=policy_path,
    )
    violations = collect_gate_violations(report, config)
    assert not any("allowlist" in item for item in violations)


def test_collect_gate_violations_auth_env_when_llm_enabled_without_key(monkeypatch) -> None:
    monkeypatch.delenv("MCTS_LLM_API_KEY", raising=False)
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        enable_llm_judge=True,
        require_auth_env_for_sensitive=True,
    )
    violations = collect_gate_violations(report, config)
    assert any("require_auth_env_for_sensitive" in item for item in violations)


def test_collect_gate_violations_auth_env_passes_with_key(monkeypatch) -> None:
    monkeypatch.setenv("MCTS_LLM_API_KEY", "test-key")
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    config = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        enable_llm_judge=True,
        require_auth_env_for_sensitive=True,
    )
    violations = collect_gate_violations(report, config)
    assert not any("require_auth_env_for_sensitive" in item for item in violations)
