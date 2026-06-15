"""Tests for governance policy evaluation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from mcts.cli.main import app
from mcts.core.config import ScanConfig
from mcts.governance import evaluate_policy, load_policy, merge_scan_config_with_policy
from mcts.governance.gate_violations import collect_gate_violations
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.output.analysis_dir import ANALYSIS_DIR_NAME
from mcts.reporting.models import Finding, RiskScore, ScanSummary, ScoreBasis, Severity, SourceLocation
from mcts.scoring.models import RiskScoreV2, ScoreV2Basis


def _score_v2(**kwargs) -> RiskScoreV2:
    defaults = {
        "absolute_risk": 400,
        "security_score": 40,
        "risk_level": "critical",
        "legacy_overall": 90,
        "basis": ScoreV2Basis(scorable_count=1, excluded_non_scorable=0),
    }
    defaults.update(kwargs)
    return RiskScoreV2(**defaults)


def _risk_score(**kwargs) -> RiskScore:
    defaults = {
        "overall": 90,
        "risk_index": 0,
        "raw_risk": 0,
        "penalty": 0,
        "basis": ScoreBasis(
            critical=0,
            high=0,
            medium=0,
            low=0,
            scorable_total=0,
            excluded_non_scorable=0,
        ),
    }
    defaults.update(kwargs)
    return RiskScore(**defaults)


runner = CliRunner()


def test_load_and_evaluate_policy(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "min_score: 80\nmax_critical: 0\nallowed_servers:\n  - cursor/demo\nblocked_servers: []\n"
    )
    policy = load_policy(policy_path)
    assert policy is not None
    violations = evaluate_policy(policy=policy, servers=["cursor/other"])
    assert any("allowlist" in item for item in violations)
    assert not any("score" in item for item in violations)


def test_scan_gate_violations_v2_limits() -> None:
    report = SimpleNamespace(
        score=_risk_score(),
        score_v2=_score_v2(absolute_risk=400, security_score=40, risk_level="critical"),
        findings=[],
        summary=ScanSummary(),
    )
    config = ScanConfig(target=Path("."), min_security_score=50, max_absolute_risk=300, scoring_mode="both")
    violations = evaluate_scan_gate_violations(report, config)
    assert any("absolute_risk" in item for item in violations)
    assert any("security_score" in item for item in violations)


def test_scan_gate_violations_min_category_score_v2() -> None:
    findings = [
        Finding(
            id="inj-1",
            analyzer="prompt_injection",
            title="Injection",
            description="d",
            severity=Severity.CRITICAL,
            recommendation="fix",
            location=SourceLocation(file="x.py"),
        )
    ]
    report = SimpleNamespace(
        score=_risk_score(),
        score_v2=_score_v2(absolute_risk=500, security_score=10, risk_level="critical"),
        findings=findings,
        summary=ScanSummary(),
    )
    config = ScanConfig(
        target=Path("."),
        min_category_score_v2={"injection": 80},
        scoring_mode="both",
    )
    violations = evaluate_scan_gate_violations(report, config)
    assert any("v2 category score" in item for item in violations)


def test_scan_gate_violations_max_risk_level() -> None:
    report = SimpleNamespace(
        score=_risk_score(),
        score_v2=_score_v2(absolute_risk=300, security_score=50, risk_level="high"),
        findings=[],
        summary=ScanSummary(),
    )
    config = ScanConfig(target=Path("."), max_risk_level="medium", scoring_mode="both")
    violations = evaluate_scan_gate_violations(report, config)
    assert any("risk_level" in item for item in violations)


def test_scan_missing_policy_fails_before_reports(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "server.py"
    target.write_text("print('not an mcp server')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(target), "--policy", str(tmp_path / "missing.yaml"), "--no-progress"],
    )

    assert result.exit_code == 2
    assert "Governance policy not found" in result.stdout
    assert not (tmp_path / ANALYSIS_DIR_NAME).exists()


def test_scan_invalid_policy_fails_before_reports(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "server.py"
    target.write_text("print('not an mcp server')\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text("- not-a-mapping\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(target), "--policy", str(policy), "--no-progress"])

    assert result.exit_code == 2
    assert "Governance policy must be a YAML mapping" in result.stdout
    assert not (tmp_path / ANALYSIS_DIR_NAME).exists()


def test_collect_gate_violations_no_duplicate_min_score(tmp_path: Path) -> None:
    from mcts.core.scanner import Scanner

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("min_score: 80\n", encoding="utf-8")
    target = Path("examples/single-tool-agent-server/server.py")
    policy = load_policy(policy_path)
    assert policy is not None
    config = merge_scan_config_with_policy(
        ScanConfig(target=target, governance_policy=policy_path),
        policy,
    )
    report = Scanner(ScanConfig(target=target)).run()
    violations = collect_gate_violations(report, config)
    min_score_msgs = [item for item in violations if "legacy overall score" in item]
    assert len(min_score_msgs) == 1
