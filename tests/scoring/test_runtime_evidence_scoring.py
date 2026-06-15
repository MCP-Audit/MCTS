"""Phase 3 runtime evidence integration with v2 scoring uncertainty."""

from __future__ import annotations

from mcts.reporting.models import Finding, Severity
from mcts.reporting.runtime_evidence import validate_runtime_evidence
from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context
from mcts.scoring.uncertainty import evidence_quality_factor


def test_evidence_quality_factor_tightens_on_validated_taint_with_snippet() -> None:
    finding = Finding(
        id="behavioral-taint-demo-subprocess",
        analyzer="behavioral_static",
        title="Untrusted input may reach sink on demo",
        description="Handler parameters ['cmd'] may flow to security-sensitive calls: subprocess",
        severity=Severity.HIGH,
        recommendation="Validate inputs",
        evidence={
            "facts": [
                {
                    "rule_id": "RULE_TAINT_PARAM_SINK",
                    "match": "subprocess",
                    "field": "handler_body",
                    "tool": "demo",
                    "snippet": "subprocess.call(cmd)",
                }
            ],
            "sinks": ["subprocess"],
            "tainted_params": ["cmd"],
        },
    )
    ctx = build_trust_context(mode="enforce", scan_scope="repository")
    validated = apply_trust_layer([finding], ctx)[0]
    assert validated.finding_type == "validated"
    assert "handler_traced" in (validated.evidence or {}).get("risk_tags", [])
    assert evidence_quality_factor([validated]) == 0.8


def test_evidence_quality_factor_default_without_validated_runtime() -> None:
    finding = Finding(
        id="cmd-1",
        analyzer="command_execution",
        title="Shell",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
    )
    assert evidence_quality_factor([finding]) == 1.2


def test_validate_runtime_evidence_sets_live_probe_risk_tags() -> None:
    finding = Finding(
        id="jailbreak-live-payload-accepted",
        analyzer="jailbreak",
        title="Live jailbreak probe accepted override instructions",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
        evidence={
            "facts": [{"rule_id": "RULE_JAILBREAK_LIVE", "match": "1", "field": "runtime_events"}],
            "analysis_mode": "live_probe",
            "accepted_count": 1,
        },
    )
    out = validate_runtime_evidence([finding])[0]
    assert out.evidence.get("runtime_validation") == "live_probe"
    assert "live_probe" in out.evidence.get("risk_tags", [])
    assert evidence_quality_factor([out]) == 0.8
