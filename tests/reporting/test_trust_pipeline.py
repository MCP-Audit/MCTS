"""Shared trust pipeline tests."""

from mcts.reporting.finding_validator import ValidationContext
from mcts.reporting.models import Finding, Severity
from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context


def test_apply_trust_layer_off_is_noop() -> None:
    finding = Finding(
        id="x",
        analyzer="prompt_injection",
        title="t",
        description="d",
        severity=Severity.HIGH,
        recommendation="r",
    )
    ctx = build_trust_context(mode="off")
    out = apply_trust_layer([finding], ctx)
    assert out[0].display_severity is None


def test_apply_trust_layer_enforce_sets_display_fields() -> None:
    finding = Finding(
        id="chain-credential-theft",
        analyzer="attack_chains",
        title="Credential theft chain possible",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="r",
        evidence={
            "read_tools": ["ask_sales_agent_tool"],
            "credential_tools": ["ask_sales_agent_tool"],
            "exfil_tools": ["ask_sales_agent_tool"],
        },
    )
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = apply_trust_layer([finding], ctx)[0]
    assert out.display_severity == Severity.MEDIUM
    assert out.priority_score is not None
