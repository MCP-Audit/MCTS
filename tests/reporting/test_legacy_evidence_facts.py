"""Legacy evidence → bronze facts synthesis (R17)."""

from mcts.reporting.evidence_provenance import enrich_provenance
from mcts.reporting.finding_validator import ValidationContext
from mcts.reporting.models import Finding, Severity, SourceLocation


def test_legacy_evidence_synthesizes_facts_and_counterfactual() -> None:
    finding = Finding(
        id="perm-1",
        analyzer="permission_analyzer",
        severity=Severity.HIGH,
        title="Over permissioned",
        description="d",
        recommendation="fix",
        tool="run_shell",
        location=SourceLocation(file="server.py", line=12),
        evidence={"rule_id": "RULE_PERM", "match": "shell", "field": "tool_name"},
    )
    ctx = ValidationContext(mode="enforce", scan_scope="repository", tools=[], attack_graph={})
    enriched = enrich_provenance([finding], ctx)[0]
    ev = enriched.evidence or {}
    assert isinstance(ev.get("facts"), list) and ev["facts"]
    assert ev["facts"][0]["rule_id"] == "RULE_PERM"
    assert ev.get("counterfactual_remediation")
    assert ev.get("confidence_factors")


def test_skip_finding_not_enriched_with_legacy_facts() -> None:
    finding = Finding(
        id="skip-1",
        analyzer="embedding_secrets",
        severity=Severity.LOW,
        title="skipped",
        description="d",
        recommendation="r",
        evidence={"skipped": True, "reason": "model unavailable"},
    )
    ctx = ValidationContext(mode="enforce", scan_scope="repository", tools=[], attack_graph={})
    enriched = enrich_provenance([finding], ctx)[0]
    assert not (enriched.evidence or {}).get("facts")
