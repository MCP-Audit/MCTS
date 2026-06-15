"""Bronze facts on hygiene/readiness meta findings."""

from mcts.readiness.heuristics import _finding
from mcts.reporting.models import Severity


def test_readiness_heuristic_emits_bronze_facts() -> None:
    row = _finding("demo_tool", "HEUR-001", "Missing timeout configuration", Severity.HIGH)
    facts = (row.evidence or {}).get("facts")
    assert isinstance(facts, list) and facts
    assert facts[0]["rule_id"] == "HEUR-001"
    assert row.evidence.get("evidence_tier") == "bronze"
