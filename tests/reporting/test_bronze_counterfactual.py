"""Bronze counterfactual enrichment for analyzer findings."""

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner


def test_bronze_facts_get_counterfactual_under_trust() -> None:
    report = Scanner(
        ScanConfig(target="examples/vulnerable-mcp-server/server.py", findings_trust_mode="enforce")
    ).run()
    perm = next(f for f in report.findings if f.analyzer == "permission_analyzer")
    ev = perm.evidence or {}
    assert isinstance(ev.get("facts"), list) and ev["facts"]
    assert isinstance(ev.get("counterfactual_remediation"), dict)
    assert ev.get("confidence_factors")
