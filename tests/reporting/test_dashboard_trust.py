"""Dashboard payload and executive summary with findings trust enforced."""

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.report.data import build_dashboard_payload, build_executive_summary, build_recommendations

SINGLE_TOOL = Path("examples/single-tool-agent-server/server.py")


def test_executive_summary_overlap_only_no_exfil_alarm() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    executive = build_executive_summary(report.findings, report.display_summary)
    assert any("capability overlap" in p.lower() for p in executive["paragraphs"])
    assert not any("exfiltration" in p.lower() for p in executive["paragraphs"])
    assert not any("Block credential tools" in b for b in executive["recommended"])


def test_recommendations_use_display_priority_for_overlap_chains() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    recs = build_recommendations(report.findings)
    overlap_recs = [r for r in recs if r["title"].startswith("Potential capability overlap")]
    assert overlap_recs
    assert all(r["priority"] == "P3" for r in overlap_recs)
    assert all(r["impact"] == "Medium" for r in overlap_recs)


def test_dashboard_payload_analyzer_counts_use_display_severity() -> None:
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    payload = build_dashboard_payload(report)
    attack = next(a for a in payload["analyzers"] if a["name"] == "attack_chains")
    assert attack["severity_counts"]["critical"] == 0
    assert attack["severity_counts"]["medium"] >= 2
    assert payload["display_summary"]["critical"] == 0
    chain_rows = [f for f in payload["findings"] if f["analyzer"] == "attack_chains"]
    assert all(row["severity"] == "medium" for row in chain_rows)
    assert all(row["template_severity"] == "critical" for row in chain_rows)
