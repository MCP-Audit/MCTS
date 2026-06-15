"""Live scan merges protocol fuzz findings into static scoring."""

from __future__ import annotations

from unittest.mock import patch

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.fuzz.payloads import FuzzLevel
from mcts.fuzz.runner import FuzzResult
from mcts.reporting.models import Finding, Severity


def _fuzz_finding() -> Finding:
    return Finding(
        id="fuzz-stack-1",
        analyzer="fuzz",
        severity=Severity.HIGH,
        title="Stack trace leaked",
        description="probe response contained traceback",
        recommendation="sanitize errors",
    )


@patch("mcts.fuzz.runner.FuzzRunner.run")
def test_merge_fuzz_findings_adds_rows_and_note(mock_run) -> None:
    mock_run.return_value = FuzzResult(
        findings=[_fuzz_finding()],
        probes_run=4,
        level=FuzzLevel.SAFE,
    )
    config = ScanConfig(
        target="examples/vulnerable-mcp-server/server.py",
        live=True,
        live_consent=True,
    )
    scanner = Scanner(config)
    findings: list[Finding] = []
    executed: list[str] = []
    note = scanner._merge_fuzz_findings(findings, executed)
    assert note and "merged into scan score" in note
    assert executed == ["fuzz"]
    assert len(findings) == 1
    assert findings[0].analyzer == "fuzz"


def test_static_scan_skips_fuzz_without_live() -> None:
    scanner = Scanner(ScanConfig(target="examples/vulnerable-mcp-server/server.py"))
    findings: list[Finding] = []
    note = scanner._merge_fuzz_findings(findings, [])
    assert note is None
    assert not findings
