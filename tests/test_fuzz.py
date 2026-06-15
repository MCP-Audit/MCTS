"""Tests for safe read-only MCP fuzzing."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from mcts.core.config import ScanConfig
from mcts.fuzz.classifier import classify_response
from mcts.fuzz.payloads import FuzzLevel, probes_for_level
from mcts.fuzz.runner import FuzzRunner
from mcts.reporting.models import Severity


def test_safe_probes_are_read_only() -> None:
    probes = probes_for_level(FuzzLevel.SAFE)
    assert probes
    assert all(probe.read_only for probe in probes)
    assert not any(probe.followups and not probe.read_only for probe in probes)


def test_aggressive_includes_tool_call_probes() -> None:
    probes = probes_for_level(FuzzLevel.AGGRESSIVE, ("read_file",))
    assert any(not probe.read_only for probe in probes)


def test_classifier_detects_stack_trace() -> None:
    probe = probes_for_level(FuzzLevel.SAFE)[0]
    classified = classify_response(
        probe,
        'Traceback (most recent call last):\n  File "server.py", line 1',
        process_exited=False,
    )
    assert classified is not None
    assert classified.signal.value == "stack_trace"
    assert classified.severity == Severity.HIGH


def test_classifier_ignores_clean_error() -> None:
    probe = probes_for_level(FuzzLevel.SAFE)[1]
    classified = classify_response(
        probe,
        '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}',
        process_exited=False,
    )
    assert classified is None


@pytest.mark.asyncio
async def test_fuzz_runner_collects_findings() -> None:
    config = ScanConfig(
        target=__import__("pathlib").Path("examples/live-mcp-server/server.py"),
        live_consent=True,
        fuzz_level="safe",
    )
    runner = FuzzRunner(config)

    async def fake_probe(*_args, **_kwargs):
        return "Traceback (most recent call last)", False

    with patch("mcts.fuzz.runner.run_probe_messages", new=AsyncMock(side_effect=fake_probe)):
        result = await runner.run_async()

    assert result.probes_run >= 5
    assert result.findings
    assert result.findings[0].analyzer == "fuzz"
    assert result.findings[0].technique_id == "MCTS-T-1009"


def test_aggressive_requires_fuzz_consent() -> None:
    config = ScanConfig(
        target=__import__("pathlib").Path("examples/live-mcp-server/server.py"),
        live_consent=True,
        fuzz_level="aggressive",
        fuzz_consent=False,
    )
    with pytest.raises(ValueError, match="Aggressive fuzz"):
        FuzzRunner(config).run()


def test_fuzz_finding_emits_bronze_facts() -> None:
    from mcts.fuzz.classifier import ClassifiedResponse, ResponseSignal, finding_from_classification
    from mcts.fuzz.payloads import FuzzLevel, FuzzProbe

    probe = FuzzProbe(
        id="malformed-json",
        title="Malformed JSON",
        messages=({"jsonrpc": "2.0"},),
        level=FuzzLevel.SAFE,
    )
    classified = ClassifiedResponse(
        signal=ResponseSignal.STACK_TRACE,
        severity=Severity.HIGH,
        summary="Stack trace leaked",
    )
    finding = finding_from_classification(probe, classified)
    facts = (finding.evidence or {}).get("facts")
    assert isinstance(facts, list) and len(facts) >= 1
    assert finding.rule_stability == "mature"


def test_fuzz_finding_includes_response_excerpt_at_build() -> None:
    from mcts.fuzz.classifier import ClassifiedResponse, ResponseSignal, finding_from_classification
    from mcts.fuzz.payloads import FuzzLevel, FuzzProbe

    probe = FuzzProbe(
        id="malformed-json",
        title="Malformed JSON",
        messages=({"jsonrpc": "2.0"},),
        level=FuzzLevel.SAFE,
    )
    classified = ClassifiedResponse(
        signal=ResponseSignal.STACK_TRACE,
        severity=Severity.HIGH,
        summary="Stack trace leaked",
    )
    finding = finding_from_classification(
        probe,
        classified,
        response_excerpt="Traceback (most recent call last)",
        transport="http",
        remote_url="https://example.test/mcp",
    )
    assert finding.evidence.get("response_excerpt") == "Traceback (most recent call last)"
    assert finding.evidence.get("transport") == "http"
