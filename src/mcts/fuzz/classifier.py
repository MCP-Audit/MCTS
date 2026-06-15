"""Classify fuzz probe responses."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.fuzz.payloads import FuzzProbe
from mcts.reporting.models import Severity

STACK_TRACE = re.compile(r"(Traceback \(most recent call last\)|Exception:|Error:|panic:)", re.I)
PATH_ECHO = re.compile(r"(/etc/passwd|/etc/hosts|\.\./\.\./|file://)", re.I)
SECRET_ECHO = re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})", re.I)


class ResponseSignal(StrEnum):
    STACK_TRACE = "stack_trace"
    PATH_ECHO = "path_echo"
    SECRET_ECHO = "secret_echo"
    DANGEROUS_SUCCESS = "dangerous_success"
    SERVER_ERROR = "server_error"
    NO_RESPONSE = "no_response"
    CLEAN_REJECTION = "clean_rejection"


@dataclass(frozen=True)
class ClassifiedResponse:
    signal: ResponseSignal
    severity: Severity
    summary: str


def classify_response(
    probe: FuzzProbe, response_text: str, *, process_exited: bool
) -> ClassifiedResponse | None:
    """Return a classification when the response indicates a security issue."""
    if process_exited and probe.requires_valid_init:
        return ClassifiedResponse(
            signal=ResponseSignal.SERVER_ERROR,
            severity=Severity.HIGH,
            summary="Server subprocess exited during fuzz probe",
        )

    if not response_text.strip():
        if probe.id in ("malformed-json", "missing-method", "bad-init-version"):
            return None
        return ClassifiedResponse(
            signal=ResponseSignal.NO_RESPONSE,
            severity=Severity.MEDIUM,
            summary="No response body received for fuzz probe",
        )

    if STACK_TRACE.search(response_text):
        return ClassifiedResponse(
            signal=ResponseSignal.STACK_TRACE,
            severity=Severity.HIGH,
            summary="Stack trace or internal error leaked in response",
        )

    if SECRET_ECHO.search(response_text):
        return ClassifiedResponse(
            signal=ResponseSignal.SECRET_ECHO,
            severity=Severity.CRITICAL,
            summary="Sensitive material echoed in fuzz response",
        )

    if PATH_ECHO.search(response_text) and probe.id != "resources-read-traversal":
        return ClassifiedResponse(
            signal=ResponseSignal.PATH_ECHO,
            severity=Severity.HIGH,
            summary="Filesystem path echoed in fuzz response",
        )

    if (
        probe.read_only is False
        and '"error"' not in response_text.lower()
        and "result" in response_text.lower()
        and probe.level.value == "aggressive"
    ):
        return ClassifiedResponse(
            signal=ResponseSignal.DANGEROUS_SUCCESS,
            severity=Severity.CRITICAL,
            summary="Potentially dangerous tools/call probe succeeded without error",
        )

    if (
        probe.id == "resources-read-traversal"
        and "result" in response_text.lower()
        and (PATH_ECHO.search(response_text) or "root:" in response_text)
    ):
        return ClassifiedResponse(
            signal=ResponseSignal.DANGEROUS_SUCCESS,
            severity=Severity.CRITICAL,
            summary="resources/read may have returned sensitive filesystem content",
        )

    if (
        probe.id.startswith("sampling-")
        and '"error"' not in response_text.lower()
        and ("result" in response_text.lower() or "content" in response_text.lower())
    ):
        return ClassifiedResponse(
            signal=ResponseSignal.DANGEROUS_SUCCESS,
            severity=Severity.HIGH if probe.id != "sampling-burst" else Severity.CRITICAL,
            summary="Server accepted sampling/createMessage probe without rejection",
        )

    return None


def finding_from_classification(
    probe: FuzzProbe,
    classified: ClassifiedResponse,
    *,
    response_excerpt: str | None = None,
    transport: str | None = None,
    remote_url: str | None = None,
):
    technique_id = "MCTS-T-1016" if probe.id.startswith("sampling-") else "MCTS-T-1009"
    extra: dict = {
        "probe_id": probe.id,
        "signal": classified.signal.value,
        "read_only": probe.read_only,
        "level": probe.level.value,
        "attack_tags": (["attack.execution", "attack.t1499.003"] if probe.id.startswith("sampling-") else []),
    }
    if response_excerpt:
        extra["response_excerpt"] = response_excerpt
    if transport:
        extra["transport"] = transport
    if remote_url:
        extra["remote_url"] = remote_url
    return build_analyzer_finding(
        finding_id=f"fuzz-{probe.id}-{classified.signal.value}",
        analyzer="fuzz",
        title=f"Fuzz probe issue: {probe.title}",
        description=classified.summary,
        severity=classified.severity,
        recommendation=_recommendation(classified.signal, probe),
        rule_id=f"RULE_FUZZ_{classified.signal.value.upper()}",
        match=classified.signal.value,
        field="fuzz_response",
        technique_id=technique_id,
        confidence=0.75 if classified.signal == ResponseSignal.CLEAN_REJECTION else 0.85,
        extra_evidence=extra,
    )


def _recommendation(signal: ResponseSignal, probe: FuzzProbe) -> str:
    if probe.id.startswith("sampling-"):
        return (
            "Require explicit approval for sampling/createMessage; cap token budgets "
            "and block nested tool requests in sampling flows (MCTS-T-1016)."
        )
    mapping = {
        ResponseSignal.STACK_TRACE: "Harden error handling; return generic JSON-RPC errors only.",
        ResponseSignal.PATH_ECHO: "Validate and reject traversal patterns; avoid echoing raw paths.",
        ResponseSignal.SECRET_ECHO: "Remove secrets from error paths and tool responses.",
        ResponseSignal.DANGEROUS_SUCCESS: "Reject malicious tool/resource inputs; enforce authorization.",
        ResponseSignal.SERVER_ERROR: "Improve protocol robustness; prevent crashes on malformed input.",
        ResponseSignal.NO_RESPONSE: "Ensure the server handles malformed input without hanging.",
        ResponseSignal.CLEAN_REJECTION: "No action required.",
    }
    return mapping.get(signal, "Review MCP server input validation.")
