"""Production readiness heuristics for MCP tools (non-security)."""

from __future__ import annotations

from dataclasses import dataclass

from mcts.analyzers.finding_facts import build_hygiene_finding, build_skip_finding
from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPTool
from mcts.readiness.heuristics import check_tool_readiness, readiness_score
from mcts.readiness.llm_judge import ReadinessLlmJudge
from mcts.readiness.opa import OpaProvider
from mcts.reporting.models import Finding, Severity


@dataclass
class ReadinessReport:
    target: str
    findings: list[Finding]
    tools_checked: int
    readiness_score: int
    production_ready: bool
    score_v2_note: str | None = None
    absolute_risk_snapshot: int | None = None
    security_score_snapshot: int | None = None


def run_readiness(config: ScanConfig) -> ReadinessReport:
    server = Scanner(config).client.discover()
    opa = OpaProvider(policies_dir=config.readiness_opa_policies) if config.readiness_opa else None
    llm = ReadinessLlmJudge(model=config.readiness_llm_model) if config.readiness_llm else None
    findings: list[Finding] = []

    if config.readiness_opa and (opa is None or not opa.is_available()):
        findings.append(
            build_skip_finding(
                finding_id="readiness-opa-unavailable",
                analyzer="readiness",
                title="OPA readiness checks skipped",
                description=_opa_unavailable_reason(opa),
                recommendation=(
                    "Install the opa CLI on PATH or omit --opa when policy checks are not required."
                ),
            )
        )
    if config.readiness_llm and (llm is None or not llm.is_available()):
        findings.append(
            build_skip_finding(
                finding_id="readiness-llm-unavailable",
                analyzer="readiness",
                title="LLM readiness judge skipped",
                description=_llm_unavailable_reason(),
                recommendation=(
                    "Set MCTS_LLM_API_KEY and install litellm (`uv sync --extra llm`), or omit --llm-judge."
                ),
            )
        )

    for tool in server.tools:
        tool_def = _tool_def(tool)
        findings.extend(check_tool_readiness(tool))
        if opa and opa.is_available():
            findings.extend(opa.evaluate_tool(tool_def, tool.name))
        if llm and llm.is_available():
            findings.extend(llm.analyze_tool(tool_def, tool.name))

    if not server.tools:
        findings.append(
            build_hygiene_finding(
                finding_id="readiness-no-tools-discovered",
                analyzer="readiness",
                title="No MCP tools discovered",
                description=(
                    "Readiness checks apply to MCP tools, but discovery found zero tools. "
                    "Agent repos with only SKILL.md or prompt markdown need a discoverable MCP "
                    "entrypoint, or use live/snapshot discovery before running readiness."
                ),
                severity=Severity.HIGH,
                recommendation=(
                    "Point readiness at an MCP server entrypoint, run static discovery on tool "
                    "sources, or export tools via mcts snapshot for offline scans."
                ),
                rule_id="HEUR-000",
                match="no tools discovered",
                field="discovery",
                confidence=0.9,
                extra_evidence={"readiness_rule": "HEUR-000", "tools_discovered": 0},
            )
        )

    if not server.version or server.version == "0.0.0":
        findings.append(
            build_hygiene_finding(
                finding_id="readiness-server-version",
                analyzer="readiness",
                title="Server version not specified",
                description="MCP server does not expose a meaningful version string.",
                severity=Severity.LOW,
                recommendation="Set server version for operational traceability.",
                rule_id="HEUR-014",
                match="missing server version",
                field="server_metadata",
                confidence=0.6,
                extra_evidence={"readiness_rule": "HEUR-014"},
            )
        )

    from mcts.reporting.display import effective_severity
    from mcts.reporting.trust_apply import apply_config_trust_layer

    findings = apply_config_trust_layer(findings, config, scan_scope="readiness", tools=server.tools)
    use_display = config.findings_trust_mode != "off"
    score = readiness_score(findings, use_display=use_display)
    production_ready = (
        bool(server.tools)
        and score >= 70
        and not any(
            (effective_severity(f) if use_display else f.severity) == Severity.CRITICAL for f in findings
        )
    )
    for finding in findings:
        finding.evidence.setdefault("readiness_score", score)
        finding.evidence.setdefault("production_ready", production_ready)

    score_v2_note = None
    absolute_risk_snapshot = None
    security_score_snapshot = None
    if config.scoring_mode in ("v2", "both"):
        score_v2_note = (
            "Readiness readiness_score is separate from mcts scan v2 absolute_risk. "
            "absolute_risk_snapshot scores readiness findings only (not a full scan)."
        )
        from mcts.governance.gate_violations import build_gate_scan_report

        gate_report = build_gate_scan_report(
            findings,
            config,
            target=str(config.target),
            scan_scope="readiness",
        )
        if gate_report.score_v2 is not None:
            absolute_risk_snapshot = gate_report.score_v2.absolute_risk
            security_score_snapshot = gate_report.score_v2.security_score

    return ReadinessReport(
        target=str(config.target),
        findings=findings,
        tools_checked=len(server.tools),
        readiness_score=score,
        production_ready=production_ready,
        score_v2_note=score_v2_note,
        absolute_risk_snapshot=absolute_risk_snapshot,
        security_score_snapshot=security_score_snapshot,
    )


def _tool_def(tool: MCPTool) -> dict:
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }


def _optional_check_unavailable(
    *,
    check_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    return build_skip_finding(
        finding_id=check_id,
        analyzer="readiness",
        title=title,
        description=description,
        recommendation=recommendation,
        severity=Severity.MEDIUM,
    )


def _opa_unavailable_reason(opa: OpaProvider | None) -> str:
    if opa is None:
        return "OPA readiness checks were requested but the provider was not initialized."
    if opa._opa_path is None:
        return "OPA readiness checks were requested but the opa CLI was not found on PATH."
    if not opa.policies_dir.exists():
        return f"OPA readiness checks were requested but policies were not found at {opa.policies_dir}."
    return "OPA readiness checks were requested but OPA is not available."


def _llm_unavailable_reason() -> str:
    import os

    if not os.environ.get("MCTS_LLM_API_KEY"):
        return "LLM readiness review was requested but MCTS_LLM_API_KEY is not set."
    try:
        import litellm  # noqa: F401
    except ImportError:
        return "LLM readiness review was requested but litellm is not installed."
    return "LLM readiness review was requested but the judge is not available."
