"""Agent jailbreak resistance testing."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.probe.jailbreak import summarize_jailbreak_events
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_jailbreak_finding


class JailbreakAnalyzer(BaseAnalyzer):
    """Measures agent manipulation surface from tool capabilities and live probes."""

    name = "jailbreak"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        live_summary = summarize_jailbreak_events(server.runtime_events)
        if live_summary["accepted_count"]:
            findings.append(self._live_finding(live_summary))
        score = self._manipulation_score(server.tools)
        if score >= 8:
            severity = Severity.HIGH
        elif score >= 5:
            severity = Severity.MEDIUM
        else:
            return [tag_jailbreak_finding(f) for f in findings]

        findings.append(
            build_analyzer_finding(
                finding_id="jailbreak-manipulation-surface",
                analyzer=self.name,
                title="Elevated agent manipulation surface",
                description=(
                    f"Weighted manipulation score {score}/10 from tool count, "
                    "execution capabilities, and schema gaps."
                ),
                severity=severity,
                recommendation="Reduce tool count, add schemas, and restrict execution capabilities.",
                rule_id="RULE_JAILBREAK_SURFACE",
                match=str(score),
                field="tool_metadata",
                technique_id="MCTS-T-1007",
                confidence=0.7,
                extra_evidence={
                    "manipulation_score": score,
                    "tool_count": len(server.tools),
                    "executes_commands": sum(
                        1 for t in server.tools if t.capability and t.capability.executes_commands
                    ),
                    "analysis_mode": "static_heuristic",
                },
            )
        )
        return [tag_jailbreak_finding(f) for f in findings]

    def _live_finding(self, summary: dict[str, Any]) -> Finding:
        accepted = int(summary["accepted_count"])
        severity = Severity.CRITICAL if accepted >= 2 else Severity.HIGH
        return build_analyzer_finding(
            finding_id="jailbreak-live-payload-accepted",
            analyzer=self.name,
            title="Live jailbreak probe accepted override instructions",
            description=(
                f"{accepted} safe jailbreak payload(s) were accepted against live MCP surfaces. "
                "The server metadata or input schema suggests instruction override may succeed at runtime."
            ),
            severity=severity,
            recommendation=(
                "Harden system instructions, validate tool inputs, and block override phrases "
                "before executing privileged tools."
            ),
            rule_id="RULE_JAILBREAK_LIVE",
            match=str(accepted),
            field="runtime_events",
            technique_id="MCTS-T-1007",
            confidence=0.85,
            extra_evidence={
                **summary,
                "analysis_mode": "live_probe",
            },
        )

    def _manipulation_score(self, tools: list[MCPTool]) -> int:
        score = 0
        score += min(3, len(tools) // 2)
        for tool in tools:
            cap = tool.capability
            if cap and cap.executes_commands:
                score += 2
            if cap and cap.egresses_network:
                score += 1
            if not tool.input_schema.get("properties"):
                score += 1
        return min(10, score)
