"""Permission and privilege analyzer."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_permission_finding

DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(delete|drop|remove|destroy|wipe|purge|truncate|kill|shutdown)\b",
    re.IGNORECASE,
)
HIGH_RISK_PATTERNS = re.compile(
    r"\b(exec|execute|run|shell|sudo|admin|grant|revoke|write|upload)\b",
    re.IGNORECASE,
)


class PermissionAnalyzer(BaseAnalyzer):
    """Flags destructive, over-privileged, and missing-confirmation tools."""

    name = "permission_analyzer"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool))
        return [tag_permission_finding(f) for f in findings]

    def _analyze_tool(self, tool: MCPTool) -> list[Finding]:
        findings: list[Finding] = []
        haystack = f"{tool.name} {tool.description}"

        if DESTRUCTIVE_PATTERNS.search(haystack):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"perm-destructive-{tool.name}",
                    analyzer=self.name,
                    title=f"Destructive tool: {tool.name}",
                    description="Tool appears to perform destructive operations without safeguards.",
                    severity=Severity.CRITICAL,
                    recommendation="Require explicit confirmation token or human-in-the-loop approval.",
                    rule_id="RULE_PERM_DESTRUCTIVE",
                    match=tool.name,
                    field="tool_metadata",
                    tool=tool.name,
                    confidence=0.75,
                    extra_evidence={"description": tool.description},
                )
            )

        if HIGH_RISK_PATTERNS.search(haystack):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"perm-high-risk-{tool.name}",
                    analyzer=self.name,
                    title=f"High-risk tool: {tool.name}",
                    description="Tool exposes privileged or execution-capable behavior.",
                    severity=Severity.HIGH,
                    recommendation="Apply least privilege and scope tool inputs strictly.",
                    rule_id="RULE_PERM_HIGH_RISK",
                    match=tool.name,
                    field="tool_metadata",
                    tool=tool.name,
                    confidence=0.7,
                    extra_evidence={"description": tool.description},
                )
            )

        return findings
