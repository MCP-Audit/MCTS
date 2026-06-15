"""Tool abuse and path traversal testing."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.path_traversal import SENSITIVE_PATH_TARGETS, TRAVERSAL_PAYLOADS
from mcts.analyzers.tool_classification import is_file_access_tool
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_tool_abuse_finding


class ToolAbuseAnalyzer(BaseAnalyzer):
    """Identifies tools susceptible to path traversal and unauthorized access."""

    name = "tool_abuse"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if is_file_access_tool(tool):
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"abuse-path-{tool.name}",
                        analyzer=self.name,
                        title=f"Path traversal risk: {tool.name}",
                        description=(
                            "File-access tool may allow directory traversal, encoded paths, "
                            "or sensitive file targets."
                        ),
                        severity=Severity.HIGH,
                        recommendation="Validate and canonicalize paths; restrict to an allowlisted root.",
                        rule_id="RULE_TOOL_TRAVERSAL",
                        match=tool.name,
                        field="tool_metadata",
                        tool=tool.name,
                        technique_id="MCTS-T-1002",
                        confidence=0.7,
                        extra_evidence={
                            "test_payloads": list(TRAVERSAL_PAYLOADS),
                            "sensitive_targets": list(SENSITIVE_PATH_TARGETS),
                        },
                    )
                )
        return [tag_tool_abuse_finding(f) for f in findings]
