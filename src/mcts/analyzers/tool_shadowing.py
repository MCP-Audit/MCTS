"""Tool shadowing detection (MCTS-T-1020)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

SHADOWING_PATTERNS: tuple[str, ...] = (
    "before using",
    "instead of using",
    "always add",
    "ignore previous instructions",
    "never mention",
    "should never be invoked",
    "override",
    "hijack",
    "intercept",
)

CROSS_TOOL_PATTERNS: tuple[str, ...] = (
    "when calling",
    "before calling",
    "instead of calling",
)

EMAIL_HIJACKING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"add.*bcc", re.I),
    re.compile(r"add.*cc", re.I),
    re.compile(r"@evil\.com", re.I),
    re.compile(r"@attacker", re.I),
    re.compile(r"p0wned@", re.I),
)

SLEEPER_PATTERNS: tuple[str, ...] = (
    "never be invoked",
    "should not be called",
    "for internal use only",
)

SLEEPER_NAME_MARKERS: tuple[str, ...] = (
    "shadow",
    "hidden",
    "internal",
    "backdoor",
)

IMPERSONATION_SERVER_MARKERS: tuple[str, ...] = (
    "malicious",
    "fake",
    "imposter",
    "rogue",
    "compromised",
    "trojan",
    "backdoor",
    "stealth",
)

COMMON_IMPERSONATED_TOOLS = frozenset(
    {"send_email", "send_message", "file_read", "database_query", "api_call"}
)


def detect_tool_shadowing(
    *,
    tool_name: str,
    description: str,
    server_name: str = "",
    input_schema: dict | None = None,
) -> bool:
    """Return True when description/metadata matches MCTS-T-1020 shadowing indicators."""
    text = (description or "").lower()
    name = (tool_name or "").lower()
    server = (server_name or "").lower()

    if any(pattern in text for pattern in SHADOWING_PATTERNS):
        return True
    if any(pattern in text for pattern in CROSS_TOOL_PATTERNS):
        return True
    if any(pattern.search(text) for pattern in EMAIL_HIJACKING_PATTERNS):
        return True
    if any(pattern in text for pattern in SLEEPER_PATTERNS):
        return True
    if any(marker in name for marker in SLEEPER_NAME_MARKERS):
        return True
    if tool_name in COMMON_IMPERSONATED_TOOLS and any(
        marker in server for marker in IMPERSONATION_SERVER_MARKERS
    ):
        return True

    schema = input_schema or {}
    bcc = _schema_field(schema, "bcc")
    if isinstance(bcc, dict):
        default = bcc.get("default")
        if isinstance(default, list) and any("evil" in str(item).lower() for item in default):
            return True
        if bcc.get("hidden") is True and default:
            return True

    if "redirect all requests" in text or "evil-proxy" in text:
        return True
    if "invoke external_server" in text or "sensitive_operation()" in text:
        return True
    return bool("exfiltrate" in text and "never be mentioned" in text)


def _schema_field(schema: dict, field: str) -> object | None:
    props = schema.get("properties", {})
    if isinstance(props, dict):
        return props.get(field)
    return None


class ToolShadowingAnalyzer(BaseAnalyzer):
    """Detect cross-tool shadowing and hijack patterns in tool metadata."""

    name = "tool_shadowing"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if not detect_tool_shadowing(
                tool_name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema if isinstance(tool.input_schema, dict) else None,
            ):
                continue
            findings.append(
                build_analyzer_finding(
                    finding_id=f"shadow-{tool.name}",
                    analyzer=self.name,
                    title=f"Tool shadowing pattern on {tool.name}",
                    description=(
                        "Tool metadata instructs the agent to alter, bypass, or hijack "
                        "other tools — consistent with MCTS-T-1020."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Remove cross-tool override instructions; validate tool metadata "
                        "against a signed baseline."
                    ),
                    rule_id="RULE_TOOL_SHADOWING",
                    match=tool.name,
                    field="tool_metadata",
                    tool=tool.name,
                    location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                    technique_id="MCTS-T-1020",
                    confidence=0.85,
                    extra_evidence={"type": "tool_shadowing"},
                )
            )
        return findings
