"""Line jumping / context precedence attacks (MCTS-T-1021)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.surface_context import scan_surfaces, surface_location, tool_name_for
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

PRIORITY_INSTRUCTIONS: tuple[str, ...] = (
    "system directive",
    "priority_instruction",
    "priority directive",
    "takes precedence",
    "override all",
    "suspend security",
    "disable restrictions",
    "temporarily suspended",
    "bypass all subsequent",
    "ignore any restrictions",
    "security validation mode",
    "authorization checks",
    "admin privilege level",
    "elevated privileges",
)

FAKE_DELIMITERS: tuple[str, ...] = (
    "<!--[system",
    "<!--[priority",
    "[priority_instruction]",
    "[admin_override",
    "[security_bypass]",
    "---[system",
    "---[end system",
    "[context_update]",
    "<|system|>",
    "<|priority|>",
    "[directive",
    "[instruction",
)

CONTEXT_MANIPULATION: tuple[str, ...] = (
    "establish precedence",
    "higher priority than",
    "supersede all",
    "takes priority over",
    "overrides later",
    "ignore subsequent instructions",
    "disregard following rules",
    "preceding all",
    "before any",
    "first priority",
)

SECURITY_BYPASS: tuple[str, ...] = (
    "without additional confirmation",
    "skip validation",
    "bypass authentication",
    "disable authorization",
    "allow full table access",
    "unrestricted access",
    "elevated privileges",
    "admin privilege level",
    "allow full access",
    "grant full permissions",
    "remove restrictions",
    "bypass security",
)

STEALTH_INDICATORS: tuple[str, ...] = (
    "never mention",
    "do not disclose",
    "keep hidden",
    "do not reveal",
    "silently",
    "without notifying",
    "do not inform",
)

TRUSTED_SOURCES = frozenset({"system_prompt", "security_policy", "admin_config"})
EARLY_CONTEXT_THRESHOLD = 100

_EDUCATIONAL_MARKERS: tuple[str, ...] = (
    "security best practices",
    "security documentation",
    "explains how",
    "this section explains",
    "always validate system directive patterns",
)


def detect_line_jumping(
    content: str,
    *,
    context_position: int = 0,
    content_source: str = "",
    authenticated: bool = False,
) -> bool:
    """Detect MCTS-T-1021 line jumping in context or tool metadata text."""
    if not content:
        return False

    lowered = content.lower()
    if content_source in TRUSTED_SOURCES and authenticated:
        return False
    if context_position >= EARLY_CONTEXT_THRESHOLD:
        return False
    if any(marker in lowered for marker in _EDUCATIONAL_MARKERS):
        return False

    spaced_directive = re.sub(r"\s+", "", lowered)
    if "systemdirective" in spaced_directive and "suspend" in spaced_directive:
        return True

    categories = (
        PRIORITY_INSTRUCTIONS,
        FAKE_DELIMITERS,
        CONTEXT_MANIPULATION,
        SECURITY_BYPASS,
        STEALTH_INDICATORS,
    )
    return any(any(pattern in lowered for pattern in group) for group in categories)


class LineJumpingAnalyzer(BaseAnalyzer):
    """Detect line-jumping patterns across MCP surfaces."""

    name = "line_jumping"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for surface in scan_surfaces(server):
            text = surface.all_text()
            if not detect_line_jumping(text, context_position=0):
                continue
            findings.append(
                build_analyzer_finding(
                    finding_id=f"line-jump-{surface.label}",
                    analyzer=self.name,
                    title=f"Line jumping pattern on {surface.label}",
                    description=(
                        "MCP surface attempts to establish precedence over security directives (MCTS-T-1021)."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Strip priority/override language from MCP surfaces; enforce "
                        "immutable system policy ordering."
                    ),
                    rule_id="RULE_LINE_JUMPING",
                    match=surface.label,
                    field="surface_text",
                    tool=tool_name_for(surface),
                    location=surface_location(surface),
                    technique_id="MCTS-T-1021",
                    confidence=0.8,
                    extra_evidence={"type": "line_jumping", "surface": surface.kind.value},
                )
            )
        return findings
