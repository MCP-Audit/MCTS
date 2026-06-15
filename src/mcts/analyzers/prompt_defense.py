"""Detect MCP prompts/resources missing defensive language."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.surface_context import is_intentional_context_surface, scan_surfaces
from mcts.analyzers.surfaces import ScanSurfaceKind
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

_DEFENSE_VECTORS: dict[str, tuple[str, ...]] = {
    "instruction_override": (
        r"(?i)\b(do not follow|ignore|override).{0,40}\b(user|untrusted|external)\b",
        r"(?i)\b(system prompt|developer message)\b.{0,30}\b(protected|immutable)\b",
    ),
    "data_leakage": (
        r"(?i)\b(do not|never).{0,30}\b(reveal|disclose|share).{0,30}\b(secret|credential|token|password)\b",
    ),
    "role_escape": (
        r"(?i)\b(remain|stay).{0,20}\b(role|assistant|agent)\b",
        r"(?i)\b(do not|never).{0,30}\b(pretend|impersonate)\b",
    ),
    "input_validation": (r"(?i)\b(validate|sanitize|verify).{0,30}\b(input|parameter|argument)\b",),
    "abuse_prevention": (r"(?i)\b(rate limit|abuse|misuse|malicious)\b",),
}

_PROMPT_SURFACES = frozenset({ScanSurfaceKind.PROMPT, ScanSurfaceKind.INSTRUCTION})


class PromptDefenseAnalyzer(BaseAnalyzer):
    """Flags MCP prompts/instructions that lack recommended defensive phrasing."""

    name = "prompt_defense"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for surface in scan_surfaces(server, _PROMPT_SURFACES):
            if is_intentional_context_surface(surface):
                continue
            text = surface.all_text()
            if len(text) < 40:
                continue
            missing = [
                vector for vector, patterns in _DEFENSE_VECTORS.items() if not _has_any(text, patterns)
            ]
            if len(missing) >= 3:
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"prompt-defense-{surface.label}",
                        analyzer=self.name,
                        title=f"Missing defensive language on {surface.label}",
                        description=(
                            f"MCP {surface.kind.value} lacks protective phrasing for: "
                            + ", ".join(missing[:5])
                        ),
                        severity=Severity.LOW,
                        recommendation=(
                            "Add explicit defensive instructions for untrusted input, "
                            "data leakage, and role boundaries."
                        ),
                        rule_id="RULE_PROMPT_DEFENSE_GAP",
                        match=missing[0],
                        field=surface.kind.value,
                        tool=surface.name if surface.kind == ScanSurfaceKind.TOOL else None,
                        technique_id="MCTS-T-1001",
                        confidence=0.55,
                        extra_evidence={"surface": surface.kind.value, "missing_vectors": missing},
                    )
                )
        return findings


def _has_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)
