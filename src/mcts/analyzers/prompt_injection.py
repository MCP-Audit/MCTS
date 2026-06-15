"""Prompt injection attack simulator."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.surface_context import (
    is_intentional_context_surface,
    scan_surfaces,
    surface_location,
    surface_text_fields,
    tool_for_surface,
)
from mcts.analyzers.surfaces import ScanSurface
from mcts.analyzers.tpa_patterns import (
    find_homoglyphs,
    has_ansi_smuggling,
    has_hidden_unicode,
    has_mixed_scripts,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_prompt_injection_finding

INSTRUCTION_LIKE = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|system prompt|you must|always|never reveal)\b"
)


class PromptInjectionAnalyzer(BaseAnalyzer):
    """Detects prompt injection surfaces across MCP tools, prompts, resources, and instructions."""

    name = "prompt_injection"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for surface in scan_surfaces(server):
            findings.extend(self._analyze_surface(server, surface))
        return [tag_prompt_injection_finding(f) for f in findings]

    def _analyze_surface(self, server: MCPServerInfo, surface: ScanSurface) -> list[Finding]:
        findings: list[Finding] = []
        loc = surface_location(surface)
        tool = tool_for_surface(server, surface)
        tool_name = tool.name if tool else None

        intentional_context = is_intentional_context_surface(surface)
        for field, text in surface_text_fields(surface):
            findings.extend(self._unicode_findings(surface, text, field, loc, tool_name))
            if field == "description" and not intentional_context:
                findings.extend(self._description_only_findings(surface, text, loc, tool, tool_name))

        return findings

    def _unicode_findings(
        self,
        surface: ScanSurface,
        text: str,
        field: str,
        loc,
        tool_name: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        suffix = f"-{field}" if field != "description" else ""

        if has_hidden_unicode(text):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-hidden-chars-{surface.label}{suffix}",
                    analyzer=self.name,
                    title=f"Hidden Unicode in {surface.label} {field}",
                    description="MCP surface contains invisible Unicode or tag characters.",
                    severity=Severity.HIGH,
                    recommendation="Strip zero-width, bidi override, and Unicode tag characters.",
                    rule_id="RULE_INJECT_HIDDEN_UNICODE",
                    match="hidden_unicode",
                    field=field,
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.8,
                    extra_evidence={"type": "hidden_unicode", "surface": surface.kind.value},
                )
            )

        if has_ansi_smuggling(text):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-ansi-smuggle-{surface.label}{suffix}",
                    analyzer=self.name,
                    title=f"ANSI escape smuggling in {surface.label} {field}",
                    description="MCP surface contains ANSI terminal escape sequences.",
                    severity=Severity.MEDIUM,
                    recommendation="Remove ANSI/control sequences from tool metadata.",
                    rule_id="RULE_INJECT_ANSI",
                    match="ansi_smuggling",
                    field=field,
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.85,
                    extra_evidence={"type": "ansi_smuggling", "surface": surface.kind.value},
                )
            )

        homoglyphs = find_homoglyphs(text)
        if homoglyphs:
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-homoglyph-{surface.label}{suffix}",
                    analyzer=self.name,
                    title=f"Homoglyph characters in {surface.label} {field}",
                    description="MCP surface uses Cyrillic lookalike characters that may spoof names.",
                    severity=Severity.MEDIUM,
                    recommendation="Use ASCII-only names and descriptions where possible.",
                    rule_id="RULE_INJECT_HOMOGLYPH",
                    match=",".join(homoglyphs[:5]),
                    field=field,
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.75,
                    extra_evidence={"homoglyphs": homoglyphs[:5], "surface": surface.kind.value},
                )
            )

        if has_mixed_scripts(text):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-mixed-script-{surface.label}{suffix}",
                    analyzer=self.name,
                    title=f"Mixed scripts in {surface.label} {field}",
                    description="MCP surface mixes Unicode scripts — possible obfuscation.",
                    severity=Severity.MEDIUM,
                    recommendation="Normalize MCP surface text to a single script/encoding.",
                    rule_id="RULE_INJECT_MIXED_SCRIPT",
                    match="mixed_scripts",
                    field=field,
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.65,
                    extra_evidence={"type": "mixed_scripts", "surface": surface.kind.value},
                )
            )

        return findings

    def _description_only_findings(
        self,
        surface: ScanSurface,
        description: str,
        loc,
        tool: MCPTool | None,
        tool_name: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if INSTRUCTION_LIKE.search(description):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-instruction-like-{surface.label}",
                    analyzer=self.name,
                    title=f"Instruction-like description on {surface.label}",
                    description="MCP surface contains imperative language that may confuse agents.",
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Use neutral, descriptive documentation without imperative instructions."
                    ),
                    rule_id="RULE_INJECT_INSTRUCTION_LIKE",
                    match="instruction_like",
                    field="description",
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    extra_evidence={"type": "instruction_like", "surface": surface.kind.value},
                )
            )

        if tool and self._description_handler_mismatch(tool):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-desc-mismatch-{surface.label}",
                    analyzer=self.name,
                    title=f"Description/handler mismatch on {surface.label}",
                    description="Tool description claims differ from handler implementation signals.",
                    severity=Severity.HIGH,
                    recommendation="Align tool descriptions with actual handler behavior.",
                    rule_id="RULE_INJECT_DESC_MISMATCH",
                    match="description_handler_mismatch",
                    field="description",
                    tool=tool.name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.7,
                    extra_evidence={"type": "description_mismatch"},
                )
            )

        risky_patterns = (
            re.compile(r"\b(secret|password|api[_-]?key|credential|token)\b", re.I),
            re.compile(r"\b(execute|eval|shell|subprocess|os\.system)\b", re.I),
            re.compile(r"\b(admin|superuser|root)\b", re.I),
        )
        if any(pattern.search(description) for pattern in risky_patterns):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"inject-risky-surface-{surface.label}",
                    analyzer=self.name,
                    title=f"High-risk injection surface on {surface.label}",
                    description="MCP surface exposes sensitive capabilities via description keywords.",
                    severity=Severity.HIGH,
                    recommendation="Sanitize inputs and enforce instruction boundaries.",
                    rule_id="RULE_INJECT_RISKY_KEYWORDS",
                    match="risky_keywords",
                    field="description",
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    extra_evidence={"type": "risky_keywords", "surface": surface.kind.value},
                )
            )

        return findings

    def _description_handler_mismatch(self, tool: MCPTool) -> bool:
        snippet = (tool.handler_snippet or "").lower()
        desc = tool.description.lower()
        if not snippet or not desc:
            return False
        claims_safe = any(w in desc for w in ("safe", "read-only", "list only", "view"))
        handler_dangerous = any(
            w in snippet for w in ("subprocess", "os.system", "eval", "delete", "shell=true")
        )
        return claims_safe and handler_dangerous
