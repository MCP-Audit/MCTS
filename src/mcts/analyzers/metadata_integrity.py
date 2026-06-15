"""Tool metadata integrity checks (description poisoning)."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.surface_context import (
    is_intentional_context_surface,
    scan_surfaces,
    surface_location,
    surface_text_fields,
    tool_for_surface,
)
from mcts.analyzers.surfaces import ScanSurface, ScanSurfaceKind
from mcts.analyzers.tpa_patterns import (
    scan_text_poison,
    scan_text_templates,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity

EXCESSIVE_LENGTH = 500


class MetadataIntegrityAnalyzer(BaseAnalyzer):
    """Detects poisoned or manipulative metadata across MCP surfaces."""

    name = "metadata_integrity"

    def __init__(self, skip_poison_checks: bool = False) -> None:
        self.skip_poison_checks = skip_poison_checks

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for surface in scan_surfaces(server):
            findings.extend(self._analyze_surface(server, surface))
        return findings

    def _analyze_surface(self, server: MCPServerInfo, surface: ScanSurface) -> list[Finding]:
        findings: list[Finding] = []
        tool = tool_for_surface(server, surface)
        loc = surface_location(surface)
        tool_name = surface.name if surface.kind == ScanSurfaceKind.TOOL else None

        intentional_context = is_intentional_context_surface(surface)
        if not self.skip_poison_checks and not intentional_context:
            for field, text in surface_text_fields(surface):
                for label, severity in scan_text_poison(text) + scan_text_templates(text):
                    findings.append(
                        self._finding(
                            surface,
                            tool,
                            f"meta-poison-{surface.label}-{field}-{label}",
                            label,
                            severity,
                            field,
                            loc,
                        )
                    )

        description = surface.description or ""
        if len(description) > EXCESSIVE_LENGTH and not intentional_context:
            findings.append(
                build_analyzer_finding(
                    finding_id=f"meta-excessive-desc-{surface.label}",
                    analyzer=self.name,
                    title=f"Excessive description length on {surface.label}",
                    description=(
                        f"Description is {len(description)} chars — may hide instructions (line jumping)."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Keep MCP surface descriptions concise; move docs outside the MCP surface."
                    ),
                    rule_id="RULE_META_EXCESSIVE_DESC",
                    match=str(len(description)),
                    field="description",
                    tool=tool_name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    extra_evidence={"length": len(description), "surface": surface.kind.value},
                )
            )

        return findings

    def _finding(
        self,
        surface: ScanSurface,
        tool: MCPTool | None,
        finding_id: str,
        label: str,
        severity: Severity,
        field: str,
        loc,
    ) -> Finding:
        return build_analyzer_finding(
            finding_id=finding_id,
            analyzer=self.name,
            title=f"Metadata poisoning on {surface.label} ({field}): {label.replace('_', ' ')}",
            description="MCP surface metadata contains manipulative or injection patterns.",
            severity=severity,
            recommendation="Rewrite descriptions as neutral capability summaries.",
            rule_id="RULE_META_POISON",
            match=label,
            field=field,
            tool=tool.name if tool else None,
            location=loc,
            technique_id="MCTS-T-1001",
            confidence=0.85,
            extra_evidence={"pattern": label, "field": field, "surface": surface.kind.value},
        )
