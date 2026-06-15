"""Shared findings trust pipeline for scan and auxiliary entry points."""

from __future__ import annotations

from typing import Any

from mcts.mcp.models import MCPTool
from mcts.reporting.finding_validator import ValidationContext, validate_findings
from mcts.reporting.models import Finding


def build_trust_context(
    *,
    mode: str,
    scan_scope: str = "repository",
    tools: list[MCPTool] | None = None,
    attack_graph: dict[str, Any] | None = None,
) -> ValidationContext:
    return ValidationContext(
        scan_scope=scan_scope,
        tools=tools or [],
        attack_graph=attack_graph or {},
        mode=mode,
    )


def apply_trust_layer(findings: list[Finding], ctx: ValidationContext) -> list[Finding]:
    """Run validator + provenance enrichment (when trust mode is active)."""
    findings = validate_findings(findings, ctx)
    if ctx.mode == "off":
        return findings
    from mcts.reporting.evidence_provenance import enrich_provenance
    from mcts.reporting.runtime_evidence import validate_runtime_evidence

    findings = enrich_provenance(findings, ctx)
    return validate_runtime_evidence(findings)
