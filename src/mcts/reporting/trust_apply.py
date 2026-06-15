"""Apply findings trust layer outside the main Scanner pipeline."""

from __future__ import annotations

from typing import Any

from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPTool
from mcts.reporting.display import effective_severity
from mcts.reporting.models import Finding
from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context


def apply_config_trust_layer(
    findings: list[Finding],
    config: ScanConfig,
    *,
    scan_scope: str = "repository",
    tools: list[MCPTool] | None = None,
    attack_graph: dict[str, Any] | None = None,
) -> list[Finding]:
    ctx = build_trust_context(
        mode=config.findings_trust_mode,
        scan_scope=scan_scope,
        tools=tools,
        attack_graph=attack_graph,
    )
    findings = apply_trust_layer(findings, ctx)
    return collapse_template_severity_if_requested(findings, config)


def collapse_template_severity_if_requested(
    findings: list[Finding],
    config: ScanConfig,
) -> list[Finding]:
    """Phase B3 opt-in: copy display_severity into template severity under enforce."""
    if not (config.collapse_template_severity or False) or config.findings_trust_mode != "enforce":
        return findings
    collapsed: list[Finding] = []
    for finding in findings:
        if finding.display_severity is not None:
            collapsed.append(finding.model_copy(update={"severity": finding.display_severity}))
        else:
            collapsed.append(finding)
    return collapsed


def resolve_config_with_policy(config: ScanConfig) -> ScanConfig:
    from mcts.governance import load_policy, merge_scan_config_with_policy

    try:
        policy = load_policy(config.governance_policy)
    except FileNotFoundError:
        policy = None
    return merge_scan_config_with_policy(config, policy)


def finding_severity_label(finding: Finding, config: ScanConfig) -> str:
    if config.findings_trust_mode == "off":
        return finding.severity.value
    return effective_severity(finding).value


def merge_scan_config_defaults(
    config: ScanConfig,
    *,
    findings_trust_mode: str | None = None,
) -> ScanConfig:
    """Merge auxiliary CLI config with governance policy.

    When ``findings_trust_mode`` is omitted, policy may inherit trust mode.
    When set (including explicit ``off``), ``findings_trust_mode_explicit`` is True.
    """
    trust_mode = (findings_trust_mode or "off").lower()
    merged = config.model_copy(
        update={
            "findings_trust_mode": trust_mode,
            "findings_trust_mode_explicit": findings_trust_mode is not None,
        }
    )
    return resolve_config_with_policy(merged)
