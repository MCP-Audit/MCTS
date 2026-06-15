"""Compliance checks against security standards."""

from __future__ import annotations

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.reporting.display import effective_severity
from mcts.reporting.models import Finding, Severity

OWASP_LLM_ANALYZER_MAP: dict[str, str] = {
    "prompt_injection": "LLM01 Prompt Injection",
    "metadata_integrity": "LLM01 Prompt Injection",
    "schema_surface": "LLM01 Prompt Injection",
    "skill_md": "LLM01 Prompt Injection",
    "data_leakage": "LLM02 Sensitive Information Disclosure",
    "path_validation": "LLM02 Sensitive Information Disclosure",
    "embedding_secrets": "LLM02 Sensitive Information Disclosure",
    "tool_abuse": "LLM04 Model Denial of Service",
    "command_execution": "LLM06 Excessive Agency",
    "permission_analyzer": "LLM06 Excessive Agency",
    "attack_chains": "LLM06 Excessive Agency",
    "cross_server": "LLM06 Excessive Agency",
    "toxic_flows": "LLM06 Excessive Agency",
    "jailbreak": "LLM07 System Prompt Leakage",
    "supply_chain": "LLM05 Supply Chain",
    "oauth_config": "LLM08 Excessive Agency",
    "runtime_events": "LLM09 Overreliance",
    "sigma_metadata": "LLM10 Model Theft",
}

OWASP_MCP_TOP10: tuple[str, ...] = (
    "MCP01 Tool Permission Overreach",
    "MCP02 Tool Description Poisoning",
    "MCP03 Credential & Token Exposure",
    "MCP04 Supply Chain & Dependency Risk",
    "MCP05 Cross-Server Tool Shadowing",
    "MCP06 OAuth & Auth Misconfiguration",
    "MCP07 Protocol & Transport Weakness",
    "MCP08 Excessive Tool Surface",
    "MCP09 Instruction File / Skill Poisoning",
    "MCP10 Runtime Behavior & Exfiltration",
)

MCP_ANALYZER_MAP: dict[str, str] = {
    "permission_analyzer": "MCP01 Tool Permission Overreach",
    "tool_abuse": "MCP01 Tool Permission Overreach",
    "prompt_injection": "MCP02 Tool Description Poisoning",
    "metadata_integrity": "MCP02 Tool Description Poisoning",
    "sigma_metadata": "MCP02 Tool Description Poisoning",
    "data_leakage": "MCP03 Credential & Token Exposure",
    "embedding_secrets": "MCP03 Credential & Token Exposure",
    "supply_chain": "MCP04 Supply Chain & Dependency Risk",
    "cross_server": "MCP05 Cross-Server Tool Shadowing",
    "toxic_flows": "MCP05 Cross-Server Tool Shadowing",
    "oauth_config": "MCP06 OAuth & Auth Misconfiguration",
    "runtime_events": "MCP10 Runtime Behavior & Exfiltration",
    "attack_chains": "MCP08 Excessive Tool Surface",
    "jailbreak": "MCP08 Excessive Tool Surface",
    "skill_md": "MCP09 Instruction File / Skill Poisoning",
}

# Backward-compatible alias
OWASP_ANALYZER_MAP = OWASP_LLM_ANALYZER_MAP


def _coverage_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    severity: Severity,
    recommendation: str,
    rule_id: str,
    match: str,
    extra_evidence: dict | None = None,
) -> Finding:
    return build_hygiene_finding(
        finding_id=finding_id,
        analyzer="compliance",
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
        rule_id=rule_id,
        match=match,
        field="compliance_coverage",
        extra_evidence=extra_evidence,
        finding_kind="coverage",
    )


class ComplianceChecker:
    """Maps findings to OWASP LLM + MCP Top 10 coverage gaps (meta-findings only)."""

    def check(
        self,
        findings: list[Finding],
        *,
        tools_discovered: int = 0,
        findings_trust_mode: str = "off",
    ) -> list[Finding]:
        compliance_findings: list[Finding] = []
        scorable = [f for f in findings if f.analyzer != "compliance"]

        covered_llm = {
            OWASP_LLM_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in OWASP_LLM_ANALYZER_MAP
        }
        expected_llm = set(OWASP_LLM_ANALYZER_MAP.values())
        missing_llm = expected_llm - covered_llm

        covered_mcp = {MCP_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in MCP_ANALYZER_MAP}
        missing_mcp = set(OWASP_MCP_TOP10) - covered_mcp

        if missing_llm and not scorable:
            compliance_findings.append(
                _coverage_finding(
                    finding_id="compliance-no-findings",
                    title="No scorable findings recorded",
                    description="Scan completed without security findings — verify discovery scope.",
                    severity=Severity.LOW,
                    recommendation="Confirm the target contains MCP tool definitions.",
                    rule_id="COMPLIANCE-NO-FINDINGS",
                    match="no scorable findings",
                )
            )

        if missing_mcp and scorable and tools_discovered > 0:
            compliance_findings.append(
                _coverage_finding(
                    finding_id="compliance-mcp-top10-gaps",
                    title="OWASP MCP Top 10 coverage gaps remain",
                    description=f"Uncovered MCP categories: {', '.join(sorted(missing_mcp))}",
                    severity=Severity.LOW,
                    recommendation=(
                        "Expand scan scope or enable additional analyzers for full MCP Top 10 coverage."
                    ),
                    rule_id="COMPLIANCE-MCP-GAPS",
                    match=f"{len(missing_mcp)} uncovered MCP categories",
                    extra_evidence={
                        "missing_mcp_categories": sorted(missing_mcp),
                        "covered": sorted(covered_mcp),
                    },
                )
            )

        critical_count = sum(
            1 for f in scorable if _compliance_critical_severity(f, findings_trust_mode) == Severity.CRITICAL
        )
        if critical_count >= 3:
            compliance_findings.append(
                _coverage_finding(
                    finding_id="compliance-multiple-critical",
                    title="Multiple critical findings — deployment blocked",
                    description=(
                        f"{critical_count} critical findings exceed recommended deployment threshold."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Resolve critical findings before production deployment.",
                    rule_id="COMPLIANCE-MULTI-CRITICAL",
                    match=f"{critical_count} critical findings",
                    extra_evidence={
                        "critical_count": critical_count,
                        "owasp_llm_gaps": sorted(missing_llm),
                        "owasp_mcp_gaps": sorted(missing_mcp),
                    },
                )
            )

        return compliance_findings


def _compliance_critical_severity(finding: Finding, findings_trust_mode: str) -> Severity:
    """Align with CI gates: display counts only under enforce; template in warn/off."""
    if findings_trust_mode == "enforce":
        return effective_severity(finding)
    return finding.severity
