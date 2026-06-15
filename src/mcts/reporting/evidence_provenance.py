"""Phase 1 evidence pyramid enrichment for attack-chain findings."""

from __future__ import annotations

from typing import Any

from mcts.mcp.models import CapabilitySignal, MCPTool
from mcts.reporting.finding_validator import ValidationContext
from mcts.reporting.models import Finding

_RULE_LABELS: dict[str, str] = {
    "CAP_CREDENTIAL_KEYWORD": "credential keyword in tool metadata",
    "CAP_CREDENTIAL_ENV": "environment variable access in handler",
    "CAP_EGRESS_HANDLER": "network or subprocess call in handler",
    "CAP_EGRESS_HINT": "egress keyword in tool metadata",
    "CAP_READ_HINT": "read/input keyword in tool metadata",
    "CAP_EXEC_HANDLER": "command execution call in handler",
    "CAP_EXEC_HINT": "execution keyword in tool metadata",
    "CAP_SCHEMA_PATH": "path parameter in input schema",
    "CAP_TOOL_NAME_SHELL": "shell-like tool name",
    "CAP_TOOL_NAME_EGRESS": "egress-like tool name",
    "CAP_TOOL_NAME_READ": "read-like tool name",
    "CAP_TOOL_NAME_SENSITIVE": "sensitive-data-like tool name",
}


def fact_coverage(findings: list[Finding]) -> dict[str, float | int]:
    """Share of security findings with structured facts (Phase 1 metric)."""
    from mcts.reporting.display import is_security_finding

    security = [f for f in findings if is_security_finding(f)]
    if not security:
        return {"total": 0, "with_facts": 0, "pct": 100.0}
    with_facts = sum(
        1 for f in security if isinstance((f.evidence or {}).get("facts"), list) and f.evidence["facts"]
    )
    total = len(security)
    return {
        "total": total,
        "with_facts": with_facts,
        "pct": round(100.0 * with_facts / total, 1),
    }


def enrich_provenance(findings: list[Finding], ctx: ValidationContext) -> list[Finding]:
    """Attach facts, interpretation, and confidence factors when trust mode is active."""
    if ctx.mode == "off":
        return findings
    tools_by_name = {tool.name: tool for tool in ctx.tools}
    return [_enrich_one(finding, ctx, tools_by_name) for finding in findings]


def _enrich_one(
    finding: Finding,
    ctx: ValidationContext,
    tools_by_name: dict[str, MCPTool],
) -> Finding:
    if finding.analyzer == "attack_chains":
        evidence = dict(finding.evidence or {})
        tool_names = _chain_tool_names(evidence)
        matched_tools = [tools_by_name[name] for name in tool_names if name in tools_by_name]
        facts = _facts_from_tools(matched_tools)
        interpretation = _interpretation(finding, evidence, matched_tools, tool_names)
        confidence_factors = _confidence_factors(finding, evidence, matched_tools, facts)
        counterfactual = _counterfactual_remediation(matched_tools, facts)

        evidence["facts"] = facts
        evidence["interpretation"] = interpretation
        evidence["confidence_factors"] = confidence_factors
        evidence["counterfactual_remediation"] = counterfactual
        evidence["evidence_tier"] = "silver" if any(f.get("snippet") for f in facts) else "bronze"

        return finding.model_copy(update={"evidence": evidence})

    evidence = dict(finding.evidence or {})
    if evidence.get("skipped"):
        return finding

    facts = evidence.get("facts")
    if isinstance(facts, list) and facts:
        evidence = _enrich_bronze_counterfactual(finding, evidence, facts)
        return finding.model_copy(update={"evidence": evidence})

    legacy_facts = _legacy_facts_from_evidence(finding, evidence)
    if legacy_facts:
        evidence["facts"] = legacy_facts
        evidence = _enrich_bronze_counterfactual(finding, evidence, legacy_facts)
        return finding.model_copy(update={"evidence": evidence})
    return finding


def _legacy_facts_from_evidence(finding: Finding, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Synthesize bronze facts from legacy evidence keys when analyzers omit facts[] (R17)."""
    rule_id = evidence.get("rule_id") or evidence.get("matched") or finding.analyzer
    match = (
        evidence.get("match")
        or evidence.get("pattern")
        or evidence.get("matched")
        or evidence.get("signal")
        or ""
    )
    if not rule_id and not match:
        return []

    field = str(evidence.get("field") or evidence.get("corpus_field") or "tool_metadata")
    fact: dict[str, Any] = {
        "rule_id": str(rule_id),
        "match": str(match),
        "field": field,
    }
    if finding.tool:
        fact["tool"] = finding.tool
    if finding.location and finding.location.file:
        fact["file"] = finding.location.file
        if finding.location.line is not None:
            fact["line"] = finding.location.line
    snippet = evidence.get("snippet") or evidence.get("response_excerpt") or evidence.get("excerpt")
    if snippet:
        fact["snippet"] = str(snippet)[:200]
    return [fact]


def _enrich_bronze_counterfactual(
    finding: Finding,
    evidence: dict[str, Any],
    facts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attach counterfactual + confidence factors for analyzer-emitted bronze facts (R17 partial)."""
    if not evidence.get("counterfactual_remediation"):
        triggered: list[str] = []
        actions: list[dict[str, str]] = []
        for fact in facts[:8]:
            rule_id = str(fact.get("rule_id", ""))
            match = str(fact.get("match", ""))
            tool = str(fact.get("tool", finding.tool or ""))
            triggered.append(f"{tool}: {rule_id} matched {match!r}")
            actions.append(
                {
                    "action": f"Address {match!r} ({rule_id}) on {tool}".strip(),
                    "removes": rule_id,
                }
            )
        evidence["counterfactual_remediation"] = {
            "triggered_by": triggered,
            "removing_any_one_eliminates_finding": len(facts) > 1,
            "actions": actions,
        }
    if not evidence.get("confidence_factors"):
        factors: list[str] = []
        for fact in facts[:6]:
            rule_id = str(fact.get("rule_id", "signal"))
            match = str(fact.get("match", ""))
            line = f"{rule_id}: {match}" if match else rule_id
            if line not in factors:
                factors.append(line)
        evidence["confidence_factors"] = factors
    if not evidence.get("evidence_tier"):
        evidence["evidence_tier"] = "silver" if any(f.get("snippet") for f in facts) else "bronze"
    return evidence


def _chain_tool_names(evidence: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("read_tools", "credential_tools", "exfil_tools", "exec_tools"):
        raw = evidence.get(key, [])
        if isinstance(raw, list):
            names.extend(str(item) for item in raw)
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _facts_from_tools(tools: list[MCPTool]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for tool in tools:
        cap = tool.capability
        if cap is None:
            continue
        for signal in cap.signals:
            facts.append(_signal_to_fact(signal, tool))
    return facts


def _signal_to_fact(signal: CapabilitySignal, tool: MCPTool) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rule_id": signal.rule_id,
        "tool": tool.name,
        "field": signal.field,
        "match": signal.match,
        "dimension": signal.dimension,
    }
    if tool.source_file:
        row["file"] = tool.source_file
    if tool.source_line is not None:
        row["line"] = tool.source_line
    snippet = signal.snippet or _handler_preview(tool)
    if snippet:
        row["snippet"] = snippet
    return row


def _handler_preview(tool: MCPTool) -> str | None:
    snippet = tool.handler_snippet
    if not snippet:
        return None
    text = snippet.replace("\n", " ").strip()
    return text[:160] if len(text) > 160 else text


def _interpretation(
    finding: Finding,
    evidence: dict[str, Any],
    tools: list[MCPTool],
    tool_names: list[str],
) -> dict[str, Any]:
    capabilities: dict[str, dict[str, list[str]]] = {}
    for tool in tools:
        cap = tool.capability
        if cap is None:
            continue
        for signal in cap.signals:
            bucket = capabilities.setdefault(signal.dimension, {"signals": []})
            label = f"{signal.field}:{signal.match}"
            if label not in bucket["signals"]:
                bucket["signals"].append(label)

    return {
        "capabilities": capabilities,
        "evidence_type": finding.evidence_type or evidence.get("evidence_type"),
        "single_tool_overlap": evidence.get("single_tool_overlap"),
        "mcp_context": {
            "tool_exposed": bool(tool_names),
            "agent_reachable": "not_assessed",
            "requires_model_delegation": True,
            "tools_on_path": tool_names,
        },
    }


def _confidence_factors(
    finding: Finding,
    evidence: dict[str, Any],
    tools: list[MCPTool],
    facts: list[dict[str, Any]],
) -> list[str]:
    factors: list[str] = []
    seen: set[str] = set()
    for fact in facts:
        rule_id = str(fact.get("rule_id", ""))
        label = _RULE_LABELS.get(rule_id, rule_id.replace("_", " ").lower())
        if rule_id == "CAP_EGRESS_HANDLER" and fact.get("match"):
            line = f"network or subprocess call in handler ({fact['match']})"
        elif rule_id == "CAP_CREDENTIAL_KEYWORD" and fact.get("match"):
            line = f"credential keyword in tool metadata ({fact['match']})"
        else:
            line = label
        if line not in seen:
            seen.add(line)
            factors.append(line)

    if evidence.get("single_tool_overlap"):
        factors.append("single-tool overlap — not a proven multi-step path")
    elif finding.evidence_type == "capability_overlap":
        factors.append("capability overlap across tools — no validated dataflow path")
    elif finding.evidence_type == "graph_path":
        factors.append("multi-tool graph path recorded in scan graph")

    if not tools:
        factors.append("tool capability signals unavailable — re-scan with tool discovery enabled")

    return factors


def _counterfactual_remediation(tools: list[MCPTool], facts: list[dict[str, Any]]) -> dict[str, Any]:
    triggered: list[str] = []
    actions: list[dict[str, str]] = []
    for fact in facts[:8]:
        rule_id = str(fact.get("rule_id", ""))
        match = str(fact.get("match", ""))
        tool = str(fact.get("tool", ""))
        triggered.append(f"{tool}: {rule_id} matched {match!r}")
        actions.append(
            {
                "action": f"Remove or refactor {match!r} ({rule_id}) on {tool}",
                "removes": rule_id,
            }
        )

    return {
        "triggered_by": triggered,
        "removing_any_one_eliminates_finding": len({fact.get("dimension") for fact in facts}) > 1,
        "actions": actions,
    }
