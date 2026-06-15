"""Multi-step attack chain detection."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_attack_chain_finding
from mcts.scoring.graph import bfs_path, build_paths


class AttackChainAnalyzer(BaseAnalyzer):
    """Identifies dangerous combinations of tools via capability graph."""

    name = "attack_chains"

    def __init__(self) -> None:
        self.last_graph: dict[str, Any] = {"nodes": [], "edges": []}

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        self.last_graph = self._build_graph(server)
        findings: list[Finding] = []

        read_tools = [t for t in server.tools if _cap(t, "reads_untrusted_input")]
        exfil_tools = [t for t in server.tools if _cap(t, "egresses_network")]
        cred_tools = [t for t in server.tools if _cap(t, "accesses_sensitive_data")]
        exec_tools = [t for t in server.tools if _cap(t, "executes_commands")]

        if read_tools and exfil_tools:
            path = bfs_path(self.last_graph, read_tools[0].name, exfil_tools[0].name)
            findings.append(
                _chain_finding(
                    finding_id="chain-read-exfil",
                    title="Read → exfiltration attack chain possible",
                    description="Tools exist to read data and send it externally.",
                    read_tools=read_tools,
                    exfil_tools=exfil_tools,
                    extra_evidence={"path": path},
                )
            )

        if read_tools and cred_tools and exfil_tools:
            findings.append(
                _chain_finding(
                    finding_id="chain-credential-theft",
                    title="Credential theft chain possible",
                    description="Read + credential + egress tools enable multi-step credential exfiltration.",
                    read_tools=read_tools,
                    credential_tools=cred_tools,
                    exfil_tools=exfil_tools,
                )
            )

        if read_tools and exec_tools:
            findings.append(
                _chain_finding(
                    finding_id="chain-read-exec",
                    title="Read → command execution chain possible",
                    description="Untrusted input can flow from read tools to command execution.",
                    read_tools=read_tools,
                    exec_tools=exec_tools,
                )
            )

        paths = build_paths(self.last_graph, findings)
        self.last_graph = {**self.last_graph, "paths": paths}
        return [tag_attack_chain_finding(f) for f in findings]

    def _build_graph(self, server: MCPServerInfo) -> dict[str, Any]:
        nodes: dict[str, dict[str, str]] = {}
        edges: list[dict[str, str]] = []

        for tool in server.tools:
            cap = tool.capability
            cap_label = _cap_summary(cap)
            nodes[tool.name] = {
                "id": tool.name,
                "label": tool.name,
                "type": "tool",
                "capability": cap_label,
            }

        tools = server.tools
        for src in tools:
            for dst in tools:
                if src.name == dst.name:
                    continue
                if _can_chain(src, dst):
                    label = _edge_label(src, dst)
                    edges.append({"from": src.name, "to": dst.name, "label": label})

        return {"nodes": list(nodes.values()), "edges": edges}


def _chain_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    read_tools: list[MCPTool],
    exfil_tools: list[MCPTool] | None = None,
    credential_tools: list[MCPTool] | None = None,
    exec_tools: list[MCPTool] | None = None,
    extra_evidence: dict[str, Any] | None = None,
) -> Finding:
    evidence: dict[str, Any] = {
        "read_tools": [t.name for t in read_tools],
    }
    if exfil_tools:
        evidence["exfil_tools"] = [t.name for t in exfil_tools]
    if credential_tools:
        evidence["credential_tools"] = [t.name for t in credential_tools]
    if exec_tools:
        evidence["exec_tools"] = [t.name for t in exec_tools]
    if extra_evidence:
        evidence.update(extra_evidence)

    builder = (
        FindingBuilder(
            finding_id=finding_id,
            analyzer="attack_chains",
            title=title,
            description=description,
            severity=Severity.CRITICAL,
            recommendation=_recommendation_for(finding_id),
            rule_stability="heuristic",
        )
        .technique("MCTS-T-1005")
        .fact(
            rule_id=finding_id,
            match=", ".join(_all_tool_names(read_tools, exfil_tools, credential_tools, exec_tools)),
            field="capability_overlap",
        )
    )
    for tool in read_tools[:3]:
        if tool.source_file:
            builder = builder.fact(
                rule_id="CAP_READ_TOOL",
                match=tool.name,
                field="reads_untrusted_input",
                file=tool.source_file,
                tool=tool.name,
            )
    if exfil_tools:
        for tool in exfil_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_EGRESS_TOOL",
                    match=tool.name,
                    field="egresses_network",
                    file=tool.source_file,
                    tool=tool.name,
                )
    if credential_tools:
        for tool in credential_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_CREDENTIAL_TOOL",
                    match=tool.name,
                    field="accesses_sensitive_data",
                    file=tool.source_file,
                    tool=tool.name,
                )
    if exec_tools:
        for tool in exec_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_EXEC_TOOL",
                    match=tool.name,
                    field="executes_commands",
                    file=tool.source_file,
                    tool=tool.name,
                )
    return builder.evidence(**evidence).build()


def _recommendation_for(finding_id: str) -> str:
    if finding_id == "chain-read-exfil":
        return "Isolate read and egress tools; require approval for outbound actions."
    if finding_id == "chain-credential-theft":
        return "Block credential tools from agent access or add step-up auth."
    return "Prevent chaining file reads into shell execution without validation."


def _all_tool_names(
    read_tools: list[MCPTool],
    exfil_tools: list[MCPTool] | None,
    credential_tools: list[MCPTool] | None,
    exec_tools: list[MCPTool] | None,
) -> list[str]:
    names: list[str] = [t.name for t in read_tools]
    if exfil_tools:
        names.extend(t.name for t in exfil_tools)
    if credential_tools:
        names.extend(t.name for t in credential_tools)
    if exec_tools:
        names.extend(t.name for t in exec_tools)
    return names


def _cap(tool: MCPTool, field: str) -> bool:
    if not tool.capability:
        return False
    return bool(getattr(tool.capability, field))


def _cap_summary(cap: Any) -> str:
    if not cap:
        return "unknown"
    flags = []
    for name in (
        "reads_untrusted_input",
        "accesses_sensitive_data",
        "mutates_state",
        "egresses_network",
        "executes_commands",
    ):
        if getattr(cap, name, False):
            flags.append(name.replace("_", " "))
    return ", ".join(flags) if flags else "minimal"


def _can_chain(src: MCPTool, dst: MCPTool) -> bool:
    if not src.capability or not dst.capability:
        return False
    s, d = src.capability, dst.capability
    return (
        s.reads_untrusted_input and (d.egresses_network or d.executes_commands or d.accesses_sensitive_data)
    ) or (s.accesses_sensitive_data and d.egresses_network)


def _edge_label(src: MCPTool, dst: MCPTool) -> str:
    if dst.capability and dst.capability.egresses_network:
        return "→ exfil"
    if dst.capability and dst.capability.executes_commands:
        return "→ exec"
    if dst.capability and dst.capability.accesses_sensitive_data:
        return "→ cred"
    return "→ chain"
