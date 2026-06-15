"""Cross-server toxic flow detection (W015–W020 / E002)."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.inventory.hitting_set import minimum_hitting_set
from mcts.inventory.models import InventoryEntry
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

_SENSITIVE_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "delete_file",
        "run_shell",
        "execute_command",
        "http_request",
        "fetch",
        "post_webhook",
        "get_env",
        "read_env",
    }
)
_WRITE_TOOLS = frozenset({"write_file", "delete_file", "run_shell", "execute_command", "deploy"})
_READ_TOOLS = frozenset({"read_file", "get_env", "read_env", "fetch", "http_request"})


class ToxicFlowAnalyzer(BaseAnalyzer):
    """Detect toxic capability flows across configured MCP servers."""

    name = "toxic_flows"

    def __init__(self, inventory: list[InventoryEntry] | None = None) -> None:
        self.inventory = inventory or []

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        if len(self.inventory) < 2:
            return []
        return analyze_inventory(self.inventory)


def analyze_inventory(inventory: list[InventoryEntry]) -> list[Finding]:
    findings: list[Finding] = []
    server_tools: dict[str, set[str]] = {}
    server_meta: dict[str, InventoryEntry] = {}

    for entry in inventory:
        key = f"{entry.client}/{entry.server_name}"
        server_meta[key] = entry
        tools = {tool.lower() for tool in entry.tools}
        server_tools[key] = tools

    toxic_flows: list[list[str]] = []

    # W015 — read on one server + write on another
    readers = [key for key, tools in server_tools.items() if tools & _READ_TOOLS]
    writers = [key for key, tools in server_tools.items() if tools & _WRITE_TOOLS]
    for reader in readers:
        for writer in writers:
            if reader == writer:
                continue
            toxic_flows.append([reader, writer])
            findings.append(
                _finding(
                    "W015",
                    f"Toxic flow W015: read ({reader}) → write ({writer})",
                    "Cross-server read/write capability chain detected.",
                    Severity.HIGH,
                    match=f"{reader} → {writer}",
                    field="cross_server_read_write",
                    evidence={"reader": reader, "writer": writer},
                    id_suffix=f"{reader}-{writer}",
                )
            )

    # W016 — sensitive tool shadowing across servers
    for tool in _SENSITIVE_TOOLS:
        holders = sorted(key for key, tools in server_tools.items() if tool in tools)
        if len(holders) >= 2:
            toxic_flows.append(holders)
            findings.append(
                _finding(
                    "W016",
                    f"Toxic flow W016: sensitive tool shadow `{tool}`",
                    f"Tool `{tool}` is exposed on multiple servers.",
                    Severity.HIGH,
                    match=tool,
                    field="sensitive_tool_shadow",
                    evidence={"tool": tool, "servers": holders},
                    id_suffix=tool,
                )
            )

    # W017 — server with sensitive tools but no auth env keys
    for key, entry in server_meta.items():
        tools = server_tools.get(key, set())
        if tools & _SENSITIVE_TOOLS and not entry.env_keys:
            findings.append(
                _finding(
                    "W017",
                    f"Toxic flow W017: sensitive tools without auth env ({key})",
                    "Server exposes sensitive tools but declares no auth-related env keys.",
                    Severity.MEDIUM,
                    match=key,
                    field="missing_auth_env",
                    evidence={"server": key, "tools": sorted(tools & _SENSITIVE_TOOLS)},
                    id_suffix=key,
                )
            )

    # W018 — duplicate server names across clients
    by_name: dict[str, list[str]] = {}
    for key in server_meta:
        name = key.split("/", 1)[-1]
        by_name.setdefault(name, []).append(key)
    for name, keys in by_name.items():
        if len(keys) >= 2:
            findings.append(
                _finding(
                    "W018",
                    f"Toxic flow W018: duplicate server name `{name}`",
                    "Same server name appears under multiple clients.",
                    Severity.MEDIUM,
                    match=name,
                    field="duplicate_server_name",
                    evidence={"server_name": name, "servers": keys},
                    id_suffix=name,
                )
            )

    # W019 — high tool count spread (agent confusion risk)
    if len(server_tools) >= 3:
        total_tools = sum(len(tools) for tools in server_tools.values())
        if total_tools >= 20:
            findings.append(
                _finding(
                    "W019",
                    "Toxic flow W019: broad multi-server tool surface",
                    f"{total_tools} tools across {len(server_tools)} servers increases agent confusion risk.",
                    Severity.MEDIUM,
                    match=f"{total_tools} tools / {len(server_tools)} servers",
                    field="broad_tool_surface",
                    evidence={"server_count": len(server_tools), "tool_count": total_tools},
                )
            )

    # W020 — minimum hitting set recommendation
    if toxic_flows:
        hitting = minimum_hitting_set(toxic_flows)
        findings.append(
            _finding(
                "W020",
                "Toxic flow W020: minimum server removal set",
                "Disable or isolate these servers to break all detected toxic flows.",
                Severity.MEDIUM,
                match=", ".join(hitting),
                field="minimum_hitting_set",
                evidence={"remove_servers": hitting, "flow_count": len(toxic_flows)},
            )
        )

    return findings


def _finding_id_slug(value: str) -> str:
    return value.replace("/", "-").replace(" ", "-")


def _finding(
    code: str,
    title: str,
    description: str,
    severity: Severity,
    *,
    match: str,
    field: str,
    evidence: dict,
    id_suffix: str | None = None,
) -> Finding:
    payload = {"issue_code": code, **evidence}
    suffix = id_suffix or match
    finding_id = f"toxic-flow-{code.lower()}-{_finding_id_slug(suffix)}"
    return build_analyzer_finding(
        finding_id=finding_id,
        analyzer="toxic_flows",
        title=title,
        description=description,
        severity=severity,
        recommendation="Review cross-server tool exposure and apply server allowlists.",
        rule_id=code,
        match=match,
        field=field,
        technique_id="MCTS-T-1008",
        confidence=0.75,
        extra_evidence=payload,
    )
