"""Meta-findings and CLI helpers for incomplete live MCP discovery."""

from __future__ import annotations

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_live_discovery_finding


def list_failure_warning(operation: str, exc: Exception, stderr_file: str | None) -> str:
    """Build a human-readable warning for a failed MCP list_* call."""
    base = f"{operation} failed: {exc}"
    if stderr_file:
        return f"{base} (server stderr captured in {stderr_file})"
    return f"{base} (re-run with --stderr-file PATH to capture server stderr)"


def discovery_meta_findings(server: MCPServerInfo) -> list[Finding]:
    """Emit a meta-finding when live discovery returned partial server metadata."""
    if not server.discovery_warnings:
        return []

    tools_warning = any(w.startswith("list_tools") for w in server.discovery_warnings)
    if not server.initialize_succeeded:
        severity = Severity.HIGH
        description = (
            "MCP server subprocess never completed the initialize handshake. "
            "Tool metadata was not discovered; use startup diagnostics (--stderr-file) "
            "or fix the server launch command before relying on this scan."
        )
    elif tools_warning:
        severity = Severity.HIGH
        description = (
            "Live MCP discovery completed after initialize, but list_tools failed. "
            "Analyzers may run against incomplete tool metadata and miss security findings."
        )
    else:
        severity = Severity.MEDIUM
        description = (
            "Live MCP discovery completed after initialize, but one or more list_* "
            "operations failed. Analyzers may run against incomplete prompt/resource "
            "metadata and miss security findings."
        )

    return [
        tag_live_discovery_finding(
            build_hygiene_finding(
                finding_id="live-discovery-incomplete",
                analyzer="live_discovery",
                title="Live MCP discovery incomplete",
                description=description,
                severity=severity,
                recommendation=(
                    "Investigate MCP server list_tools/list_prompts/list_resources handlers; "
                    "increase --timeout if needed. Capture server stderr with --stderr-file "
                    "for diagnostics. Use --strict-live in CI to fail the scan when discovery "
                    "is incomplete."
                ),
                rule_id="LIVE-DISCOVERY",
                match=description[:120],
                field="discovery_warnings",
                confidence=1.0,
                extra_evidence={
                    "discovery_mode": server.discovery_mode,
                    "discovery_warnings": list(server.discovery_warnings),
                    "tool_count": len(server.tools),
                    "initialize_succeeded": server.initialize_succeeded,
                },
            )
        )
    ]


def tools_list_failed(warnings: list[str]) -> bool:
    return any(w.startswith("list_tools") for w in warnings)
