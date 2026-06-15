"""Optional cloud ML inspection (Cisco AI Defense-compatible API)."""

from __future__ import annotations

import os

import httpx

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding, build_skip_finding
from mcts.analyzers.surface_context import scan_surfaces
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity


class CloudInspectAnalyzer(BaseAnalyzer):
    """POST MCP artifact text to a cloud inspect API (opt-in)."""

    name = "cloud_inspect"

    def __init__(self, endpoint: str | None = None) -> None:
        self.endpoint = endpoint or os.environ.get(
            "MCTS_CLOUD_ENDPOINT", "https://api.us.ai-defense.cisco.com/inspect/chat"
        )

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        api_key = os.environ.get("MCTS_CLOUD_API_KEY")
        if not api_key:
            return [
                build_skip_finding(
                    finding_id="cloud-inspect-skipped",
                    analyzer=self.name,
                    title="Cloud inspect skipped",
                    description="MCTS_CLOUD_API_KEY is not set",
                    recommendation="Export MCTS_CLOUD_API_KEY or disable --enable-cloud-inspect.",
                )
            ]
        findings: list[Finding] = []
        headers = {
            "Content-Type": "application/json",
            "X-Cisco-AI-Defense-API-Key": api_key,
        }
        for surface in scan_surfaces(server):
            text = surface.all_text()[:8000]
            if len(text) < 10:
                continue
            payload = {
                "messages": [{"role": "user", "content": text}],
                "config": {"enabled_rules": ["Prompt Injection", "Code Detection"]},
            }
            try:
                resp = httpx.post(self.endpoint, json=payload, headers=headers, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError):
                continue
            for rule in _triggered_rules(data):
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"cloud-{rule['id']}-{surface.label}",
                        analyzer=self.name,
                        title=f"Cloud inspect: {rule['name']} on {surface.label}",
                        description=rule.get("description", rule["name"]),
                        severity=_map_severity(rule.get("severity", "medium")),
                        recommendation="Review cloud-flagged MCP content.",
                        rule_id=f"RULE_CLOUD_{rule['id']}",
                        match=rule["name"],
                        field="mcp_surface",
                        tool=surface.name if surface.kind.value == "tool" else None,
                        technique_id="MCTS-T-1001",
                        confidence=0.75,
                        extra_evidence={"surface": surface.kind.value, "rule": rule["name"]},
                    )
                )
        return findings


def _triggered_rules(data: dict) -> list[dict]:
    rows: list[dict] = []
    for key in ("rules", "triggered_rules", "results"):
        block = data.get(key)
        if isinstance(block, list):
            for item in block:
                if isinstance(item, dict) and item.get("triggered", True):
                    rows.append(
                        {
                            "id": item.get("id") or item.get("name") or "rule",
                            "name": str(item.get("name") or item.get("rule") or "rule"),
                            "description": str(item.get("description") or ""),
                            "severity": item.get("severity") or "medium",
                        }
                    )
    return rows


def _map_severity(raw: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(str(raw).lower(), Severity.MEDIUM)
