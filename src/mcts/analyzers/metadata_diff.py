"""Tool metadata baseline comparison (rug pull / persistent redefinition)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation


class MetadataDiffAnalyzer(BaseAnalyzer):
    """Compare current tool metadata against a saved baseline snapshot."""

    name = "metadata_diff"

    def __init__(self, baseline_path: Path | None = None) -> None:
        self.baseline_path = baseline_path

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        if self.baseline_path is None or not self.baseline_path.exists():
            return []

        baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        baseline_tools: dict[str, dict[str, Any]] = baseline.get("tools", {})
        findings: list[Finding] = []

        current = {tool.name: _tool_snapshot(tool) for tool in server.tools}

        for name, snap in current.items():
            if name not in baseline_tools:
                continue
            previous = baseline_tools[name]
            if previous.get("hash") == snap["hash"]:
                continue

            changed_fields = [
                field for field in ("description", "input_schema") if previous.get(field) != snap.get(field)
            ]
            if not changed_fields:
                continue

            findings.append(
                build_analyzer_finding(
                    finding_id=f"meta-diff-{name}",
                    analyzer=self.name,
                    title=f"Tool metadata changed since baseline: {name}",
                    description=(
                        f"Tool '{name}' differs from baseline ({', '.join(changed_fields)}). "
                        "Possible rug pull or persistent tool redefinition."
                    ),
                    severity=Severity.CRITICAL,
                    recommendation=(
                        "Pin tool manifests cryptographically (MCTS-M-002); reject metadata "
                        "changes without explicit operator approval."
                    ),
                    rule_id="RULE_METADATA_DIFF",
                    match=name,
                    field="tool_metadata",
                    tool=name,
                    location=SourceLocation(
                        file=snap.get("source_file") or "",
                        line=snap.get("source_line"),
                    ),
                    technique_id="MCTS-T-1013",
                    confidence=0.9,
                    extra_evidence={
                        "changed_fields": changed_fields,
                        "baseline_hash": previous.get("hash"),
                        "current_hash": snap["hash"],
                        "attack_tags": ["attack.persistence", "attack.t1556"],
                    },
                )
            )

        for name in baseline_tools:
            if name not in current:
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"meta-removed-{name}",
                        analyzer=self.name,
                        title=f"Baseline tool removed: {name}",
                        description=f"Tool '{name}' existed in baseline but is missing from current scan.",
                        severity=Severity.MEDIUM,
                        recommendation=(
                            "Verify tool removal was intentional; monitor for shadow replacements."
                        ),
                        rule_id="RULE_METADATA_REMOVED",
                        match=name,
                        field="tool_metadata",
                        tool=name,
                        technique_id="MCTS-T-1040",
                        confidence=0.9,
                    )
                )

        return findings


def save_baseline(server: MCPServerInfo, path: Path, *, target: str) -> None:
    payload = {
        "target": target,
        "tools": {tool.name: _tool_snapshot(tool) for tool in server.tools},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _tool_snapshot(tool: MCPTool) -> dict[str, Any]:
    description = tool.description
    schema = tool.input_schema
    digest = hashlib.sha256(
        json.dumps({"description": description, "input_schema": schema}, sort_keys=True).encode()
    ).hexdigest()
    return {
        "description": description,
        "input_schema": schema,
        "source_file": tool.source_file,
        "source_line": tool.source_line,
        "hash": digest,
    }
