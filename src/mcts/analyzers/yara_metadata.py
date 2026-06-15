"""YARA pattern matching on MCP metadata (optional yara-python)."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding, build_skip_finding
from mcts.analyzers.surface_context import scan_surfaces
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

_DEFAULT_RULES_DIR = Path(__file__).resolve().parents[1] / "taxonomy" / "yara"

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class YaraMetadataAnalyzer(BaseAnalyzer):
    """Match YARA rules against MCP surface text."""

    name = "yara_metadata"

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path
        self._rules = None

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        rules = self._load_rules()
        if rules is None:
            return [
                build_skip_finding(
                    finding_id="yara-skipped",
                    analyzer=self.name,
                    title="YARA analysis skipped",
                    description="yara-python or packaged rule files are unavailable",
                    recommendation="Install the yara extra (`uv sync --extra yara`) or pass --yara-rules.",
                )
            ]
        findings: list[Finding] = []
        for surface in scan_surfaces(server):
            text = surface.all_text()
            if not text.strip():
                continue
            for match in rules.match(data=text.encode("utf-8", errors="replace")):
                meta = match.meta or {}
                severity = _SEVERITY_MAP.get(str(meta.get("severity", "MEDIUM")).upper(), Severity.MEDIUM)
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"yara-{match.rule}-{surface.label}",
                        analyzer=self.name,
                        title=f"YARA match '{match.rule}' on {surface.label}",
                        description=str(meta.get("description") or match.rule),
                        severity=severity,
                        recommendation="Review matched MCP metadata for malicious patterns.",
                        rule_id=match.rule,
                        match=match.rule,
                        field="mcp_surface",
                        tool=surface.name if surface.kind.value == "tool" else None,
                        technique_id="MCTS-T-1010",
                        confidence=0.9,
                        snippet=str(meta.get("description") or match.rule),
                        extra_evidence={
                            "surface": surface.kind.value,
                            "strings": [str(s) for s in match.strings[:3]],
                        },
                    )
                )
        return findings

    def _load_rules(self):
        if self._rules is not None:
            return self._rules
        try:
            import yara  # type: ignore[import-untyped]
        except ImportError:
            return None
        rule_dir = self.rules_path or _DEFAULT_RULES_DIR
        if not rule_dir.exists():
            return None
        sources = {path.stem: path.read_text(encoding="utf-8") for path in rule_dir.glob("*.yar*")}
        if not sources:
            return None
        self._rules = yara.compile(sources=sources)
        return self._rules
