"""Apply bundled MCTS Sigma rules to tool metadata."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.surface_context import scan_surfaces, surface_location, tool_for_surface, tool_name_for
from mcts.analyzers.surfaces import ScanSurface, ScanSurfaceKind
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity
from mcts.taxonomy.sigma.loader import MetadataSigmaRule, cached_metadata_rules
from mcts.taxonomy.sigma.matcher import is_substantive_pattern, match_sigma_pattern

_LEVEL_TO_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

_TEXT_FIELDS = frozenset({"tool_description", "description", "tool_name", "name"})
_SCHEMA_VALUE_FIELDS = frozenset({"path", "query", "command", "url", "message", "filename", "file"})
_NAME_ONLY_TECHNIQUES = frozenset({"MCTS-T-1020"})
_COMMENT_POISON_MARKERS = (
    "system:",
    "ignore",
    "override",
    "instruction",
    "exfil",
    "bypass",
    "secret",
    "always",
    "never reveal",
    "<|system|>",
    "[inst]",
    "### instruction",
)


class SigmaMetadataAnalyzer(BaseAnalyzer):
    """Match MCTS Sigma metadata patterns against discovered MCP tools."""

    name = "sigma_metadata"

    def __init__(self, sigma_rules_path: Path | None = None) -> None:
        self.sigma_rules_path = sigma_rules_path

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        rules = cached_metadata_rules(self.sigma_rules_path)
        findings: list[Finding] = []
        seen: set[str] = set()

        for surface in scan_surfaces(server):
            corpora = _surface_corpora(surface)
            if surface.kind == ScanSurfaceKind.TOOL:
                tool = tool_for_surface(server, surface)
                if tool:
                    corpora = _merge_corpora(corpora, _tool_corpora(tool))
            for rule in rules:
                for field, pattern in rule.patterns:
                    if not is_substantive_pattern(pattern):
                        continue
                    for corpus_field, text in corpora.get(field, []):
                        if not match_sigma_pattern(text, pattern):
                            continue
                        if corpus_field == "name" and rule.technique_id not in _NAME_ONLY_TECHNIQUES:
                            continue
                        if _benign_html_comment_only(text, pattern):
                            continue
                        finding_id = (
                            f"sigma-{rule.technique_id}-{surface.label}-{rule.rule_id}-{field}-{corpus_field}"
                        )
                        if finding_id in seen:
                            continue
                        seen.add(finding_id)
                        findings.append(
                            build_analyzer_finding(
                                finding_id=finding_id,
                                analyzer=self.name,
                                title=f"Sigma rule match on {surface.label}: {rule.title}",
                                description=(
                                    f"MCTS Sigma pattern matched in {corpus_field} ({rule.technique_id})."
                                ),
                                severity=_LEVEL_TO_SEVERITY.get(rule.level.lower(), Severity.MEDIUM),
                                recommendation=(
                                    "Review matched metadata against MCTS guidance and "
                                    "sanitize MCP surface definitions before deployment."
                                ),
                                rule_id=rule.rule_id,
                                match=pattern,
                                field=field,
                                tool=tool_name_for(surface),
                                location=surface_location(surface),
                                technique_id=rule.technique_id,
                                confidence=0.8,
                                snippet=text[:200] if text else None,
                                extra_evidence={
                                    "sigma_rule_id": rule.rule_id,
                                    "sigma_field": field,
                                    "sigma_pattern": pattern,
                                    "corpus_field": corpus_field,
                                    "surface": surface.kind.value,
                                    "attack_tags": _attack_tags(rule),
                                },
                            )
                        )
        return findings


def _merge_corpora(
    left: dict[str, list[tuple[str, str]]],
    right: dict[str, list[tuple[str, str]]],
) -> dict[str, list[tuple[str, str]]]:
    merged = {key: list(values) for key, values in left.items()}
    for key, values in right.items():
        merged.setdefault(key, []).extend(values)
    return merged


def _surface_corpora(surface: ScanSurface) -> dict[str, list[tuple[str, str]]]:
    corpora: dict[str, list[tuple[str, str]]] = {
        "tool_description": [("description", surface.description)],
        "description": [("description", surface.description)],
        "tool_name": [("name", surface.name)],
        "name": [("name", surface.name)],
    }
    if surface.extra_text:
        corpora.setdefault("description", []).append(("extra", surface.extra_text))
    if surface.uri:
        corpora["url"] = [("uri", surface.uri)]
        corpora["path"] = [("uri", surface.uri)]
    return corpora


def _tool_corpora(tool: MCPTool) -> dict[str, list[tuple[str, str]]]:
    corpora: dict[str, list[tuple[str, str]]] = {
        "tool_description": [("description", tool.description)],
        "description": [("description", tool.description)],
        "tool_name": [("name", tool.name)],
        "name": [("name", tool.name)],
    }
    schema_strings = _schema_strings(tool.input_schema)
    for field in _SCHEMA_VALUE_FIELDS:
        corpora[field] = [(label, value) for label, value in schema_strings]
    return corpora


def _schema_strings(schema: Any, prefix: str = "inputSchema") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if isinstance(schema, dict):
        for key in ("default", "description", "title", "pattern", "const"):
            value = schema.get(key)
            if isinstance(value, str) and value:
                rows.append((f"{prefix}.{key}", value))
        for prop_name, prop_schema in schema.get("properties", {}).items():
            if isinstance(prop_schema, dict):
                rows.extend(_schema_strings(prop_schema, f"{prefix}.properties.{prop_name}"))
        for index, enum_val in enumerate(schema.get("enum", [])):
            if isinstance(enum_val, str):
                rows.append((f"{prefix}.enum[{index}]", enum_val))
    elif isinstance(schema, list):
        for index, item in enumerate(schema):
            rows.extend(_schema_strings(item, f"{prefix}[{index}]"))
    return rows


def _benign_html_comment_only(text: str, pattern: str) -> bool:
    """Skip Sigma hits where the only match is a non-malicious HTML comment."""
    if "<!--" not in text:
        return False
    core = pattern.replace("*", "").strip().lower()
    if core not in {"<!--", "<!-- "}:
        return False
    comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL | re.IGNORECASE)
    if not comments:
        return False
    for body in comments:
        lowered = body.lower()
        if any(marker in lowered for marker in _COMMENT_POISON_MARKERS):
            return False
    return True


def _attack_tags(rule: MetadataSigmaRule) -> list[str]:
    tags: list[str] = []
    for tag in rule.tags:
        if tag.startswith("attack."):
            tags.append(tag)
    return tags
