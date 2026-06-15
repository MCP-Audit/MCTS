"""Meta-findings for incomplete static MCP discovery."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.discovery.language_detect import RUST_MCP_INDICATORS, detect_repo_languages
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_static_discovery_finding


def static_discovery_meta_findings(server: MCPServerInfo, config: ScanConfig) -> list[Finding]:
    """Emit findings when static discovery likely missed MCP tools."""
    if server.tools:
        return []
    if config.live or config.remote_url or config.snapshot_path:
        return []

    target = ScanTarget(config.target)
    if target.kind != TargetKind.DIRECTORY:
        return []

    langs = {language.lower() for language in config.languages}
    detected = detect_repo_languages(target.path, exclude_dirs=frozenset(config.exclude_dirs))
    rust_sources = _rust_mcp_sources_present(target.path, config.exclude_dirs)

    if rust_sources and ("rust" in langs or "rs" in langs):
        return [
            tag_static_discovery_finding(
                build_hygiene_finding(
                    finding_id="static-discovery-rust-incomplete",
                    analyzer="static_discovery",
                    title="Rust MCP sources found but no tools discovered",
                    description=(
                        "The repository contains Rust MCP indicators but static discovery "
                        "returned zero tools. Handler analysis and behavioral SAST did not run."
                    ),
                    severity=Severity.HIGH,
                    recommendation=(
                        "Verify rmcp #[tool] registration patterns are supported, pass "
                        "--languages rust, or use --live --i-understand-live-risk for live discovery."
                    ),
                    rule_id="STATIC-RUST",
                    match="rust indicators without tools",
                    field="static_discovery",
                    technique_id="MCTS-T-1001",
                    confidence=0.9,
                    extra_evidence={
                        "languages": sorted(langs),
                        "detected_languages": sorted(detected),
                        "discovery_mode": server.discovery_mode,
                    },
                )
            )
        ]

    if detected & langs:
        return [
            tag_static_discovery_finding(
                build_hygiene_finding(
                    finding_id="static-discovery-incomplete",
                    analyzer="static_discovery",
                    title="Static MCP tool discovery returned zero tools",
                    description=(
                        "MCP source indicators were found for enabled languages but no tools "
                        "were discovered. Security analysis may be incomplete."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation=(
                        "Use --live --i-understand-live-risk, export a tools/list snapshot, "
                        "or verify static discovery supports your SDK registration patterns."
                    ),
                    rule_id="STATIC-ZERO",
                    match="zero tools discovered",
                    field="static_discovery",
                    confidence=0.8,
                    extra_evidence={
                        "languages": sorted(langs),
                        "detected_languages": sorted(detected),
                        "discovery_mode": server.discovery_mode,
                    },
                )
            )
        ]
    return []


def _rust_mcp_sources_present(root: Path, exclude_dirs: list[str]) -> bool:
    skip = frozenset(exclude_dirs)
    for path in root.rglob("*.rs"):
        rel_parts = path.relative_to(root).parts
        if set(rel_parts) & skip:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(indicator in content for indicator in RUST_MCP_INDICATORS):
            return True
    return False
