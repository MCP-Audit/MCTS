"""Scan configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

DEFAULT_EXCLUDE_DIRS = (
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
)

DEFAULT_SURFACES = ["tool", "prompt", "resource", "instruction"]


class ScanConfig(BaseModel):
    """Configuration for a MCTS security scan."""

    target: Path
    output: Path | None = None
    output_format: str = "json"
    terminal_format: str | None = None
    fail_on_critical: bool = False
    min_score: int | None = Field(default=None, ge=0, le=100)
    max_critical: int | None = Field(default=None, ge=0)
    max_high: int | None = Field(default=None, ge=0)
    enable_jailbreak: bool = True
    enable_attack_chains: bool = True
    timeout_seconds: int = Field(default=120, ge=1)
    theme: str = "cyber"
    no_progress: bool = False
    include_globs: list[str] = Field(default_factory=lambda: ["**/*.py"])
    exclude_globs: list[str] = Field(default_factory=list)
    exclude_dirs: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    max_file_bytes: int = Field(default=500_000, ge=1)
    live: bool = False
    live_command: str | None = None
    live_args: list[str] = Field(default_factory=list)
    live_env: dict[str, str] = Field(default_factory=dict)
    config_path: Path | None = None
    config_server: str | None = None
    live_consent: bool = False
    merge_static_live: bool = True
    fuzz_level: str = "safe"
    fuzz_consent: bool = False
    languages: list[str] = Field(default_factory=lambda: ["python", "typescript"])
    sigma_rules_path: Path | None = None
    baseline_path: Path | None = None
    save_baseline_path: Path | None = None
    semantic_secrets: bool = False
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
    behavioral_probe: bool = False
    enable_jailbreak_live: bool = False
    fail_on_category: dict[str, int] = Field(default_factory=dict)
    # P0 — multi-surface + remote transport
    surfaces: list[str] = Field(default_factory=lambda: list(DEFAULT_SURFACES))
    resource_mime_allowlist: list[str] = Field(default_factory=list)
    remote_url: str | None = None
    remote_transport: str = "streamable-http"
    bearer_token: str | None = None
    remote_headers: dict[str, str] = Field(default_factory=dict)
    oauth_token_url: str | None = None
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    oauth_scopes: str | None = None
    protocol_probe: bool = False
    stderr_file: str | None = None
    strict_live: bool = False
    strict_discovery: bool = False
    expand_vars: str = "auto"
    # P1 — static snapshot + supply chain
    snapshot_path: Path | None = None
    snapshot_tools: Path | None = None
    snapshot_prompts: Path | None = None
    snapshot_resources: Path | None = None
    snapshot_instructions: Path | None = None
    pip_audit: bool = False
    npm_audit: bool = False
    # P2 — optional analyzers
    enable_yara: bool = False
    yara_rules_path: Path | None = None
    enable_llm_judge: bool = False
    enable_llm_triage: bool = False
    llm_model: str | None = None
    enable_semgrep: bool = False
    semgrep_rules_path: Path | None = None
    enable_cloud_inspect: bool = False
    cloud_endpoint: str | None = None
    enable_prompt_defense: bool = True
    enable_behavioral_static: bool = True
    enable_surface_metadata: bool = True
    enable_virustotal: bool = False
    vt_max_files: int = 10
    # Filters
    tool_filter: list[str] = Field(default_factory=list)
    analyzer_filter: list[str] = Field(default_factory=list)
    severity_filter: list[str] = Field(default_factory=list)
    hide_safe: bool = False
    analyzers: list[str] = Field(default_factory=list)
    readiness_opa: bool = False
    readiness_opa_policies: Path | None = None
    readiness_llm: bool = False
    readiness_llm_model: str | None = None
    raw_envelope: bool = False
    auto: bool = False
    auto_server: str | None = None
    auto_html: Path | None = None
    technique_filter: list[str] = Field(default_factory=list)
    full_toxic_flows: bool = False
    governance_policy: Path | None = None
    ci_preset: bool = False
    discover_instructions: bool = True
    instruction_globs: list[str] = Field(default_factory=list)
    instruction_files: list[Path] = Field(default_factory=list)
    skills_dirs: list[Path] = Field(default_factory=list)
    surface_scoped_analyzers: bool = True
    scoring_mode: str = "both"
    weights_profile: str = "manual_v1"
    corpus_stats_path: Path | None = None
    assets_path: Path | None = None
    min_security_score: int | None = Field(default=None, ge=0, le=100)
    max_absolute_risk: int | None = Field(default=None, ge=0)
    max_risk_level: str | None = None
    min_category_score_v2: dict[str, int] = Field(default_factory=dict)
    max_worst_absolute_risk: int | None = Field(default=None, ge=0)
    findings_trust_mode: str = "off"
    findings_trust_mode_explicit: bool = False
    ignore_policy: bool = False
    fail_on_priority_min: int | None = Field(default=None, ge=0, le=100)
    min_evidence_strength: str | None = None
    enforce_bronze_facts: bool | None = None
    collapse_template_severity: bool | None = None
    require_auth_env_for_sensitive: bool = False
    max_json_findings: int | None = Field(
        default=None,
        ge=1,
        description="Truncate JSON report findings to this count (scan_notes records truncation)",
    )

    @classmethod
    def _validate_min_evidence_strength(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from mcts.reporting.trust_gates import normalize_evidence_strength

        return normalize_evidence_strength(value)

    @field_validator("findings_trust_mode")
    @classmethod
    def _validate_findings_trust_mode(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"off", "warn", "enforce"}:
            raise ValueError("findings_trust_mode must be off, warn, or enforce")
        return normalized

    @field_validator("scoring_mode")
    @classmethod
    def _validate_scoring_mode(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"legacy", "v2", "both"}:
            raise ValueError("scoring_mode must be legacy, v2, or both")
        return normalized
