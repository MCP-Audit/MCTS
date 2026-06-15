"""YAML governance policies for scan and inventory gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class GovernancePolicy(BaseModel):
    min_score: int | None = Field(default=None, ge=0, le=100)
    min_security_score: int | None = Field(default=None, ge=0, le=100)
    max_absolute_risk: int | None = Field(default=None, ge=0)
    max_risk_level: str | None = Field(default=None)
    min_category_score_v2: dict[str, int] = Field(default_factory=dict)
    max_worst_absolute_risk: int | None = Field(default=None, ge=0)
    max_critical: int | None = Field(default=None, ge=0)
    max_high: int | None = Field(default=None, ge=0)
    fail_on_priority_min: int | None = Field(default=None, ge=0, le=100)
    min_evidence_strength: str | None = None
    enforce_bronze_facts: bool = False
    collapse_template_severity: bool = False
    findings_trust_mode: str | None = None
    allowed_servers: list[str] = Field(default_factory=list)
    blocked_servers: list[str] = Field(default_factory=list)
    require_auth_env_for_sensitive: bool = False

    @field_validator("min_evidence_strength")
    @classmethod
    def _validate_policy_evidence_strength(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from mcts.reporting.trust_gates import normalize_evidence_strength

        return normalize_evidence_strength(value)

    @field_validator("findings_trust_mode")
    @classmethod
    def _validate_policy_trust_mode(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower().strip()
        if normalized not in {"off", "warn", "enforce"}:
            raise ValueError("findings_trust_mode must be off, warn, or enforce")
        return normalized


def load_policy(path: Path | None) -> GovernancePolicy | None:
    if path is None:
        default = Path(".mcts/policy.yaml")
        if default.exists():
            path = default
        else:
            return None
    if not path.exists():
        raise FileNotFoundError(f"Governance policy not found: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Governance policy must be a YAML mapping")
    return GovernancePolicy.model_validate(_normalize(payload))


def evaluate_policy(
    *,
    policy: GovernancePolicy,
    servers: list[str],
) -> list[str]:
    """YAML-only gates not represented on ScanConfig (allowlist/blocklist).

    Numeric thresholds (min_score, max_critical, v2 limits, priority) merge into
    ScanConfig via merge_scan_config_with_policy and are enforced by scan_gates only.
    """
    violations: list[str] = []
    if policy.allowed_servers and not any(server in policy.allowed_servers for server in servers):
        checked = ", ".join(repr(server) for server in servers)
        violations.append(f"scan target not in allowlist (checked: {checked})")
    for server in policy.blocked_servers:
        if server in servers:
            violations.append(f"blocked server present: {server}")
    return violations


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    row = dict(payload)
    if "allowlist" in row and "allowed_servers" not in row:
        row["allowed_servers"] = row.pop("allowlist")
    if "blocklist" in row and "blocked_servers" not in row:
        row["blocked_servers"] = row.pop("blocklist")
    return row


def merge_scan_config_with_policy(config: Any, policy: GovernancePolicy | None) -> Any:
    """Fill unset scan config fields from governance policy (CLI flags take precedence).

    Policy applies when the scan config still holds defaults (e.g. findings_trust_mode=off
    without an explicit CLI choice, optional gates None). Explicit CLI values are never overwritten.
    """
    if policy is None or config.ignore_policy:
        return config

    updates: dict[str, Any] = {}

    if (
        not config.findings_trust_mode_explicit
        and config.findings_trust_mode == "off"
        and policy.findings_trust_mode is not None
    ):
        updates["findings_trust_mode"] = policy.findings_trust_mode

    for field in (
        "min_score",
        "max_critical",
        "max_high",
        "fail_on_priority_min",
        "min_evidence_strength",
        "min_security_score",
        "max_absolute_risk",
        "max_risk_level",
        "max_worst_absolute_risk",
    ):
        policy_value = getattr(policy, field)
        if policy_value is None:
            continue
        if getattr(config, field) is None:
            updates[field] = policy_value

    if not config.min_category_score_v2 and policy.min_category_score_v2:
        updates["min_category_score_v2"] = dict(policy.min_category_score_v2)

    for field in ("enforce_bronze_facts", "collapse_template_severity"):
        if getattr(config, field) is not None:
            continue
        if getattr(policy, field):
            updates[field] = True

    if not config.require_auth_env_for_sensitive and policy.require_auth_env_for_sensitive:
        updates["require_auth_env_for_sensitive"] = True

    if not updates:
        return config

    return config.model_copy(update=updates)
