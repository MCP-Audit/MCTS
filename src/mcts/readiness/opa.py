"""Optional OPA policy evaluation for readiness checks."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.reporting.models import Severity

_DEFAULT_POLICIES = Path(__file__).resolve().parent / "policies"
_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OpaProvider:
    """Evaluate bundled Rego policies when the opa CLI is available."""

    def __init__(self, policies_dir: Path | None = None) -> None:
        self.policies_dir = policies_dir or _DEFAULT_POLICIES
        self._opa_path = shutil.which("opa")

    def is_available(self) -> bool:
        return self._opa_path is not None and self.policies_dir.exists()

    def evaluate_tool(self, tool_def: dict[str, Any], tool_name: str) -> list:
        if not self.is_available():
            return []
        facts = _create_tool_facts(tool_def, tool_name)
        findings: list = []
        for policy_path in sorted(self.policies_dir.glob("*.rego")):
            for violation in _run_opa(self._opa_path or "opa", policy_path, facts):
                raw_severity = str(violation.get("severity", "MEDIUM")).upper()
                severity = _SEVERITY_MAP.get(raw_severity, Severity.MEDIUM)
                policy = str(violation.get("policy", "unknown"))
                message = str(violation.get("message", "OPA policy violation"))
                findings.append(
                    build_hygiene_finding(
                        finding_id=f"readiness-opa-{policy}-{tool_name}",
                        analyzer="readiness",
                        title=f"OPA: {message} ({tool_name})",
                        description=message,
                        severity=severity,
                        recommendation="Fix tool definition to satisfy readiness Rego policy.",
                        rule_id=f"OPA-{policy}",
                        match=message,
                        field="opa_policy",
                        tool=tool_name,
                        confidence=0.8,
                        extra_evidence={
                            "readiness_rule": f"OPA-{policy}",
                            "policy": policy,
                            "source": "opa",
                            "category": violation.get("category"),
                        },
                    )
                )
        return findings


def _create_tool_facts(tool_definition: dict[str, Any], tool_name: str) -> dict[str, Any]:
    timeout_fields = ("timeout", "timeoutMs", "timeout_ms", "timeoutSeconds")
    timeout_value = None
    has_timeout = False
    config = tool_definition.get("config", {})
    for field in timeout_fields:
        if field in tool_definition:
            has_timeout = True
            timeout_value = tool_definition[field]
            break
        if isinstance(config, dict) and field in config:
            has_timeout = True
            timeout_value = config[field]
            break

    retry_fields = ("retries", "maxRetries", "max_retries", "retryLimit", "retry_limit")
    retry_value = None
    has_retry_limit = False
    for field in retry_fields:
        if field in tool_definition:
            has_retry_limit = True
            retry_value = tool_definition[field]
            break
        if isinstance(config, dict) and field in config:
            has_retry_limit = True
            retry_value = config[field]
            break

    capabilities = tool_definition.get("capabilities", [])
    capabilities_count = len(capabilities) if isinstance(capabilities, list) else 0
    error_schema_fields = ("errorSchema", "error_schema", "errors", "errorResponse")
    has_error_schema = any(field in tool_definition for field in error_schema_fields)
    input_schema = tool_definition.get("inputSchema", {})
    has_input_schema = bool(input_schema) and isinstance(input_schema, dict)
    input_properties_count = len(input_schema.get("properties", {})) if has_input_schema else 0
    has_required_fields = "required" in input_schema if has_input_schema else False
    description = tool_definition.get("description", "")
    rate_limit_fields = ("rateLimit", "rate_limit", "throttle", "rateLimitPerMinute")
    has_rate_limit = any(field in tool_definition for field in rate_limit_fields)

    return {
        "type": "tool",
        "tool_name": tool_name,
        "has_timeout": has_timeout,
        "timeout_value": timeout_value,
        "has_retry_limit": has_retry_limit,
        "retry_limit": retry_value,
        "capabilities_count": capabilities_count,
        "has_error_schema": has_error_schema,
        "has_input_schema": has_input_schema,
        "input_properties_count": input_properties_count,
        "has_required_fields": has_required_fields,
        "has_description": bool(description),
        "description_length": len(description),
        "has_rate_limit": has_rate_limit,
        "raw": tool_definition,
    }


def _run_opa(opa_path: str, policy_path: Path, facts: dict[str, Any]) -> list[dict[str, Any]]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
        json.dump(facts, handle)
        input_path = handle.name
    try:
        proc = subprocess.run(
            [
                opa_path,
                "eval",
                "--input",
                input_path,
                "--data",
                str(policy_path),
                "--format",
                "json",
                "data.mcp.readiness.violation",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    finally:
        Path(input_path).unlink(missing_ok=True)

    if proc.returncode != 0:
        return []
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []

    violations: list[dict[str, Any]] = []
    for expr in payload.get("result", []):
        value = expr.get("value", [])
        if isinstance(value, list):
            for msg in value:
                violations.append(_enrich_violation(msg, policy_path.stem))
        elif isinstance(value, str):
            violations.append(_enrich_violation(value, policy_path.stem))
    return violations


def _enrich_violation(message: Any, policy: str) -> dict[str, Any]:
    text = message if isinstance(message, str) else str(message)
    lowered = text.lower()
    if "must" in lowered or "required" in lowered:
        severity = "HIGH"
    elif "should" in lowered or "recommended" in lowered:
        severity = "MEDIUM"
    elif "consider" in lowered or "may" in lowered:
        severity = "LOW"
    else:
        severity = "MEDIUM"
    return {
        "message": text,
        "policy": policy,
        "severity": severity,
        "category": "SILENT_FAILURE_PATH",
        "rule_id": f"OPA-{policy}",
    }
