"""HEUR-001 through HEUR-020 production readiness checks for MCP tools."""

# ruff: noqa: E501

from __future__ import annotations

from typing import Any

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.mcp.models import MCPTool
from mcts.reporting.models import Finding, Severity

_MIN_DESCRIPTION_LENGTH = 20
_MAX_TIMEOUT_MS = 300_000


def check_tool_readiness(tool: MCPTool) -> list[Finding]:
    """Run all 20 heuristic readiness rules on an MCP tool."""
    tool_def = _tool_def(tool)
    name = tool.name
    findings: list[Finding] = []
    findings.extend(_check_missing_timeout(tool_def, name))
    findings.extend(_check_timeout_too_long(tool_def, name))
    findings.extend(_check_no_retry_limit(tool_def, name))
    findings.extend(_check_unlimited_retries(tool_def, name))
    findings.extend(_check_no_backoff_strategy(tool_def, name))
    findings.extend(_check_missing_error_schema(tool_def, name))
    findings.extend(_check_error_schema_missing_code(tool_def, name))
    findings.extend(_check_no_output_schema(tool_def, name))
    findings.extend(_check_vague_description(tool_def, name))
    findings.extend(_check_too_many_capabilities(tool_def, name))
    findings.extend(_check_no_required_fields(tool_def, name))
    findings.extend(_check_no_input_validation_hints(tool_def, name))
    findings.extend(_check_no_rate_limit(tool_def, name))
    findings.extend(_check_no_version(tool_def, name))
    findings.extend(_check_no_observability(tool_def, name))
    findings.extend(_check_resource_cleanup_not_documented(tool_def, name))
    findings.extend(_check_no_idempotency_indication(tool_def, name))
    findings.extend(_check_dangerous_operation_keywords(tool_def, name))
    findings.extend(_check_no_authentication_context(tool_def, name))
    findings.extend(_check_circular_dependency_risk(tool_def, name))
    return findings


def readiness_score(findings: list[Finding], *, use_display: bool = False) -> int:
    from mcts.reporting.display import effective_severity

    deductions = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
    }
    score = 100
    for finding in findings:
        severity = effective_severity(finding) if use_display else finding.severity
        score -= deductions.get(severity, 0)
    return max(0, score)


def _tool_def(tool: MCPTool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
    }


def _finding(tool_name: str, rule_id: str, title: str, severity: Severity, **evidence: Any) -> Finding:
    return build_hygiene_finding(
        finding_id=f"readiness-{rule_id.lower()}-{tool_name}",
        analyzer="readiness",
        title=f"{title} ({tool_name})",
        description=title,
        severity=severity,
        recommendation="Improve MCP tool operational documentation and configuration.",
        rule_id=rule_id.upper(),
        match=title,
        field="tool_metadata",
        tool=tool_name,
        extra_evidence={"readiness_rule": rule_id.upper(), **evidence},
    )


def _config(tool_def: dict[str, Any]) -> dict[str, Any]:
    config = tool_def.get("config")
    return config if isinstance(config, dict) else {}


def _check_missing_timeout(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("timeout", "timeoutMs", "timeout_ms", "timeoutSeconds")
    config = _config(tool_def)
    if any(field in tool_def or field in config for field in fields):
        return []
    return [
        _finding(
            tool_name,
            "HEUR-001",
            "Missing timeout configuration",
            Severity.HIGH,
            category="MISSING_TIMEOUT_GUARD",
        )
    ]


def _check_timeout_too_long(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    config = _config(tool_def)
    for field in ("timeout", "timeoutMs", "timeout_ms"):
        value = tool_def.get(field) or config.get(field)
        if value is not None and value > _MAX_TIMEOUT_MS:
            findings.append(
                _finding(
                    tool_name,
                    "HEUR-002",
                    f"Timeout {field}={value}ms exceeds 5 minutes",
                    Severity.MEDIUM,
                    field=field,
                    value=value,
                )
            )
    return findings


def _check_no_retry_limit(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("maxRetries", "retries", "max_retries", "retryCount", "retryLimit", "retry_limit")
    config = _config(tool_def)
    retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy")
    has_retries = any(field in tool_def or field in config for field in fields)
    if isinstance(retry_policy, dict):
        has_retries = has_retries or any(field in retry_policy for field in fields)
    if has_retries:
        return []
    return [
        _finding(
            tool_name,
            "HEUR-003",
            "No retry limit configured",
            Severity.MEDIUM,
            category="UNSAFE_RETRY_LOOP",
        )
    ]


def _check_unlimited_retries(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    fields = ("maxRetries", "retries", "max_retries", "retryLimit")
    config = _config(tool_def)
    retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy") or {}
    for field in fields:
        value = tool_def.get(field) or config.get(field)
        if isinstance(retry_policy, dict):
            value = value or retry_policy.get(field)
        if value == -1:
            findings.append(
                _finding(tool_name, "HEUR-004", "Unlimited retries configured", Severity.HIGH, value=value)
            )
        elif value is not None and value > 10:
            findings.append(
                _finding(
                    tool_name,
                    "HEUR-004",
                    f"Retry limit {value} is very high",
                    Severity.HIGH,
                    value=value,
                )
            )
    return findings


def _check_no_backoff_strategy(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    retry_fields = ("maxRetries", "retries", "max_retries", "retryLimit")
    config = _config(tool_def)
    retry_policy = tool_def.get("retryPolicy") or config.get("retryPolicy") or {}
    has_retries = any(
        tool_def.get(field)
        or config.get(field)
        or (retry_policy.get(field) if isinstance(retry_policy, dict) else None)
        for field in retry_fields
    )
    if not has_retries:
        return []
    backoff_fields = (
        "backoff",
        "backoffMs",
        "exponentialBackoff",
        "backoffStrategy",
        "retryDelay",
        "retryBackoff",
    )
    has_backoff = any(field in tool_def or field in config for field in backoff_fields)
    if isinstance(retry_policy, dict):
        has_backoff = has_backoff or any(field in retry_policy for field in backoff_fields)
    if has_backoff:
        return []
    return [_finding(tool_name, "HEUR-005", "Retry logic without backoff strategy", Severity.LOW)]


def _check_missing_error_schema(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("errorSchema", "error_schema", "errors", "errorResponse")
    if any(field in tool_def for field in fields):
        return []
    return [_finding(tool_name, "HEUR-006", "Missing error response schema", Severity.MEDIUM)]


def _check_error_schema_missing_code(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    for field in ("errorSchema", "error_schema", "errors", "errorResponse"):
        schema = tool_def.get(field)
        if isinstance(schema, dict):
            props = schema.get("properties", {})
            if "code" not in props and "errorCode" not in props:
                return [
                    _finding(
                        tool_name,
                        "HEUR-007",
                        "Error schema missing code/errorCode property",
                        Severity.LOW,
                    )
                ]
            break
    return []


def _check_no_output_schema(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("outputSchema", "output_schema", "responseSchema", "response_schema")
    if any(field in tool_def for field in fields):
        return []
    return [_finding(tool_name, "HEUR-008", "Missing output schema", Severity.LOW)]


def _check_vague_description(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    description = tool_def.get("description", "")
    if not description:
        return [_finding(tool_name, "HEUR-009", "Missing tool description", Severity.MEDIUM)]
    if len(description) < _MIN_DESCRIPTION_LENGTH:
        return [
            _finding(
                tool_name,
                "HEUR-009",
                f"Description too short ({len(description)} chars)",
                Severity.MEDIUM,
                length=len(description),
            )
        ]
    generic = {"tool", "utility", "helper", "function", "method"}
    words = description.lower().split()
    if len([w for w in words if w not in generic]) < 3:
        return [_finding(tool_name, "HEUR-009", "Description uses only generic terms", Severity.MEDIUM)]
    return []


def _check_too_many_capabilities(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    description = tool_def.get("description", "").lower()
    overload = [kw for kw in ("any", "all", "everything", "anything", "whatever") if kw in description]
    if overload:
        findings.append(
            _finding(
                tool_name,
                "HEUR-010",
                f"Scope-overload keywords: {', '.join(overload)}",
                Severity.HIGH,
                keywords=overload,
            )
        )
    verbs = (
        "create",
        "read",
        "write",
        "update",
        "delete",
        "get",
        "set",
        "fetch",
        "send",
        "post",
        "put",
        "patch",
        "remove",
        "add",
        "list",
        "find",
        "search",
        "query",
        "execute",
        "run",
        "start",
        "stop",
        "restart",
        "pause",
        "resume",
        "cancel",
        "retry",
    )
    found = [verb for verb in verbs if verb in description]
    if len(found) > 5:
        findings.append(
            _finding(
                tool_name,
                "HEUR-010",
                f"Description mentions {len(found)} action verbs",
                Severity.HIGH,
                verbs=found,
            )
        )
    return findings


def _check_no_required_fields(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    schema = tool_def.get("inputSchema")
    if isinstance(schema, dict):
        props = schema.get("properties", {})
        if props and not schema.get("required"):
            return [_finding(tool_name, "HEUR-011", "Input schema has no required fields", Severity.LOW)]
    return []


def _check_no_input_validation_hints(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    schema = tool_def.get("inputSchema")
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties", {})
    if not props:
        return []
    keywords = (
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "format",
        "minItems",
        "maxItems",
    )
    missing = [
        name
        for name, prop in props.items()
        if isinstance(prop, dict) and not any(kw in prop for kw in keywords)
    ]
    if missing and len(missing) >= len(props) * 0.5:
        return [
            _finding(
                tool_name,
                "HEUR-012",
                f"{len(missing)} input properties lack validation constraints",
                Severity.LOW,
                properties=missing[:5],
            )
        ]
    return []


def _check_no_rate_limit(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("rateLimit", "rate_limit", "rateLimitPerMinute", "throttle", "maxCallsPerSecond")
    config = _config(tool_def)
    if any(field in tool_def or field in config for field in fields):
        return []
    return [_finding(tool_name, "HEUR-013", "No rate limit configured", Severity.LOW)]


def _check_no_version(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = ("version", "apiVersion", "api_version", "schemaVersion")
    if any(field in tool_def for field in fields):
        return []
    return [_finding(tool_name, "HEUR-014", "No version information", Severity.LOW)]


def _check_no_observability(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    fields = (
        "observability",
        "logging",
        "metrics",
        "telemetry",
        "tracing",
        "monitoring",
        "instrumentation",
        "logger",
    )
    config = _config(tool_def)
    if any(field in tool_def or field in config for field in fields):
        return []
    return [_finding(tool_name, "HEUR-015", "No observability configuration", Severity.LOW)]


def _check_resource_cleanup_not_documented(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    description = tool_def.get("description", "").lower()
    resources = (
        "connection",
        "file",
        "stream",
        "socket",
        "handle",
        "session",
        "lock",
        "transaction",
        "database",
        "network",
    )
    found = [item for item in resources if item in description]
    if not found:
        return []
    cleanup = ("close", "cleanup", "release", "dispose", "free", "disconnect")
    if any(item in description for item in cleanup):
        return []
    return [
        _finding(
            tool_name,
            "HEUR-016",
            "Uses resources but cleanup is not documented",
            Severity.MEDIUM,
            resources=found[:3],
        )
    ]


def _check_no_idempotency_indication(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    description = tool_def.get("description", "").lower()
    state_changing = (
        "create",
        "delete",
        "update",
        "modify",
        "remove",
        "insert",
        "write",
        "post",
        "put",
        "patch",
        "drop",
        "truncate",
    )
    if not any(verb in description for verb in state_changing):
        return []
    idempotency = ("idempotent", "safe to retry", "can be retried", "idempotency", "duplicate", "repeat")
    if any(item in description for item in idempotency):
        return []
    return [
        _finding(tool_name, "HEUR-017", "State-changing tool lacks idempotency documentation", Severity.LOW)
    ]


def _check_dangerous_operation_keywords(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    combined = f"{tool_def.get('name', '')} {tool_def.get('description', '')}".lower()
    dangerous = ("delete", "drop", "truncate", "exec", "eval", "rm ", "remove", "destroy", "purge", "wipe")
    found = [kw for kw in dangerous if kw in combined]
    if not found:
        return []
    return [
        _finding(
            tool_name,
            "HEUR-018",
            f"Dangerous operation keywords: {', '.join(found)}",
            Severity.HIGH,
            keywords=found,
        )
    ]


def _check_no_authentication_context(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    auth_fields = ("auth", "authentication", "credentials", "apiKey", "api_key", "token")
    config = _config(tool_def)
    if any(field in tool_def or field in config for field in auth_fields):
        return []
    description = tool_def.get("description", "").lower()
    external = (
        "api",
        "service",
        "endpoint",
        "http",
        "rest",
        "request",
        "external",
        "remote",
        "third-party",
        "cloud",
        "server",
    )
    if any(item in description for item in external):
        return [
            _finding(tool_name, "HEUR-019", "External service use without auth documentation", Severity.LOW)
        ]
    return []


def _check_circular_dependency_risk(tool_def: dict[str, Any], tool_name: str) -> list[Finding]:
    description = tool_def.get("description", "").lower()
    if tool_name and tool_name.lower() in description:
        return [
            _finding(
                tool_name,
                "HEUR-020",
                "Tool references itself in description",
                Severity.MEDIUM,
            )
        ]
    for pattern in ("calls itself", "recursive", "loop", "repeat until"):
        if pattern in description:
            return [_finding(tool_name, "HEUR-020", f"Description mentions {pattern}", Severity.MEDIUM)]
    return []
