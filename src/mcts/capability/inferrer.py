"""Rule-based capability inference for MCP tools."""

from __future__ import annotations

import re

from mcts.mcp.models import CapabilityProfile, CapabilitySignal, MCPTool

READ_HINTS = re.compile(r"\b(read|fetch|get|list|query|load|open|email)\b", re.I)
EGRESS_HINTS = re.compile(r"\b(send|post|upload|webhook|http|export|request|fetch\s+url)\b", re.I)
EXEC_HINTS = re.compile(r"\b(exec|execute|run|shell|subprocess|system|eval|command)\b", re.I)
SENSITIVE_HINTS = re.compile(r"\b(password|token|credential|secret|key|auth|env)\b", re.I)
CREDENTIAL_MARKERS = re.compile(r"(api[_-]?token|sales_api|password|credential|secret|auth[_-]?token)", re.I)
ENV_ACCESS = re.compile(r"\b(os\.environ|getenv|process\.env)\b", re.I)
MUTATE_HINTS = re.compile(r"\b(delete|write|update|create|drop|remove|destroy|insert)\b", re.I)

DANGEROUS_CALLS = re.compile(
    r"\b(subprocess|os\.system|eval|exec|httpx|requests|urllib|webhook|"
    r"child_process|execSync|spawnSync|spawn)\b",
    re.I,
)


def _snippet_around(text: str, match: re.Match[str], *, radius: int = 48) -> str:
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    return text[start:end].replace("\n", " ").strip()


def _add_signal(
    signals: list[CapabilitySignal],
    *,
    rule_id: str,
    dimension: str,
    field: str,
    match: str,
    snippet: str | None = None,
) -> None:
    signals.append(
        CapabilitySignal(
            rule_id=rule_id,
            dimension=dimension,
            field=field,
            match=match,
            snippet=snippet,
        )
    )


def _scan_pattern(
    signals: list[CapabilitySignal],
    *,
    pattern: re.Pattern[str],
    text: str,
    rule_id: str,
    dimension: str,
    field: str,
) -> bool:
    hit = pattern.search(text)
    if not hit:
        return False
    _add_signal(
        signals,
        rule_id=rule_id,
        dimension=dimension,
        field=field,
        match=hit.group(0),
        snippet=_snippet_around(text, hit),
    )
    return True


def infer_capability(tool: MCPTool) -> CapabilityProfile:
    """Derive capability dimensions from tool metadata and handler snippet."""
    signals: list[CapabilitySignal] = []
    haystack = f"{tool.name} {tool.description}"
    schema_text = " ".join(tool.input_schema.get("properties", {}).keys())
    haystack = f"{haystack} {schema_text}"
    snippet = tool.handler_snippet or ""

    reads = _scan_pattern(
        signals,
        pattern=READ_HINTS,
        text=haystack,
        rule_id="CAP_READ_HINT",
        dimension="reads_untrusted_input",
        field="tool_metadata",
    )
    if "path" in haystack.lower():
        reads = True
        _add_signal(
            signals,
            rule_id="CAP_SCHEMA_PATH",
            dimension="reads_untrusted_input",
            field="input_schema",
            match="path",
        )

    sensitive = _scan_pattern(
        signals,
        pattern=SENSITIVE_HINTS,
        text=haystack,
        rule_id="CAP_CREDENTIAL_KEYWORD",
        dimension="accesses_sensitive_data",
        field="tool_metadata",
    )
    if not sensitive:
        sensitive = _scan_pattern(
            signals,
            pattern=CREDENTIAL_MARKERS,
            text=haystack,
            rule_id="CAP_CREDENTIAL_KEYWORD",
            dimension="accesses_sensitive_data",
            field="tool_metadata",
        )
    if not sensitive:
        sensitive = _scan_pattern(
            signals,
            pattern=ENV_ACCESS,
            text=snippet,
            rule_id="CAP_CREDENTIAL_ENV",
            dimension="accesses_sensitive_data",
            field="handler_snippet",
        )

    mutates = _scan_pattern(
        signals,
        pattern=MUTATE_HINTS,
        text=haystack,
        rule_id="CAP_MUTATE_HINT",
        dimension="mutates_state",
        field="tool_metadata",
    )

    egress_meta = _scan_pattern(
        signals,
        pattern=EGRESS_HINTS,
        text=haystack,
        rule_id="CAP_EGRESS_HINT",
        dimension="egresses_network",
        field="tool_metadata",
    )
    egress_handler = _scan_pattern(
        signals,
        pattern=DANGEROUS_CALLS,
        text=snippet,
        rule_id="CAP_EGRESS_HANDLER",
        dimension="egresses_network",
        field="handler_snippet",
    )

    exec_meta = _scan_pattern(
        signals,
        pattern=EXEC_HINTS,
        text=haystack,
        rule_id="CAP_EXEC_HINT",
        dimension="executes_commands",
        field="tool_metadata",
    )
    exec_handler = _scan_pattern(
        signals,
        pattern=DANGEROUS_CALLS,
        text=snippet,
        rule_id="CAP_EXEC_HANDLER",
        dimension="executes_commands",
        field="handler_snippet",
    )

    if "run_shell" in tool.name or "shell" in tool.name.lower():
        exec_meta = True
        _add_signal(
            signals,
            rule_id="CAP_TOOL_NAME_SHELL",
            dimension="executes_commands",
            field="tool_name",
            match=tool.name,
        )
    if "webhook" in tool.name.lower() or "send_" in tool.name:
        egress_meta = True
        _add_signal(
            signals,
            rule_id="CAP_TOOL_NAME_EGRESS",
            dimension="egresses_network",
            field="tool_name",
            match=tool.name,
        )
    if "read_file" in tool.name or "get_env" in tool.name:
        reads = True
        sensitive = True
        _add_signal(
            signals,
            rule_id="CAP_TOOL_NAME_READ",
            dimension="reads_untrusted_input",
            field="tool_name",
            match=tool.name,
        )
        _add_signal(
            signals,
            rule_id="CAP_TOOL_NAME_SENSITIVE",
            dimension="accesses_sensitive_data",
            field="tool_name",
            match=tool.name,
        )

    profile = CapabilityProfile(
        reads_untrusted_input=reads or bool(READ_HINTS.search(haystack) or "path" in haystack.lower()),
        accesses_sensitive_data=sensitive
        or bool(
            SENSITIVE_HINTS.search(haystack)
            or CREDENTIAL_MARKERS.search(haystack)
            or ENV_ACCESS.search(snippet)
        ),
        mutates_state=mutates or bool(MUTATE_HINTS.search(haystack)),
        egresses_network=egress_meta
        or egress_handler
        or bool(EGRESS_HINTS.search(haystack) or DANGEROUS_CALLS.search(snippet)),
        executes_commands=exec_meta
        or exec_handler
        or bool(EXEC_HINTS.search(haystack) or DANGEROUS_CALLS.search(snippet)),
        signals=signals,
    )

    if "run_shell" in tool.name or "shell" in tool.name.lower():
        profile.executes_commands = True
    if "webhook" in tool.name.lower() or "send_" in tool.name:
        profile.egresses_network = True
    if "read_file" in tool.name or "get_env" in tool.name:
        profile.reads_untrusted_input = True
        profile.accesses_sensitive_data = True

    return profile
