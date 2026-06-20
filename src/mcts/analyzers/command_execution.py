"""Command execution detection in tool handlers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.reference_tier import apply_reference_tier, is_demo_reference_server
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_command_execution_finding

DANGEROUS_CALLS: dict[str, tuple[str, Severity]] = {
    "subprocess": ("subprocess invocation", Severity.CRITICAL),
    "os.system": ("os.system call", Severity.CRITICAL),
    "eval": ("eval() call", Severity.CRITICAL),
    "exec": ("exec() call", Severity.CRITICAL),
}

_SNIPPET_PATTERNS: dict[str, re.Pattern[str]] = {
    "subprocess": re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\("),
    "os.system": re.compile(r"\bos\.system\s*\("),
    "eval": re.compile(r"\beval\s*\("),
    "exec": re.compile(r"\bexec\s*\("),
}

_JS_EXTENSIONS = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


class CommandExecutionAnalyzer(BaseAnalyzer):
    """Detects shell/command execution in MCP tool handler source."""

    name = "command_execution"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        demo = is_demo_reference_server(server)
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool, server.source_files, demo=demo))
        return [tag_command_execution_finding(f) for f in findings]

    def _analyze_tool(
        self,
        tool: MCPTool,
        source_files: dict[str, str],
        *,
        demo: bool,
    ) -> list[Finding]:
        source_path = _resolve_tool_source_path(tool, source_files)
        if source_path and source_path in source_files:
            source = source_files[source_path]
            suffix = Path(source_path).suffix.lower()
            if suffix in _JS_EXTENSIONS:
                return self._findings_from_ts_snippet(
                    tool,
                    source,
                    source_path,
                    demo=demo,
                )
            try:
                tree = ast.parse(source)
            except SyntaxError:
                return self._findings_from_snippet(
                    tool,
                    tool.handler_snippet or source,
                    source_path,
                    demo=demo,
                )

            findings: list[Finding] = []
            func_node = _find_function(tree, tool.name)
            if func_node is None:
                return self._findings_from_snippet(
                    tool,
                    tool.handler_snippet or source,
                    source_path,
                    demo=demo,
                )

            for node in ast.walk(func_node):
                call_label = _classify_call(node)
                if call_label is None:
                    continue
                label, severity = DANGEROUS_CALLS[call_label]
                line = getattr(node, "lineno", tool.source_line)
                findings.append(
                    _cmd_finding(
                        tool=tool,
                        call_label=call_label,
                        label=label,
                        severity=severity,
                        line=line,
                        field="handler_ast",
                        file=source_path,
                        extra={"call": call_label, "line": line},
                    )
                )
            return findings

        if tool.handler_snippet:
            return self._findings_from_snippet(
                tool,
                tool.handler_snippet,
                tool.source_file,
                demo=demo,
            )
        return []

    def _findings_from_ts_snippet(
        self,
        tool: MCPTool,
        source: str,
        source_path: str,
        *,
        demo: bool,
    ) -> list[Finding]:
        """TypeScript handlers: require real call-site patterns, not substring noise."""
        return self._findings_from_snippet(
            tool,
            source,
            source_path,
            demo=demo,
            strict=True,
        )

    def _findings_from_snippet(
        self,
        tool: MCPTool,
        snippet: str,
        source_path: str | None,
        *,
        demo: bool,
        strict: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for call, (label, severity) in DANGEROUS_CALLS.items():
            if not _snippet_matches_call(snippet, call, strict=strict):
                continue
            finding = _cmd_finding(
                tool=tool,
                call_label=call,
                label=label,
                severity=severity,
                line=tool.source_line,
                field="handler_snippet",
                file=source_path,
                snippet=snippet[:160] if snippet else None,
                extra={"call": call, "source": "snippet"},
            )
            if demo and strict:
                finding = apply_reference_tier(finding, demo=True)
            findings.append(finding)
        return findings


def _snippet_matches_call(snippet: str, call: str, *, strict: bool) -> bool:
    pattern = _SNIPPET_PATTERNS.get(call)
    return bool(pattern and pattern.search(snippet))


def _resolve_tool_source_path(tool: MCPTool, source_files: dict[str, str]) -> str | None:
    if not tool.source_file:
        return None
    path = tool.source_file.replace("\\", "/")
    if path in source_files and not path.endswith(("tools/index.ts", "tools/index.js")):
        return tool.source_file
    if not path.endswith(("tools/index.ts", "tools/index.js")):
        return tool.source_file if tool.source_file in source_files else None
    normalized = tool.name.lower().replace("g-zip", "gzip")
    for candidate in source_files:
        cand = candidate.replace("\\", "/")
        if "/tools/" not in cand or Path(cand).suffix.lower() not in _JS_EXTENSIONS:
            continue
        stem = Path(cand).stem.lower()
        if stem == normalized or stem.replace("-", "") == normalized.replace("-", ""):
            return candidate
    return tool.source_file if tool.source_file in source_files else None


def _cmd_finding(
    *,
    tool: MCPTool,
    call_label: str,
    label: str,
    severity: Severity,
    line: int | None,
    field: str,
    file: str | None = None,
    snippet: str | None = None,
    extra: dict | None = None,
) -> Finding:
    finding_id = f"cmd-{tool.name}-{call_label.replace('.', '-')}"
    source_file = file or tool.source_file
    builder = (
        FindingBuilder(
            finding_id=finding_id,
            analyzer="command_execution",
            title=f"Command execution in {tool.name}: {label}",
            description=(
                f"Tool handler uses {label}, enabling arbitrary command execution."
                if field == "handler_ast"
                else f"Tool handler appears to use {label}."
            ),
            severity=severity,
            recommendation="Remove shell execution; use allowlisted subprocess with argument lists.",
        )
        .tool(tool.name)
        .technique("MCTS-T-1003")
        .confidence(0.7)
    )
    if source_file:
        builder = builder.location(source_file, line)
    fact_kwargs: dict = {
        "rule_id": "RULE_CMD_EXEC",
        "match": call_label,
        "field": field,
        "tool": tool.name,
    }
    if source_file:
        fact_kwargs["file"] = source_file
    if line is not None:
        fact_kwargs["line"] = line
    if snippet:
        fact_kwargs["snippet"] = snippet
    builder = builder.fact(**fact_kwargs)
    if extra:
        builder = builder.evidence(**extra)
    return builder.build()


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    return None


def _classify_call(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            if func.value.id == "subprocess":
                return "subprocess"
            qualified = f"{func.value.id}.{func.attr}"
            if qualified in DANGEROUS_CALLS:
                return qualified
            if func.attr in ("system", "popen") and func.value.id == "os":
                return "os.system"
        if func.attr in DANGEROUS_CALLS:
            return func.attr
    if isinstance(func, ast.Name) and func.id in DANGEROUS_CALLS:
        return func.id
    return None
