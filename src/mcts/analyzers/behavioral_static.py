"""Python/TypeScript/Go/Rust behavioral SAST: description vs handler implementation."""

from __future__ import annotations

import ast
import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.sast.go.sinks import detect_go_sinks
from mcts.sast.go.taint import analyze_go_taint
from mcts.sast.python.crossfile import expand_python_handler
from mcts.sast.python.module_taint import analyze_python_module_taint
from mcts.sast.python.semantic import analyze_python_semantics
from mcts.sast.python.taint import analyze_handler_taint
from mcts.sast.rust.sinks import detect_rust_sinks
from mcts.sast.rust.taint import analyze_rust_taint
from mcts.sast.typescript.sinks import detect_typescript_sinks
from mcts.sast.typescript.taint import analyze_typescript_taint
from mcts.scoring.evidence_tags import tag_behavioral_static_finding

_BENIGN_CLAIMS = (
    (
        re.compile(r"(?i)\b(read[- ]?only|read only|no write|does not modify)\b"),
        {"write", "delete", "remove", "fs", "open"},
    ),
    (
        re.compile(r"(?i)\b(safe|harmless|benign)\b"),
        {"subprocess", "os.system", "eval", "exec", "child_process"},
    ),
    (
        re.compile(r"(?i)\b(local file|read file)\b"),
        {"requests.", "urllib", "http.client", "socket", "fetch", "axios"},
    ),
)

_SINK_MARKERS = {
    "subprocess": Severity.HIGH,
    "os.system": Severity.HIGH,
    "eval": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "requests.": Severity.MEDIUM,
    "urllib": Severity.MEDIUM,
    "open": Severity.MEDIUM,
    "shutil.rmtree": Severity.HIGH,
    "pathlib.Path.write": Severity.MEDIUM,
    "child_process": Severity.HIGH,
    "fetch": Severity.MEDIUM,
    "axios": Severity.MEDIUM,
    "fs": Severity.MEDIUM,
    "exec.Command": Severity.HIGH,
    "http.Get": Severity.MEDIUM,
    "Command::new": Severity.HIGH,
    "reqwest": Severity.MEDIUM,
    "sql": Severity.HIGH,
    "os.remove": Severity.HIGH,
    "pickle": Severity.HIGH,
    "socket": Severity.MEDIUM,
    "Template": Severity.HIGH,
    "shutil": Severity.HIGH,
}


class BehavioralStaticAnalyzer(BaseAnalyzer):
    """Detects description/implementation mismatches and taint flows in tool handlers."""

    name = "behavioral_static"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for resource in server.resources:
            if not resource.content:
                continue
            pseudo = MCPTool(
                name=resource.name or resource.uri,
                description=resource.description or "",
                handler_snippet=resource.content[:8000],
                source_file=resource.uri,
            )
            findings.extend(self._analyze_tool(pseudo))
        for tool in server.tools:
            snippet = self._handler_source(tool, server)
            if not snippet:
                continue
            findings.extend(self._analyze_tool(tool, snippet, server))
        return [tag_behavioral_static_finding(f) for f in findings]

    def _analyze_tool(
        self,
        tool: MCPTool,
        snippet: str | None = None,
        server: MCPServerInfo | None = None,
    ) -> list[Finding]:
        body = self._resolve_body(tool, snippet, server)
        if not body:
            return []
        sinks = _detect_sinks(body, tool.source_file)
        taint = None
        if _looks_like_python(body, tool.source_file):
            handler_body = tool.handler_snippet or body
            snippet_taint = analyze_handler_taint(handler_body)
            if tool.name and f"def {tool.name}" in body:
                module_taint = analyze_python_module_taint(body, tool.name)
                taint = _merge_taint(module_taint, snippet_taint)
            else:
                taint = snippet_taint
        elif _is_typescript(tool.source_file) or _looks_like_typescript(body):
            taint = analyze_typescript_taint(body)
        elif _is_go(tool.source_file) or _looks_like_go(body):
            taint = analyze_go_taint(body)
        elif _is_rust(tool.source_file) or _looks_like_rust(body):
            taint = analyze_rust_taint(body)
        if taint:
            for sink in taint.sinks:
                sinks.setdefault(sink, Severity.HIGH)
        findings: list[Finding] = []
        if sinks:
            findings.extend(self._mismatch_findings(tool, sinks))
            if taint and taint.sinks:
                findings.extend(self._taint_findings(tool, taint, sinks))
            if not findings:
                findings.extend(self._opaque_sink_findings(tool, sinks))
        if _looks_like_python(body, tool.source_file):
            findings.extend(
                self._semantic_findings(
                    tool,
                    analyze_python_semantics(body, tool.description or ""),
                )
            )
        return findings

    def _resolve_body(
        self,
        tool: MCPTool,
        snippet: str | None,
        server: MCPServerInfo | None,
    ) -> str:
        if server is not None:
            return self._handler_source(tool, server)
        if tool.source_file and _is_python(tool.source_file):
            full = _read_handler(tool.source_file, None)
            if full:
                return full
        return snippet if snippet is not None else (tool.handler_snippet or "")

    def _handler_source(self, tool: MCPTool, server: MCPServerInfo) -> str:
        snippet = tool.handler_snippet or ""
        if tool.source_file and not snippet:
            snippet = _read_handler(tool.source_file, tool.source_line)
        if not snippet and not tool.source_file:
            return ""
        if tool.source_file and _is_python(tool.source_file):
            return expand_python_handler(tool.source_file, snippet, server.source_files)
        return snippet

    def _mismatch_findings(self, tool: MCPTool, sinks: dict[str, Severity]) -> list[Finding]:
        findings: list[Finding] = []
        description = tool.description or ""
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)

        for claim_re, forbidden in _BENIGN_CLAIMS:
            if not claim_re.search(description):
                continue
            hit = [
                s
                for s in sinks
                if any(s.lower().startswith(f.lower()) or f.lower() in s.lower() for f in forbidden)
            ]
            if hit:
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"behavioral-mismatch-{tool.name}-{'-'.join(hit[:2])}",
                        analyzer=self.name,
                        title=f"Description/code mismatch on {tool.name}",
                        description=(f"Tool claims '{claim_re.pattern}' but handler uses: {', '.join(hit)}"),
                        severity=max(sinks[s] for s in hit),
                        recommendation="Align tool description with actual handler behavior.",
                        rule_id="RULE_BEHAVIOR_MISMATCH",
                        match=hit[0],
                        field="handler_body",
                        tool=tool.name,
                        location=loc,
                        technique_id="MCTS-T-1001",
                        confidence=0.8,
                        snippet=(tool.handler_snippet or "")[:160].replace("\n", " ").strip() or None,
                        extra_evidence={"sinks": hit, "description": description[:200]},
                    )
                )
        return findings

    def _taint_findings(self, tool: MCPTool, taint, sinks: dict[str, Severity]) -> list[Finding]:
        if not taint.sinks:
            return []
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)
        snippet = (tool.handler_snippet or "")[:160].replace("\n", " ").strip() or None
        if taint.tainted_params:
            description = (
                f"Handler parameters {sorted(taint.tainted_params)} may flow to "
                f"security-sensitive calls: {', '.join(taint.sinks)}"
            )
            confidence = 0.75
        else:
            description = (
                f"Handler invokes helper code with security-sensitive calls: {', '.join(taint.sinks)}"
            )
            confidence = 0.65
        return [
            build_analyzer_finding(
                finding_id=f"behavioral-taint-{tool.name}-{'-'.join(taint.sinks[:2])}",
                analyzer=self.name,
                title=f"Untrusted input may reach sink on {tool.name}",
                description=description,
                severity=max(sinks.get(s, Severity.HIGH) for s in taint.sinks),
                recommendation="Validate and sanitize tool inputs before dangerous operations.",
                rule_id="RULE_TAINT_PARAM_SINK",
                match=taint.sinks[0],
                field="handler_body",
                tool=tool.name,
                location=loc,
                technique_id="MCTS-T-1001",
                confidence=confidence,
                snippet=snippet,
                extra_evidence={
                    "sinks": taint.sinks,
                    "tainted_params": sorted(taint.tainted_params),
                },
            )
        ]

    def _semantic_findings(self, tool: MCPTool, issues) -> list[Finding]:
        if not issues:
            return []
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)
        findings: list[Finding] = []
        for issue in issues:
            findings.append(
                build_analyzer_finding(
                    finding_id=f"behavioral-semantic-{tool.name}-{issue.label}",
                    analyzer=self.name,
                    title=f"Semantic risk on {tool.name}: {issue.label.replace('_', ' ')}",
                    description=(
                        f"Handler or description indicates {issue.category.replace('_', ' ')} "
                        f"({issue.label})."
                    ),
                    severity=Severity.HIGH if issue.confidence >= 0.8 else Severity.MEDIUM,
                    recommendation="Align documented behavior with implementation; remove hidden directives.",
                    rule_id="RULE_BEHAVIOR_SEMANTIC",
                    match=issue.label,
                    field="handler_body",
                    tool=tool.name,
                    location=loc,
                    technique_id="MCTS-T-1001",
                    confidence=issue.confidence,
                    extra_evidence={"category": issue.category, "label": issue.label},
                )
            )
        return findings

    def _opaque_sink_findings(self, tool: MCPTool, sinks: dict[str, Severity]) -> list[Finding]:
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)
        labels = list(sinks.keys())[:4]
        return [
            build_analyzer_finding(
                finding_id=f"behavioral-sink-{tool.name}-{'-'.join(labels)}",
                analyzer=self.name,
                title=f"Security-sensitive operations in {tool.name}",
                description=f"Handler module uses: {', '.join(labels)}",
                severity=max(sinks.values()),
                recommendation="Review helper functions invoked by this tool for hidden behavior.",
                rule_id="RULE_BEHAVIOR_SINK",
                match=labels[0],
                field="handler_body",
                tool=tool.name,
                location=loc,
                technique_id="MCTS-T-1001",
                confidence=0.6,
                extra_evidence={"sinks": labels},
            )
        ]


def _merge_taint(left, right):
    from mcts.sast.python.taint import TaintResult

    if not left or not left.sinks:
        return right
    if not right or not right.sinks:
        return left
    return TaintResult(
        sinks=list(dict.fromkeys(left.sinks + right.sinks)),
        tainted_params=set(left.tainted_params) | set(right.tainted_params),
    )


def _is_python(path: str | None) -> bool:
    return bool(path and path.endswith(".py"))


def _looks_like_python(snippet: str, path: str | None) -> bool:
    if _is_typescript(path) or _looks_like_typescript(snippet):
        return False
    if _is_python(path):
        return True
    stripped = snippet.lstrip()
    return (
        stripped.startswith("def ")
        or stripped.startswith("async def ")
        or (stripped.startswith(("import ", "from ")) and "function " not in snippet[:200])
    )


def _is_typescript(path: str | None) -> bool:
    return bool(path and path.endswith((".ts", ".tsx", ".js", ".jsx")))


def _is_go(path: str | None) -> bool:
    return bool(path and path.endswith(".go"))


def _is_rust(path: str | None) -> bool:
    return bool(path and path.endswith(".rs"))


def _looks_like_typescript(snippet: str) -> bool:
    stripped = snippet.lstrip()
    return (
        stripped.startswith("function ")
        or stripped.startswith("async function")
        or "=>" in snippet[:300]
        or "export async function" in snippet
    )


def _looks_like_go(snippet: str) -> bool:
    return "func " in snippet and "package " in snippet


def _looks_like_rust(snippet: str) -> bool:
    stripped = snippet.lstrip()
    return stripped.startswith("fn ") or "fn " in snippet[:200]


def _read_handler(path: str, line: int | None) -> str:
    try:
        source = open(path, encoding="utf-8").read()  # noqa: SIM115
    except OSError:
        return ""
    if line is None:
        return source[:4000]
    lines = source.splitlines()
    start = max(0, line - 1)
    return "\n".join(lines[start : start + 80])


def _detect_sinks(snippet: str, source_file: str | None) -> dict[str, Severity]:
    sinks: dict[str, Severity] = {}
    if _is_typescript(source_file) or _looks_like_typescript(snippet):
        for label in detect_typescript_sinks(snippet):
            sinks[label] = _SINK_MARKERS.get(label, Severity.MEDIUM)
    if _is_go(source_file) or _looks_like_go(snippet):
        for label in detect_go_sinks(snippet):
            sinks[label] = _SINK_MARKERS.get(label, Severity.MEDIUM)
    if _is_rust(source_file) or _looks_like_rust(snippet):
        for label in detect_rust_sinks(snippet):
            sinks[label] = _SINK_MARKERS.get(label, Severity.MEDIUM)
    for marker, severity in _SINK_MARKERS.items():
        if marker in snippet:
            sinks[marker] = severity
    if not _is_python(source_file):
        return sinks
    try:
        tree = ast.parse(snippet)
    except SyntaxError:
        return sinks
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in ("subprocess.run", "subprocess.Popen", "os.system", "eval", "exec"):
                sinks[name] = Severity.HIGH
    return sinks


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""
