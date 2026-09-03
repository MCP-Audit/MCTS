"""Repository-wide static MCP tool discovery."""

from __future__ import annotations

import ast
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from mcts.capability.inferrer import infer_capability
from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget, TargetKind
from mcts.mcp.models import MCPServerInfo, MCPTool

TOOL_DECORATOR_PATTERN = re.compile(
    r"@(?:\w+\.)?tool\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\(",
    re.MULTILINE,
)

MCP_FILE_INDICATORS = (
    "@tool",
    ".tool(",
    "FastMCP",
    'Server("mcp")',
)

DEFAULT_SKIP_PATH_PARTS = frozenset({"tests", "test"})

TYPE_HINT_MAP: dict[str, str] = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "Any": "string",
}


class StaticDiscovery:
    """Discover MCP tools by walking Python source files."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.target = ScanTarget(config.target)

    def discover(self) -> MCPServerInfo:
        if self.target.kind == TargetKind.FILE:
            return self._discover_file(self.target.path)

        source_files = self._collect_source_files(self.target.path)
        tools: list[MCPTool] = []
        for file_path in source_files:
            tools.extend(self._parse_tools_from_file(Path(file_path)))

        return MCPServerInfo(
            name=self.target.path.name,
            tools=tools,
            transport="stdio",
            discovery_mode="static",
            source_files=source_files,
        )

    def _discover_file(self, file_path: Path) -> MCPServerInfo:
        if not file_path.exists():
            return MCPServerInfo(name=str(file_path), tools=[])

        content = self._read_file(file_path)
        tools = self._parse_tools_from_content(file_path, content)
        return MCPServerInfo(
            name=file_path.stem,
            tools=tools,
            transport="stdio",
            discovery_mode="static",
            source_files={str(file_path): content},
        )

    def _collect_source_files(self, root: Path) -> dict[str, str]:
        files: dict[str, str] = {}
        for path in sorted(root.rglob("*.py")):
            if not self._should_scan(path, root):
                continue
            content = self._read_file(path)
            if content and self._looks_like_mcp_file(content):
                files[str(path)] = content
        return files

    def _should_scan(self, path: Path, root: Path) -> bool:
        rel = path.relative_to(root)
        parts = set(rel.parts)
        if parts & DEFAULT_SKIP_PATH_PARTS:
            return False
        if any(part in self.config.exclude_dirs for part in rel.parts):
            return False
        rel_str = str(rel)
        if self.config.exclude_globs and any(_matches_glob(rel_str, g) for g in self.config.exclude_globs):
            return False
        if self.config.include_globs and not any(
            _matches_glob(rel_str, g) for g in self.config.include_globs
        ):
            return False
        try:
            if path.stat().st_size > self.config.max_file_bytes:
                return False
        except OSError:
            return False
        return True

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    def _looks_like_mcp_file(self, content: str) -> bool:
        return any(indicator in content for indicator in MCP_FILE_INDICATORS)

    def _parse_tools_from_file(self, file_path: Path) -> list[MCPTool]:
        content = self._read_file(file_path)
        if not content:
            return []
        return self._parse_tools_from_content(file_path, content)

    def _parse_tools_from_content(self, file_path: Path, content: str) -> list[MCPTool]:
        tools: list[MCPTool] = []
        for match in TOOL_DECORATOR_PATTERN.finditer(content):
            func_name = match.group(1)
            tool = self._build_tool(file_path, content, func_name)
            if tool:
                tools.append(tool)
        return tools

    def _build_tool(self, file_path: Path, content: str, func_name: str) -> MCPTool | None:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return MCPTool(name=func_name, source_file=str(file_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == func_name:
                description = ast.get_docstring(node) or ""
                schema = _schema_from_function(node)
                snippet = _handler_snippet(content, node)
                tool = MCPTool(
                    name=func_name,
                    description=description,
                    input_schema=schema,
                    source_file=str(file_path),
                    source_line=node.lineno,
                    handler_snippet=snippet,
                )
                tool.capability = infer_capability(tool)
                return tool
        return MCPTool(name=func_name, source_file=str(file_path))

    def _extract_docstring(self, source: str, func_name: str) -> str:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return ""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == func_name:
                return ast.get_docstring(node) or ""
        return ""


def _matches_glob(relative_path: str, pattern: str) -> bool:
    """Match a relative path while allowing ``**/`` to match the root level."""
    normalized_path = relative_path.replace("\\", "/")
    normalized_pattern = pattern.replace("\\", "/")
    if fnmatch(normalized_path, normalized_pattern):
        return True
    return normalized_pattern.startswith("**/") and fnmatch(normalized_path, normalized_pattern[3:])


def _schema_from_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    args = node.args.args
    num_defaults = len(node.args.defaults)
    optional_start = len(args) - num_defaults

    for index, arg in enumerate(args):
        if arg.arg in ("self", "cls"):
            continue
        json_type = _hint_to_json_type(arg.annotation)
        properties[arg.arg] = {"type": json_type}
        if index < optional_start:
            required.append(arg.arg)

    kw_defaults = node.args.kw_defaults or []
    for arg, default in zip(node.args.kwonlyargs, kw_defaults, strict=False):
        json_type = _hint_to_json_type(arg.annotation)
        properties[arg.arg] = {"type": json_type}
        if default is None and arg.arg not in required:
            required.append(arg.arg)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _hint_to_json_type(annotation: ast.expr | None) -> str:
    if annotation is None:
        return "string"
    if isinstance(annotation, ast.Name):
        return TYPE_HINT_MAP.get(annotation.id, "string")
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        return TYPE_HINT_MAP.get(annotation.value.id, "string")
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return TYPE_HINT_MAP.get(annotation.value, "string")
    return "string"


def _handler_snippet(source: str, node: ast.FunctionDef | ast.AsyncFunctionDef, max_lines: int = 80) -> str:
    lines = source.splitlines()
    start = max(0, node.lineno - 1)
    end = min(len(lines), node.end_lineno or node.lineno)
    snippet_lines = lines[start:end]
    if len(snippet_lines) > max_lines:
        snippet_lines = snippet_lines[:max_lines]
    return "\n".join(snippet_lines)
