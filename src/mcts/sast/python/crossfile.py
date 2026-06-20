"""Resolve local Python imports for expanded handler analysis."""

from __future__ import annotations

import ast
from pathlib import Path


def expand_python_handler(source_file: str, snippet: str, source_files: dict[str, str]) -> str:
    """Include locally imported module sources alongside a handler snippet."""
    primary = source_files.get(source_file) or _read_file(source_file)
    if not primary:
        return snippet
    chunks = [primary]
    base_dir = Path(source_file).parent
    for module_name in _local_imports(primary):
        resolved = _resolve_module(base_dir, module_name, source_files)
        if resolved:
            chunks.append(resolved)
    if snippet and snippet not in primary:
        chunks.append(snippet)
    return "\n\n".join(dict.fromkeys(chunks))


def _read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _local_imports(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.append(node.module.split(".")[0])
            elif node.level and node.module:
                modules.append(node.module)
    return list(dict.fromkeys(modules))


def _resolve_module(base_dir: Path, module_name: str, source_files: dict[str, str]) -> str | None:
    candidates = list(_module_candidates(base_dir, module_name))
    for candidate in candidates:
        key = str(candidate)
        if key in source_files:
            return source_files[key]
        if candidate.exists():
            return candidate.read_text(encoding="utf-8")
    return None


def _module_candidates(base_dir: Path, module_name: str) -> list[Path]:
    roots = [base_dir, *base_dir.parents]
    candidates: list[Path] = []
    for root in roots:
        candidates.extend(
            [
                root / f"{module_name}.py",
                root / module_name / "__init__.py",
            ]
        )
    return list(dict.fromkeys(candidates))
