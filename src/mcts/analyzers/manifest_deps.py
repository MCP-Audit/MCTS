"""Parse Python dependency manifests and lockfiles for supply-chain checks."""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

UNPINNED_PATTERN = re.compile(r"(\^|~|\*|latest|>=|<=|>|<)", re.I)
_PEP508_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_SKIP_DEPENDENCY_NAMES = frozenset({"python", "python_version"})
_PEP508_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")

# Distribution names and import roots are not always identical.  Keep this
# table deliberately small and conservative: an unknown import is still
# useful evidence, while an incorrect alias would hide a real gap.
_IMPORT_TO_DISTRIBUTION = {
    "attr": "attrs",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "Crypto": "pycryptodome",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "multipart": "python-multipart",
    "PIL": "pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
}
_STDLIB_MODULES = frozenset(getattr(sys, "stdlib_module_names", ()))


@dataclass(frozen=True)
class DeclaredDependency:
    name: str
    spec: str
    section: str


def normalize_package_name(name: str) -> str:
    return name.lower().replace("_", "-")


def iter_requirement_names(path: Path) -> set[str]:
    """Return normalized distribution names declared in a requirements file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return set()

    names: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line or line.startswith((".", "/", "\\")):
            # Includes, editable installs, paths, and pip options need their
            # own resolution semantics; do not guess at their package set.
            continue
        match = _PEP508_REQUIREMENT.match(line)
        if match:
            names.add(normalize_package_name(match.group(1)))
    return names


def import_distribution_name(module: str) -> str:
    """Map an import root to its best-known distribution name."""
    return normalize_package_name(_IMPORT_TO_DISTRIBUTION.get(module, module))


def is_stdlib_module(module: str) -> bool:
    """Return whether an import root belongs to the Python standard library."""
    return module in _STDLIB_MODULES or module in {"__future__", "builtins"}


@lru_cache(maxsize=2048)
def _parse_python_imports(path: str, mtime_ns: int, size: int) -> tuple[tuple[str, int], ...]:
    """Parse one Python file, keyed by stat data so repeated scans reuse ASTs."""
    del mtime_ns, size
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    except (OSError, UnicodeError, SyntaxError):
        return ()

    imports: list[tuple[str, int]] = []

    class _Collector(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                imports.append((alias.name.split(".", 1)[0], node.lineno))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.level == 0 and node.module and node.module != "__future__":
                imports.append((node.module.split(".", 1)[0], node.lineno))

        def visit_If(self, node: ast.If) -> None:
            # Imports guarded by TYPE_CHECKING are not runtime dependencies.
            test = node.test
            type_checking = isinstance(test, ast.Name) and test.id == "TYPE_CHECKING"
            type_checking = type_checking or (
                isinstance(test, ast.Attribute)
                and test.attr == "TYPE_CHECKING"
                and isinstance(test.value, ast.Name)
                and test.value.id == "typing"
            )
            if not type_checking:
                self.generic_visit(node)
            else:
                for child in node.orelse:
                    self.visit(child)

    _Collector().visit(tree)
    return tuple(imports)


def iter_python_imports(path: Path) -> tuple[tuple[str, int], ...]:
    """Return static, runtime import roots and source lines for one file."""
    try:
        stat = path.stat()
    except OSError:
        return ()
    return _parse_python_imports(str(path), stat.st_mtime_ns, stat.st_size)


def is_unpinned_spec(spec: str) -> bool:
    text = spec.strip()
    if not text:
        return False
    if text.startswith("=="):
        return False
    return bool(UNPINNED_PATTERN.search(text))


def load_locked_versions(root: Path) -> dict[str, str]:
    """Return normalized package name -> pinned version from adjacent lockfiles."""
    locked: dict[str, str] = {}
    for filename in ("poetry.lock", "uv.lock"):
        path = root / filename
        if path.is_file():
            locked.update(_load_toml_lock_packages(path))
    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.is_file():
        locked.update(_load_pipfile_lock(pipfile_lock))
    return locked


def iter_pyproject_dependencies(path: Path) -> list[DeclaredDependency]:
    """Extract declared Python dependencies from a pyproject.toml file."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    deps: list[DeclaredDependency] = []
    project = data.get("project")
    if isinstance(project, dict):
        raw_deps = project.get("dependencies")
        if isinstance(raw_deps, list):
            for entry in raw_deps:
                if isinstance(entry, str):
                    deps.extend(_dependency_from_pep508(entry, "project.dependencies"))

        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, entries in optional.items():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, str):
                        deps.extend(_dependency_from_pep508(entry, f"project.optional-dependencies.{group}"))

    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            poetry_deps = poetry.get("dependencies")
            if isinstance(poetry_deps, dict):
                for name, spec in poetry_deps.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        deps.extend(_dependency_from_mapping(name, spec, "tool.poetry.dependencies"))

            groups = poetry.get("group")
            if isinstance(groups, dict):
                for group_name, group_cfg in groups.items():
                    if not isinstance(group_cfg, dict):
                        continue
                    group_deps = group_cfg.get("dependencies")
                    if isinstance(group_deps, dict):
                        section = f"tool.poetry.group.{group_name}.dependencies"
                        for name, spec in group_deps.items():
                            if isinstance(name, str) and isinstance(spec, str):
                                deps.extend(_dependency_from_mapping(name, spec, section))

    return deps


def _dependency_from_pep508(entry: str, section: str) -> list[DeclaredDependency]:
    text = entry.strip()
    if not text or text.startswith("#"):
        return []
    match = _PEP508_NAME.match(text)
    if not match:
        return []
    name = match.group(1)
    if normalize_package_name(name) in _SKIP_DEPENDENCY_NAMES:
        return []
    return [DeclaredDependency(name=name, spec=text, section=section)]


def _dependency_from_mapping(name: str, spec: str, section: str) -> list[DeclaredDependency]:
    if normalize_package_name(name) in _SKIP_DEPENDENCY_NAMES:
        return []
    return [DeclaredDependency(name=name, spec=spec.strip(), section=section)]


def _load_toml_lock_packages(path: Path) -> dict[str, str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}

    locked: dict[str, str] = {}
    packages = data.get("package")
    if not isinstance(packages, list):
        return locked
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            locked[normalize_package_name(name)] = version
    return locked


def _load_pipfile_lock(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    locked: dict[str, str] = {}
    for section_name, section in data.items():
        if section_name.startswith("_") or not isinstance(section, dict):
            continue
        for name, meta in section.items():
            if not isinstance(name, str) or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                locked[normalize_package_name(name)] = version.lstrip("=")
    return locked
