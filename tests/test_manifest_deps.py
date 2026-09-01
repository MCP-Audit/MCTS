"""Tests for pyproject dependency parsing and lockfile-aware supply-chain checks."""

from __future__ import annotations

from pathlib import Path

from mcts.analyzers.manifest_deps import (
    import_distribution_name,
    is_stdlib_module,
    iter_pyproject_dependencies,
    iter_python_imports,
    iter_requirement_names,
    load_locked_versions,
    normalize_package_name,
)
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.mcp.models import MCPServerInfo


def _server() -> MCPServerInfo:
    return MCPServerInfo(tools=[])


def test_iter_pyproject_skips_poetry_metadata_and_tool_config(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry]
name = "demo"
description = "Bridge for IFD >= 3.9 environments"
authors = ["UXE AI Solutions <team@example.com>"]

[tool.pytest.ini_options]
python_files = "test_*.py"
python_classes = "Test*"

[tool.ruff]
line-length = 100

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27.0"
""",
        encoding="utf-8",
    )
    deps = iter_pyproject_dependencies(pyproject)
    names = {dep.name for dep in deps}
    assert names == {"httpx"}


def test_supply_chain_skips_poetry_metadata_false_positives(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry]
description = "Supports environments >= 3.9"
authors = ["Team <team@example.com>"]

[tool.pytest.ini_options]
python_files = "test_*.py"

[tool.poetry.dependencies]
python = "^3.11"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not findings


def test_supply_chain_flags_unpinned_without_lockfile(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
httpx = "^0.27.0"
fastmcp = ">=1.0"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    titles = {finding.title for finding in findings}
    assert "Unpinned Python dependency: httpx" in titles
    assert "Unpinned Python dependency: fastmcp" in titles


def test_supply_chain_skips_locked_poetry_dependencies(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry.dependencies]
httpx = "^0.27.0"
requests = "^2.31.0"
""",
        encoding="utf-8",
    )
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        """
[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "requests"
version = "2.31.0"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not findings


def test_supply_chain_honors_uv_lock(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "httpx>=0.28.0",
]
""",
        encoding="utf-8",
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        """
[[package]]
name = "httpx"
version = "0.28.1"
""",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not any(f.title.startswith("Unpinned Python dependency") for f in findings)


def test_load_locked_versions_from_pipfile_lock(tmp_path: Path) -> None:
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        """
{
  "default": {
    "requests": {
      "version": "==2.31.0"
    }
  }
}
""",
        encoding="utf-8",
    )

    locked = load_locked_versions(tmp_path)
    assert locked[normalize_package_name("requests")] == "2.31.0"


def test_project_dependencies_parsed(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = ["pydantic>=2.13.4"]
""",
        encoding="utf-8",
    )

    deps = iter_pyproject_dependencies(pyproject)
    assert len(deps) == 1
    assert deps[0].name == "pydantic"


def test_runtime_imports_are_parsed_without_type_checking_imports(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        """
import requests
from gql import gql
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import cachetools
""".strip(),
        encoding="utf-8",
    )

    imports = dict(iter_python_imports(source))
    assert set(imports) == {"requests", "gql", "json", "typing"}
    assert is_stdlib_module("json")
    assert not is_stdlib_module("requests")
    assert import_distribution_name("requests") == "requests"


def test_requirement_names_ignore_options_and_urls(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "requests==2.31.0\n-r base.txt\ngit+https://example.invalid/demo.git\n",
        encoding="utf-8",
    )

    assert iter_requirement_names(requirements) == {"requests"}


def test_supply_chain_flags_undeclared_runtime_imports(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "import requests",
                "from gql import gql",
                "import cachetools",
                "import json",
                "import os",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "local.py").write_text("VALUE = 1\n", encoding="utf-8")

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    undeclared = {
        finding.evidence["package"]
        for finding in findings
        if finding.title.startswith("Undeclared runtime Python import")
    }
    assert undeclared == {"cachetools", "gql", "requests"}
    assert all(
        finding.location and finding.location.file.endswith("app.py")
        for finding in findings
        if finding.title.startswith("Undeclared runtime")
    )


def test_supply_chain_accepts_imports_declared_in_requirements(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import requests\nfrom gql import gql\nimport cachetools\nimport json\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\ngql>=3.0\ncachetools==5.5.0\n",
        encoding="utf-8",
    )

    findings = SupplyChainAnalyzer(target=tmp_path).analyze(_server())
    assert not any(finding.title.startswith("Undeclared runtime") for finding in findings)
