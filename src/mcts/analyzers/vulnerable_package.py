"""Python dependency CVE scanning via pip-audit."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding, build_skip_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity


class VulnerablePackageAnalyzer(BaseAnalyzer):
    """Run pip-audit against requirements.txt or pyproject.toml in scan target."""

    name = "vulnerable_package"

    def __init__(self, target: Path) -> None:
        self.target = target

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        if not shutil.which("pip-audit"):
            return [
                _skip_finding(
                    "pip-audit CLI not found on PATH",
                    "Install pip-audit (`uv sync --extra supplychain`) or remove --pip-audit.",
                )
            ]
        req = self._find_requirements()
        if req is None:
            return [
                _skip_finding(
                    "no requirements.txt or pyproject.toml found in scan target",
                    "Add a Python dependency manifest or scan a directory that contains one.",
                )
            ]
        return self._audit_file(req)

    def _find_requirements(self) -> Path | None:
        root = self.target if self.target.is_dir() else self.target.parent
        for name in ("requirements.txt", "requirements-dev.txt"):
            path = root / name
            if path.exists():
                return path
        if (root / "pyproject.toml").exists():
            return root / "pyproject.toml"
        return None

    def _audit_file(self, path: Path) -> list[Finding]:
        cmd = ["pip-audit", "--format", "json"]
        if path.name == "pyproject.toml":
            cmd.extend(["--project-path", str(path.parent)])
        else:
            cmd.extend(["-r", str(path)])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            return []
        try:
            rows = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "unknown")
            version = str(row.get("version") or "")
            vulns = row.get("vulns") or []
            for vuln in vulns if isinstance(vulns, list) else []:
                if not isinstance(vuln, dict):
                    continue
                vid = str(vuln.get("id") or "CVE-UNKNOWN")
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"pip-audit-{name}-{vid}",
                        analyzer=self.name,
                        title=f"Vulnerable dependency: {name} {version} ({vid})",
                        description=str(vuln.get("description") or vid),
                        severity=Severity.HIGH,
                        recommendation=f"Upgrade {name} to a patched version.",
                        rule_id="RULE_PIP_AUDIT",
                        match=vid,
                        field="dependency_manifest",
                        technique_id="MCTS-T-1014",
                        confidence=0.95,
                        location=None,
                        snippet=str(vuln.get("description") or vid)[:200],
                        extra_evidence={
                            "package": name,
                            "version": version,
                            "vuln_id": vid,
                            "file": str(path),
                        },
                    )
                )
        return findings


def _skip_finding(reason: str, recommendation: str) -> Finding:
    return build_skip_finding(
        finding_id="pip-audit-skipped",
        analyzer="vulnerable_package",
        title="pip-audit scan skipped",
        description=reason,
        recommendation=recommendation,
    )
