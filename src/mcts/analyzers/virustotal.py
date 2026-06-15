"""VirusTotal hash lookup for files in scan target (optional)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import httpx

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding, build_skip_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

_MAX_FILES = 10
_SCAN_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".whl"}


class VirusTotalAnalyzer(BaseAnalyzer):
    """SHA256 hash lookup via VirusTotal API."""

    name = "virustotal"

    def __init__(self, target: Path, max_files: int = _MAX_FILES) -> None:
        self.target = target
        self.max_files = max_files

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        api_key = os.environ.get("MCTS_VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return [
                build_skip_finding(
                    finding_id="virustotal-skipped",
                    analyzer=self.name,
                    title="VirusTotal lookup skipped",
                    description="MCTS_VT_API_KEY (or VIRUSTOTAL_API_KEY) is not set",
                    recommendation="Export MCTS_VT_API_KEY or disable --enable-virustotal.",
                )
            ]
        root = self.target if self.target.is_dir() else self.target.parent
        findings: list[Finding] = []
        for path in _iter_binaries(root, self.max_files):
            sha = _sha256(path)
            stats = _vt_lookup(sha, api_key)
            if not stats:
                continue
            malicious = int(stats.get("malicious") or 0)
            if malicious <= 0:
                continue
            findings.append(
                build_analyzer_finding(
                    finding_id=f"vt-{sha[:12]}",
                    analyzer=self.name,
                    title=f"VirusTotal detection: {path.name}",
                    description=f"{malicious} engine(s) flagged {path.name}",
                    severity=Severity.HIGH if malicious >= 3 else Severity.MEDIUM,
                    recommendation="Do not distribute or execute flagged binaries.",
                    rule_id="RULE_VIRUSTOTAL",
                    match=sha,
                    field="binary_hash",
                    technique_id="MCTS-T-1038",
                    confidence=0.9,
                    extra_evidence={"path": str(path), "sha256": sha, "stats": stats},
                )
            )
        return findings


def _iter_binaries(root: Path, limit: int) -> list[Path]:
    rows: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SCAN_EXTENSIONS:
            rows.append(path)
        if len(rows) >= limit:
            break
    return rows


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _vt_lookup(sha256: str, api_key: str) -> dict | None:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        resp = httpx.get(url, headers={"x-apikey": api_key}, timeout=30)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats")
    except (httpx.HTTPError, ValueError):
        return None
