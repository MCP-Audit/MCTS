"""Security analysis for agent SKILL.md instruction files."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.tpa_patterns import find_control_chars, has_ansi_smuggling, has_hidden_unicode
from mcts.inventory.models import SkillEntry
from mcts.mcp.models import AgentSkillFile, MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

_INSTRUCTION_OVERRIDE = re.compile(
    r"(?i)\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions|rules|policy|prompt)\b"
)
_EXFIL = re.compile(r"(?i)\b(curl|wget|webhook|exfil|pastebin|ngrok|requestbin)\b")
_SHELL = re.compile(r"(?i)\b(rm\s+-rf|bash\s+-c|eval\s*\(|/bin/sh|powershell\s+-)\b")
_CREDENTIAL = re.compile(
    r"(?i)\b(api[_ -]?key|secret[_ -]?key|access[_ -]?token|private[_ -]?key|password)\b"
)
_REMOTE_FETCH = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_MARKDOWN_LINK_TARGET = re.compile(r"\]\(\s*(https?://[^\s)]+)", re.IGNORECASE)
_MARKDOWN_AUTOLINK = re.compile(r"<(https?://[^>\s]+)>", re.IGNORECASE)
_MARKDOWN_REFERENCE_TARGET = re.compile(
    r"^\s*\[[^\]]+\]:\s*(https?://\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_MARKDOWN_HTML_LINK_TARGET = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["'](https?://[^"']+)["']""",
    re.IGNORECASE,
)
_UNPINNED_INSTALL = re.compile(r"(?i)\b(pip install|npm install|uv add)\b[^;\n]*(\^|~|latest|\*)")
_SYSTEM_PATH = re.compile(r"(?i)\b(/etc/|~/.ssh|/var/|C:\\Windows\\)\b")
_REMOTE_DOWNLOAD = re.compile(r"(?i)\b(curl|wget|fetch)\b.{0,80}\b(http|https)")

_SKILL_RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("W007", "remote_download", _REMOTE_DOWNLOAD, "Remote download instructions in SKILL.md"),
    ("W008", "credential_harvest", _CREDENTIAL, "Credential harvesting language in SKILL.md"),
    ("W009", "shell_execution", _SHELL, "Shell execution guidance in SKILL.md"),
    ("W010", "instruction_override", _INSTRUCTION_OVERRIDE, "Instruction override language in SKILL.md"),
    ("W011", "hidden_unicode", re.compile(""), "Hidden Unicode characters in SKILL.md"),
    ("W012", "exfil_channel", _EXFIL, "Exfiltration instructions in SKILL.md"),
    ("W013", "unpinned_install", _UNPINNED_INSTALL, "Unpinned package install guidance in SKILL.md"),
    ("W014", "system_path_write", _SYSTEM_PATH, "System path references in SKILL.md"),
)


def analyze_skill(entry: SkillEntry) -> list[Finding]:
    """Scan a SKILL.md file for injection, exfil, and credential-harvest patterns."""
    text = entry.content
    if not text.strip():
        return []

    findings: list[Finding] = []
    for code, label, pattern, title in _SKILL_RULES:
        if code == "W011":
            if has_hidden_unicode(text) or has_ansi_smuggling(text):
                controls = find_control_chars(text)
                findings.append(
                    _finding(
                        entry,
                        code,
                        label,
                        title,
                        evidence={"control_chars": controls[:8]},
                    )
                )
            continue
        if pattern.search(text):
            findings.append(_finding(entry, code, label, title))

    remote_urls = _remote_urls_outside_markdown_citations(text)
    if len(remote_urls) >= 3:
        findings.append(
            _finding(
                entry,
                "W007",
                "remote_fetch_volume",
                "Multiple remote URL fetches referenced in SKILL.md",
                evidence={"url_count": len(remote_urls)},
            )
        )

    return findings


def _remote_urls_outside_markdown_citations(text: str) -> list[str]:
    citation_spans = sorted(
        match.span(1)
        for pattern in (
            _MARKDOWN_LINK_TARGET,
            _MARKDOWN_AUTOLINK,
            _MARKDOWN_REFERENCE_TARGET,
            _MARKDOWN_HTML_LINK_TARGET,
        )
        for match in pattern.finditer(text)
    )

    remote_urls: list[str] = []
    span_index = 0
    for match in _REMOTE_FETCH.finditer(text):
        while span_index < len(citation_spans) and citation_spans[span_index][1] <= match.start():
            span_index += 1
        if (
            span_index < len(citation_spans)
            and citation_spans[span_index][0] <= match.start() < citation_spans[span_index][1]
        ):
            continue
        remote_urls.append(match.group(0))

    return remote_urls


def analyze_skills(entries: list[SkillEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in entries:
        findings.extend(analyze_skill(entry))
    return findings


class SkillMdAnalyzer(BaseAnalyzer):
    """Scan discovered agent SKILL.md files for injection and exfil patterns."""

    name = "skill_md"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        entries = [_skill_entry_from_agent(skill) for skill in server.agent_skills]
        return analyze_skills(entries)


def _skill_entry_from_agent(skill: AgentSkillFile) -> SkillEntry:
    return SkillEntry(
        client=skill.origin,
        skill_name=skill.name,
        skill_path=skill.path,
        content_length=len(skill.content),
        content=skill.content,
    )


def _finding(
    entry: SkillEntry,
    code: str,
    label: str,
    title: str,
    *,
    evidence: dict | None = None,
) -> Finding:
    payload = {"issue_code": code, "skill_path": entry.skill_path, "client": entry.client}
    if evidence:
        payload.update(evidence)
    return Finding(
        id=f"skill-md-{entry.skill_name}-{label}",
        analyzer="skill_md",
        title=title,
        description=f"Skill `{entry.skill_name}` ({entry.client}) contains suspicious instruction content.",
        severity=Severity.HIGH,
        recommendation="Review SKILL.md for prompt injection, exfil instructions, or credential harvesting.",
        technique_id="MCTS-T-1001",
        location=SourceLocation(file=entry.skill_path, line=1),
        evidence=payload,
    )
