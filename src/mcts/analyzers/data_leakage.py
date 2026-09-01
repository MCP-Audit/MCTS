"""Sensitive data leakage detection."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_data_leakage_finding

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), Severity.CRITICAL),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.CRITICAL),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z\-_]+"), Severity.CRITICAL),
    (
        "GitHub PAT",
        re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})"),
        Severity.CRITICAL,
    ),
    ("GitLab PAT", re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), Severity.CRITICAL),
    ("npm Access Token", re.compile(r"npm_[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("PyPI API Token", re.compile(r"pypi-[A-Za-z0-9_-]{20,}"), Severity.CRITICAL),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"), Severity.HIGH),
    (
        "Bearer Token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        Severity.HIGH,
    ),
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)[\"']?(?:api[_-]?(?:key|token)|client[_-]?secret|access[_-]?token|"
            r"auth[_-]?token|refresh[_-]?token|private[_-]?key|webhook[_-]?secret|"
            r"signing[_-]?secret|database[_-]?password|db[_-]?password|password|secret|token)"
            r"[\"']?\s*[:=]\s*"
            r"[\"']?[A-Za-z0-9_./+=:@-]{8,}"
        ),
        Severity.HIGH,
    ),
    ("Database URL", re.compile(r"(?i)(postgres|mysql|mongodb)://\S+"), Severity.HIGH),
    (
        "Internal URL",
        re.compile(r"https?://(?:localhost|127\.0\.0\.1|internal|\.local)\S*"),
        Severity.MEDIUM,
    ),
]

SECRET_ENV_VARS = (
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "HUGGINGFACE_TOKEN",
    "LANGFUSE_SECRET_KEY",
    "LANGSMITH_API_KEY",
    "MISTRAL_API_KEY",
    "NPM_TOKEN",
    "PINECONE_API_KEY",
    "PYPI_API_TOKEN",
    "WANDB_API_KEY",
)

HIDDEN_CHAR_PATTERN = re.compile(r"[\u200b-\u200f\ufeff\u202a-\u202e]")

TEMPLATE_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:YOUR_(?:API_)?KEY|REPLACE_WITH(?:_[A-Z0-9]+)*|INSERT_(?:API_)?KEY(?:_HERE)?)\b"
)

LOGGING_CALL_PATTERN = re.compile(
    r"""
    ^\s*
    (?:
        print
        |console\.(?:log|info|warn|warning|error|debug)
        |(?:logger|logging|log)\.(?:log|info|warn|warning|error|debug|exception|critical)
        |(?:self\.)?logger\.(?:log|info|warn|warning|error|debug|exception|critical)
    )
    \s*\(
    """,
    re.VERBOSE,
)


def _is_logging_statement(line: str) -> bool:
    return bool(LOGGING_CALL_PATTERN.search(line))


def _redact_secrets(line: str) -> str:
    """Return bounded context with every recognized credential removed."""
    redacted = line
    for _, pattern, _ in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted.strip()[:120]


def _is_template_secret(match: re.Match[str]) -> bool:
    """Recognize explicit copy-paste placeholders without hiding nearby credentials."""
    return bool(TEMPLATE_SECRET_PATTERN.search(match.group(0)))


class DataLeakageAnalyzer(BaseAnalyzer):
    """Scans tool metadata and source files for exposed secrets."""

    name = "data_leakage"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_metadata(server))
        findings.extend(self._scan_source_files(server))
        return [tag_data_leakage_finding(f) for f in findings]

    def _scan_metadata(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            corpus = f"{tool.name} {tool.description} {tool.input_schema}"
            for label, pattern, severity in SECRET_PATTERNS:
                if pattern.search(corpus):
                    findings.append(
                        Finding(
                            id=f"leak-meta-{tool.name}-{label.lower().replace(' ', '-')}",
                            analyzer=self.name,
                            title=f"Potential {label} exposure in {tool.name}",
                            description=f"Pattern matching {label} found in tool metadata.",
                            severity=severity,
                            tool=tool.name,
                            recommendation="Remove secrets from tool definitions; use secure secret stores.",
                            technique_id="MCTS-T-1004",
                            confidence=0.8,
                            location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                            evidence={"pattern": pattern.pattern},
                        )
                    )
            for env_var in SECRET_ENV_VARS:
                if env_var in corpus:
                    findings.append(
                        Finding(
                            id=f"leak-env-{tool.name}-{env_var.lower()}",
                            analyzer=self.name,
                            title=f"Referenced sensitive env var: {env_var}",
                            description="Tool metadata references environment variables that may leak.",
                            severity=Severity.MEDIUM,
                            tool=tool.name,
                            recommendation=f"Avoid exposing {env_var} through tool responses.",
                            technique_id="MCTS-T-1004",
                            confidence=0.7,
                            location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                            evidence={"env_var": env_var},
                        )
                    )
        return findings

    def _scan_source_files(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for file_path, content in server.source_files.items():
            for line_no, line in enumerate(content.splitlines(), start=1):
                for label, pattern, severity in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    if _is_template_secret(match):
                        continue
                    if label == "Internal URL" and _is_logging_statement(line):
                        continue
                    finding_id = f"leak-src-{file_path}-{line_no}-{label.lower().replace(' ', '-')}"
                    if finding_id in seen:
                        continue
                    seen.add(finding_id)
                    findings.append(
                        Finding(
                            id=finding_id,
                            analyzer=self.name,
                            title=f"Potential {label} in source",
                            description=f"Pattern matching {label} found at {file_path}:{line_no}.",
                            severity=severity,
                            recommendation="Remove hardcoded secrets; use environment or secret managers.",
                            technique_id="MCTS-T-1004",
                            confidence=0.7,
                            location=SourceLocation(file=file_path, line=line_no),
                            evidence={"pattern": pattern.pattern, "line": _redact_secrets(line)},
                        )
                    )
        return findings
