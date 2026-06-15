"""Input schema surface analysis."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.schema_fsp import detect_schema_fsp
from mcts.analyzers.tpa_patterns import (
    SUSPICIOUS_SCHEMA_DEFAULTS,
    scan_schema_surface,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_schema_surface_finding

CREDENTIAL_PARAM_NAMES = re.compile(
    r"(?i)^(password|secret|token|api_key|apikey|credential|auth|private_key)$"
)


class SchemaSurfaceAnalyzer(BaseAnalyzer):
    """Detects suspicious input schema patterns (FSP / credential params)."""

    name = "schema_surface"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool))
        return [tag_schema_surface_finding(f) for f in findings]

    def _analyze_tool(self, tool: MCPTool) -> list[Finding]:
        findings: list[Finding] = []
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)
        schema = tool.input_schema
        if detect_schema_fsp(schema if isinstance(schema, dict) else None):
            findings.append(
                build_analyzer_finding(
                    finding_id=f"schema-fsp-{tool.name}",
                    analyzer=self.name,
                    title=f"Full-schema poisoning on {tool.name}",
                    description="Input schema matches MCTS-T-1001.002 full-schema poisoning markers.",
                    severity=Severity.CRITICAL,
                    recommendation="Remove poisoned defaults, enums, and descriptions from schemas.",
                    rule_id="RULE_SCHEMA_FSP",
                    match=tool.name,
                    field="input_schema",
                    tool=tool.name,
                    location=loc,
                    technique_id="MCTS-T-1001.002",
                    confidence=0.85,
                    extra_evidence={"type": "schema_fsp"},
                )
            )

        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        for label, schema_path, severity in scan_schema_surface(schema):
            safe_label = label.replace(".", "-")
            findings.append(
                build_analyzer_finding(
                    finding_id=f"schema-poison-{tool.name}-{safe_label}-{schema_path.replace('.', '-')}",
                    analyzer=self.name,
                    title=f"Schema poisoning pattern on {tool.name}: {label.replace('_', ' ')}",
                    description=f"Suspicious content in schema at {schema_path}.",
                    severity=severity,
                    recommendation="Sanitize parameter names, descriptions, defaults, and enum values.",
                    rule_id="RULE_SCHEMA_POISON",
                    match=label,
                    field=schema_path,
                    tool=tool.name,
                    location=loc,
                    technique_id="MCTS-T-1001.002",
                    confidence=0.8,
                    extra_evidence={"pattern": label, "schema_path": schema_path},
                )
            )

        for param_name, param_schema in properties.items():
            if CREDENTIAL_PARAM_NAMES.match(param_name):
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"schema-cred-param-{tool.name}-{param_name}",
                        analyzer=self.name,
                        title=f"Credential parameter in schema: {tool.name}.{param_name}",
                        description="Tool schema exposes a credential-like parameter to the agent.",
                        severity=Severity.HIGH,
                        recommendation="Never accept secrets via tool parameters; use secure stores.",
                        rule_id="RULE_SCHEMA_CRED_PARAM",
                        match=param_name,
                        field="input_schema.properties",
                        tool=tool.name,
                        location=loc,
                        technique_id="MCTS-T-1001.002",
                        confidence=0.8,
                        extra_evidence={"parameter": param_name},
                    )
                )

            default = param_schema.get("default") if isinstance(param_schema, dict) else None
            if default is not None and SUSPICIOUS_SCHEMA_DEFAULTS.search(str(default)):
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"schema-suspicious-default-{tool.name}-{param_name}",
                        analyzer=self.name,
                        title=f"Suspicious schema default: {tool.name}.{param_name}",
                        description=f"Parameter default value may widen attack surface: {default!r}.",
                        severity=Severity.MEDIUM,
                        recommendation="Remove dangerous defaults from tool input schemas.",
                        rule_id="RULE_SCHEMA_SUSPICIOUS_DEFAULT",
                        match=str(default)[:120],
                        field=f"input_schema.properties.{param_name}.default",
                        tool=tool.name,
                        location=loc,
                        technique_id="MCTS-T-1001.002",
                        confidence=0.7,
                        extra_evidence={"parameter": param_name, "default": str(default)},
                    )
                )

            if param_name in ("path", "file", "filename", "url", "command") and param_name not in required:
                dangerous = param_name in ("command", "url")
                if dangerous or tool.capability and tool.capability.reads_untrusted_input:
                    findings.append(
                        build_analyzer_finding(
                            finding_id=f"schema-optional-danger-{tool.name}-{param_name}",
                            analyzer=self.name,
                            title=f"Optional dangerous param: {tool.name}.{param_name}",
                            description=f"High-risk parameter '{param_name}' is not marked required.",
                            severity=Severity.MEDIUM,
                            recommendation="Require explicit values for sensitive parameters.",
                            rule_id="RULE_SCHEMA_OPTIONAL_DANGER",
                            match=param_name,
                            field="input_schema.required",
                            tool=tool.name,
                            location=loc,
                            technique_id="MCTS-T-1001.002",
                            confidence=0.6,
                            extra_evidence={"parameter": param_name},
                        )
                    )

        return findings
