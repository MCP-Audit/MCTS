"""MCP server models."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CapabilitySignal(BaseModel):
    """One matched inferrer rule — provenance for capability dimensions."""

    rule_id: str
    dimension: str
    field: str
    match: str
    snippet: str | None = None


class CapabilityProfile(BaseModel):
    reads_untrusted_input: bool = False
    accesses_sensitive_data: bool = False
    mutates_state: bool = False
    egresses_network: bool = False
    executes_commands: bool = False
    signals: list[CapabilitySignal] = Field(default_factory=list)


def _coerce_json_dict(value: Any) -> dict[str, Any]:
    """Accept dict or JSON object string (legacy reports used stringified schemas)."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


class MCPTool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source_file: str | None = None
    source_line: int | None = None
    handler_snippet: str | None = None
    capability: CapabilityProfile | None = None
    discovered_via: str = "static"

    @field_validator("input_schema", mode="before")
    @classmethod
    def coerce_input_schema(cls, value: Any) -> dict[str, Any]:
        return _coerce_json_dict(value)


class MCPPrompt(BaseModel):
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)
    source_file: str | None = None
    source_line: int | None = None
    discovered_via: str = "mcp"


class AgentSkillFile(BaseModel):
    """Agent skill instruction file discovered outside MCP prompts/list."""

    name: str
    path: str
    content: str = ""
    origin: str = "repo"


class MCPResource(BaseModel):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None
    content: str | None = None


class SurfaceScanOptions(BaseModel):
    """Per-scan surface filtering attached during orchestration."""

    surfaces: list[str] = Field(default_factory=list)
    resource_mime_allowlist: list[str] = Field(default_factory=list)


class MCPServerInfo(BaseModel):
    name: str = "unknown"
    version: str = "0.0.0"
    tools: list[MCPTool] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    instructions: str | None = None
    instruction_sources: list[str] = Field(default_factory=list)
    agent_skills: list[AgentSkillFile] = Field(default_factory=list)
    transport: str = "stdio"
    discovery_mode: str = "static"
    source_files: dict[str, str] = Field(default_factory=dict)
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
    surface_scan: SurfaceScanOptions | None = None
    discovery_warnings: list[str] = Field(default_factory=list)
    initialize_succeeded: bool = False
