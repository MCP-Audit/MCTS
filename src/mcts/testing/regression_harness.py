"""Evaluate MCTS detectors against bundled regression fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcts.analyzers.agentic_pr_sabotage import detect_agentic_pr_sabotage
from mcts.analyzers.api_flooding import detect_api_flooding
from mcts.analyzers.api_harvest import detect_api_harvest
from mcts.analyzers.attack_chains import AttackChainAnalyzer
from mcts.analyzers.authority_claim_tool import detect_authority_claim_tool
from mcts.analyzers.autonomous_loop import detect_autonomous_loop_event
from mcts.analyzers.backdoored_install import detect_backdoored_install_event
from mcts.analyzers.behavioral_extraction import detect_behavioral_extraction
from mcts.analyzers.bridge_hopping import detect_bridge_hopping
from mcts.analyzers.capability_enumeration import detect_capability_enumeration
from mcts.analyzers.chat_backchannel import detect_chat_backchannel
from mcts.analyzers.cli_weaponization import detect_cli_weaponization
from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.command_injection import detect_command_injection
from mcts.analyzers.compromised_server_pivot import detect_compromised_server_pivot
from mcts.analyzers.consent_fatigue import detect_consent_fatigue
from mcts.analyzers.context_memory_implant import detect_context_memory_implant
from mcts.analyzers.covert_channel import detect_covert_channel
from mcts.analyzers.credential_access import detect_credential_file_access
from mcts.analyzers.credential_relay import detect_credential_relay
from mcts.analyzers.cross_agent_injection import detect_cross_agent_injection
from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.analyzers.cross_server_registry import detect_cross_server_shadowing
from mcts.analyzers.cross_tool_contamination import detect_cross_tool_contamination
from mcts.analyzers.csrf_token_relay import detect_csrf_token_relay
from mcts.analyzers.data_destruction import detect_data_destruction
from mcts.analyzers.data_harvesting import detect_data_harvesting
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.directory_listing import detect_suspicious_directory_listing
from mcts.analyzers.disinformation_output import detect_disinformation_output
from mcts.analyzers.dns_poisoning import detect_dns_poisoning_event
from mcts.analyzers.dns_resolution_anomaly import detect_dns_resolution_anomaly
from mcts.analyzers.embedding_secrets import EmbeddingSecretsAnalyzer
from mcts.analyzers.env_file_access import detect_env_file_access
from mcts.analyzers.exposed_endpoint import detect_exposed_endpoint
from mcts.analyzers.fake_tool_invocation import detect_fake_tool_invocation
from mcts.analyzers.inspector_rce import detect_inspector_rce_event
from mcts.analyzers.instruction_steganography import detect_instruction_steganography
from mcts.analyzers.line_jumping import detect_line_jumping
from mcts.analyzers.metadata_integrity import MetadataIntegrityAnalyzer
from mcts.analyzers.multimodal_injection import detect_multimodal_injection
from mcts.analyzers.oauth_code_interception import detect_oauth_code_interception
from mcts.analyzers.oauth_escalation_runtime import (
    detect_confused_deputy_event,
    detect_rogue_as_event,
    detect_scope_substitution_event,
)
from mcts.analyzers.oauth_implicit import detect_oauth_implicit_flow
from mcts.analyzers.oauth_mixup import detect_oauth_mixup_event
from mcts.analyzers.oauth_phishing import detect_oauth_phishing_config
from mcts.analyzers.oauth_token_persistence import detect_oauth_token_persistence_event
from mcts.analyzers.over_privileged import detect_over_privileged_process
from mcts.analyzers.parameter_exfil_chain import detect_parameter_exfil_chain
from mcts.analyzers.path_traversal import detect_path_traversal_event
from mcts.analyzers.privilege_tool_abuse import detect_privilege_tool_abuse
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.rag_backdoor import detect_rag_backdoor
from mcts.analyzers.response_tampering import detect_response_tampering
from mcts.analyzers.root_privilege_abuse import detect_root_privilege_abuse
from mcts.analyzers.rug_pull import detect_rug_pull_event
from mcts.analyzers.sampling_abuse import detect_sampling_abuse
from mcts.analyzers.sandbox_escape import detect_sandbox_escape
from mcts.analyzers.schema_fsp import detect_schema_fsp
from mcts.analyzers.schema_surface import SchemaSurfaceAnalyzer
from mcts.analyzers.server_enumeration import detect_server_enumeration
from mcts.analyzers.shared_memory_poisoning import detect_shared_memory_poisoning
from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.sql_dump import detect_sql_dump
from mcts.analyzers.stego_exfil import detect_stego_exfil
from mcts.analyzers.supply_chain_signals import detect_supply_chain_manifest
from mcts.analyzers.suspicious_registration import detect_suspicious_tool_registration
from mcts.analyzers.token_api_theft import detect_token_api_theft
from mcts.analyzers.token_pivot import detect_token_pivot
from mcts.analyzers.tool_chaining import detect_tool_chaining
from mcts.analyzers.tool_enumeration import detect_tool_enumeration
from mcts.analyzers.tool_output_injection import detect_tool_output_injection
from mcts.analyzers.tool_redefinition import (
    detect_tool_definition_file_event,
    detect_tool_redefinition_baseline,
)
from mcts.analyzers.tool_shadowing import detect_tool_shadowing
from mcts.analyzers.training_data_poisoning import detect_training_data_poisoning
from mcts.analyzers.vector_poisoning import detect_vector_poisoning
from mcts.analyzers.version_enumeration import detect_version_enumeration
from mcts.fuzz.classifier import classify_response
from mcts.fuzz.payloads import FuzzLevel, probes_for_level
from mcts.inventory.models import InventoryEntry
from mcts.mcp.models import CapabilityProfile, MCPServerInfo, MCPTool

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "regression"
REGRESSION_THRESHOLD = 80.0
REGRESSION_TECHNIQUES: tuple[str, ...] = (
    "MCTS-T-1001",
    "MCTS-T-1014",
    "MCTS-T-1015",
    "MCTS-T-1028",
    "MCTS-T-1027",
    "MCTS-T-1031",
    "MCTS-T-1011",
    "MCTS-T-1020",
    "MCTS-T-1012",
    "MCTS-T-1023",
    "MCTS-T-1007",
    "MCTS-T-1032",
    "MCTS-T-1006",
    "MCTS-T-1002",
    "MCTS-T-1003",
    "MCTS-T-1004",
    "MCTS-T-1005",
    "MCTS-T-1008",
    "MCTS-T-1009",
    "MCTS-T-1010",
    "MCTS-T-1022",
    "MCTS-T-1016",
    "MCTS-T-1013",
    "MCTS-T-1040",
    "MCTS-T-1021",
    "MCTS-T-1001.002",
    "MCTS-T-1024",
    "MCTS-T-1029",
    "MCTS-T-1030",
    "MCTS-T-1033",
    "MCTS-T-1026",
    "MCTS-T-1017",
    "MCTS-T-1018",
    "MCTS-T-1019",
    "MCTS-T-1041",
    "MCTS-T-1034",
    "MCTS-T-1035",
    "MCTS-T-1036",
    "MCTS-T-1037",
    "MCTS-T-1038",
    "MCTS-T-1039",
    "MCTS-T-1042",
    "MCTS-T-1043",
    "MCTS-T-1044",
    "MCTS-T-1045",
    "MCTS-T-1046",
    "MCTS-T-1047",
    "MCTS-T-1048",
    "MCTS-T-1049",
    "MCTS-T-1050",
    "MCTS-T-1051",
    "MCTS-T-1052",
    "MCTS-T-1053",
    "MCTS-T-1054",
    "MCTS-T-1055",
    "MCTS-T-1056",
    "MCTS-T-1057",
    "MCTS-T-1058",
    "MCTS-T-1059",
    "MCTS-T-1060",
    "MCTS-T-1061",
    "MCTS-T-1062",
    "MCTS-T-1063",
    "MCTS-T-1064",
    "MCTS-T-1065",
    "MCTS-T-1066",
    "MCTS-T-1067",
    "MCTS-T-1068",
    "MCTS-T-1069",
    "MCTS-T-1070",
    "MCTS-T-1071",
    "MCTS-T-1072",
    "MCTS-T-1073",
    "MCTS-T-1074",
    "MCTS-T-1075",
    "MCTS-T-1076",
    "MCTS-T-1077",
    "MCTS-T-1078",
    "MCTS-T-1079",
)


@dataclass(frozen=True)
class RegressionCase:
    case_id: str
    expect: bool
    payload: dict[str, Any]


@dataclass(frozen=True)
class RegressionResult:
    technique_id: str
    total: int
    correct: int
    false_positives: list[str]
    false_negatives: list[str]

    @property
    def accuracy_pct(self) -> float:
        if self.total == 0:
            return 100.0
        return round(100.0 * self.correct / self.total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "total": self.total,
            "correct": self.correct,
            "accuracy_pct": self.accuracy_pct,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
        }


def detect_metadata_poison(tool_name: str, description: str) -> bool:
    """Return True when metadata analyzers (post-dedupe) flag the tool."""
    tool = MCPTool(
        name=tool_name,
        description=description,
        input_schema={"type": "object", "properties": {}},
    )
    server = MCPServerInfo(name="parity", tools=[tool])
    findings: list = []
    findings.extend(PromptInjectionAnalyzer().analyze(server))
    findings.extend(MetadataIntegrityAnalyzer().analyze(server))
    findings.extend(SchemaSurfaceAnalyzer().analyze(server))
    findings.extend(SigmaMetadataAnalyzer().analyze(server))
    findings = [f for f in dedupe_sigma_findings(findings) if f.technique_id not in {"MCTS-T-1020"}]
    return any(f.tool == tool_name for f in findings)


def _static_server(entry: dict[str, Any]) -> MCPServerInfo:
    tool_rows = entry.get("tools")
    if not isinstance(tool_rows, list):
        tool_rows = [entry]
    tools: list[MCPTool] = []
    for row in tool_rows:
        if not isinstance(row, dict):
            continue
        cap = row.get("capability")
        capability = CapabilityProfile(**cap) if isinstance(cap, dict) else None
        tools.append(
            MCPTool(
                name=str(row.get("tool_name") or row.get("name") or "tool"),
                description=str(row.get("tool_description") or row.get("description") or ""),
                handler_snippet=row.get("handler_snippet"),
                source_file=row.get("source_file"),
                input_schema=row.get("input_schema") or {},
                capability=capability,
            )
        )
    source_files = dict(entry.get("source_files") or {})
    if entry.get("source_content") and entry.get("source_file"):
        source_files[str(entry["source_file"])] = str(entry["source_content"])
    return MCPServerInfo(name="regression", tools=tools, source_files=source_files)


def detect_command_execution_static(entry: dict[str, Any]) -> bool:
    findings = CommandExecutionAnalyzer().analyze(_static_server(entry))
    return any(f.analyzer == "command_execution" for f in findings)


def detect_data_leakage_static(entry: dict[str, Any]) -> bool:
    findings = DataLeakageAnalyzer().analyze(_static_server(entry))
    return any(f.analyzer == "data_leakage" for f in findings)


def detect_attack_chain_static(entry: dict[str, Any]) -> bool:
    findings = AttackChainAnalyzer().analyze(_static_server(entry))
    return any(f.analyzer == "attack_chains" for f in findings)


def detect_cross_server_static(entry: dict[str, Any]) -> bool:
    rows = entry.get("inventory") or []
    inventory = [
        InventoryEntry(
            client=str(row.get("client", "test")),
            config_path=str(row.get("config_path", "/tmp/config.json")),
            server_name=str(row.get("server_name", "server")),
            tools=list(row.get("tools") or []),
        )
        for row in rows
        if isinstance(row, dict)
    ]
    if len(inventory) < 2:
        return False
    findings = CrossServerAnalyzer(inventory).analyze_inventory(inventory)
    return any(f.technique_id == "MCTS-T-1008" for f in findings)


def detect_fuzz_static(entry: dict[str, Any]) -> bool:
    probe_id = str(entry.get("probe_id", "malformed-json"))
    probe = next((p for p in probes_for_level(FuzzLevel.SAFE) if p.id == probe_id), None)
    if probe is None:
        return False
    return (
        classify_response(
            probe,
            str(entry.get("response_text", "")),
            process_exited=bool(entry.get("process_exited", False)),
        )
        is not None
    )


def detect_sigma_metadata_static(entry: dict[str, Any]) -> bool:
    findings = SigmaMetadataAnalyzer().analyze(_static_server(entry))
    return any(f.analyzer == "sigma_metadata" for f in findings)


def detect_embedding_secrets_static(entry: dict[str, Any]) -> bool:
    findings = EmbeddingSecretsAnalyzer(semantic_secrets=True).analyze(_static_server(entry))
    return any(f.analyzer == "embedding_secrets" and not (f.evidence or {}).get("skipped") for f in findings)


def detect_shadowing_case(entry: dict[str, Any]) -> bool:
    schema = entry.get("parameters")
    input_schema: dict[str, Any] | None = None
    if isinstance(schema, dict):
        input_schema = {"type": "object", "properties": schema}
    return detect_tool_shadowing(
        tool_name=str(entry.get("tool_name", "")),
        description=str(entry.get("tool_description", "")),
        server_name=str(entry.get("server_name", "")),
        input_schema=input_schema,
    )


def detect_line_jumping_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_line_jumping(
        str(log.get("context_content", "")),
        context_position=int(log.get("context_position", 0)),
        content_source=str(log.get("content_source", "")),
        authenticated=bool(log.get("authenticated", False)),
    )


def detect_path_case(entry: dict[str, Any]) -> bool:
    return detect_path_traversal_event(
        tool_name=str(entry.get("tool_name", "")),
        path=str(entry.get("path", "")),
        result=entry.get("result"),
    )


def detect_command_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_command_injection(
        tool_name=str(log.get("tool_name", "")),
        tool_parameters=log.get("tool_parameters"),
    )


def detect_rug_pull_case(entry: dict[str, Any]) -> bool:
    log = entry.get("log_entry", entry)
    return detect_rug_pull_event(log)


def detect_oauth_case(entry: dict[str, Any]) -> bool:
    config = entry.get("config", entry)
    if isinstance(config, dict):
        return detect_oauth_phishing_config(config)
    return False


def detect_fsp_case(entry: dict[str, Any]) -> bool:
    schema = entry.get("input_schema")
    if isinstance(schema, dict):
        return detect_schema_fsp(schema)
    return False


def detect_oauth_mixup_case(entry: dict[str, Any]) -> bool:
    return detect_oauth_mixup_event(entry)


def detect_sampling_case(entry: dict[str, Any]) -> bool:
    return detect_sampling_abuse(entry)


def detect_credential_access_case(entry: dict[str, Any]) -> bool:
    return detect_credential_file_access(
        tool_name=str(entry.get("tool_name", "")),
        file_path=str(entry.get("file_path") or entry.get("path") or ""),
    )


def detect_tool_redefinition_case(entry: dict[str, Any]) -> bool:
    if "baseline_tools" in entry:
        return detect_tool_redefinition_baseline(
            baseline_tools=list(entry.get("baseline_tools") or []),
            current_tools=list(entry.get("current_tools") or []),
            metadata_changed=bool(entry.get("metadata_changed", False)),
        )
    return detect_tool_definition_file_event(entry)


def detect_over_privileged_case(entry: dict[str, Any]) -> bool:
    return detect_over_privileged_process(entry)


def detect_behavioral_extraction_case(entry: dict[str, Any]) -> bool:
    return detect_behavioral_extraction(entry)


def detect_exposed_endpoint_case(entry: dict[str, Any]) -> bool:
    return detect_exposed_endpoint(entry)


def detect_dns_poisoning_case(entry: dict[str, Any]) -> bool:
    return detect_dns_poisoning_event(entry)


def detect_supply_chain_case(entry: dict[str, Any]) -> bool:
    return detect_supply_chain_manifest(entry)


def detect_tool_output_case(entry: dict[str, Any]) -> bool:
    return detect_tool_output_injection(
        tool_output=str(entry.get("tool_output", "")),
        tool_name=str(entry.get("tool_name", "")),
    )


def detect_cross_server_registry_case(entry: dict[str, Any]) -> bool:
    return detect_cross_server_shadowing(entry)


def detect_privilege_tool_case(entry: dict[str, Any]) -> bool:
    return detect_privilege_tool_abuse(entry)


def detect_suspicious_registration_case(entry: dict[str, Any]) -> bool:
    return detect_suspicious_tool_registration(entry)


def detect_fake_tool_case(entry: dict[str, Any]) -> bool:
    return detect_fake_tool_invocation(entry)


def detect_sandbox_escape_case(entry: dict[str, Any]) -> bool:
    return detect_sandbox_escape(entry)


def detect_rogue_as_case(entry: dict[str, Any]) -> bool:
    return detect_rogue_as_event(entry)


def detect_confused_deputy_case(entry: dict[str, Any]) -> bool:
    return detect_confused_deputy_event(entry)


def detect_scope_substitution_case(entry: dict[str, Any]) -> bool:
    return detect_scope_substitution_event(entry)


def detect_instruction_steganography_case(entry: dict[str, Any]) -> bool:
    return detect_instruction_steganography(entry)


def detect_vector_poisoning_case(entry: dict[str, Any]) -> bool:
    return detect_vector_poisoning(entry)


def detect_autonomous_loop_case(entry: dict[str, Any]) -> bool:
    return detect_autonomous_loop_event(entry)


def detect_inspector_rce_case(entry: dict[str, Any]) -> bool:
    return detect_inspector_rce_event(entry)


def detect_oauth_token_persistence_case(entry: dict[str, Any]) -> bool:
    return detect_oauth_token_persistence_event(entry)


def detect_backdoored_install_case(entry: dict[str, Any]) -> bool:
    return detect_backdoored_install_event(entry)


def detect_context_memory_implant_case(entry: dict[str, Any]) -> bool:
    return detect_context_memory_implant(entry)


def load_cases(technique_id: str) -> list[RegressionCase]:
    logs_path = FIXTURES_ROOT / technique_id / "test-logs.json"
    expected_path = FIXTURES_ROOT / technique_id / "expected.json"
    if not logs_path.exists() or not expected_path.exists():
        return []

    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    if technique_id == "MCTS-T-1034":
        return _cases_ndjson(logs_path, expected)

    if technique_id == "MCTS-T-1001":
        return _cases_t1001(expected)

    raw = json.loads(logs_path.read_text(encoding="utf-8"))
    if technique_id == "MCTS-T-1020":
        return _cases_t1008(raw, expected)
    if technique_id == "MCTS-T-1002":
        return _cases_t1105(raw, expected)
    if technique_id == "MCTS-T-1021":
        return _cases_t1401(raw, expected)
    if technique_id in {"MCTS-T-1011", "MCTS-T-1001.002"}:
        return _cases_simple_array(raw, expected)
    if technique_id == "MCTS-T-1023":
        return _cases_t1101(raw, expected)
    if technique_id == "MCTS-T-1013":
        return _cases_t1201(raw, expected)
    if technique_id == "MCTS-T-1012":
        return _cases_t1009(raw, expected)
    if technique_id == "MCTS-T-1016":
        return _cases_simple_array(raw, expected)
    if technique_id == "MCTS-T-1024":
        return _cases_t1502(raw, expected)
    if technique_id == "MCTS-T-1040":
        return _cases_simple_array(raw, expected)
    if technique_id in {"MCTS-T-1006", "MCTS-T-1027", "MCTS-T-1029"}:
        return _cases_should_trigger_array(raw, expected)
    if technique_id == "MCTS-T-1026":
        return _cases_t1603(raw, expected)
    if technique_id == "MCTS-T-1028":
        return _cases_t1004(raw, expected)
    if technique_id in {
        "MCTS-T-1014",
        "MCTS-T-1015",
        "MCTS-T-1007",
        "MCTS-T-1031",
        "MCTS-T-1032",
        "MCTS-T-1033",
    }:
        return _cases_simple_array(raw, expected)
    if technique_id == "MCTS-T-1030":
        return _cases_simple_array(raw, expected)
    if technique_id == "MCTS-T-1017":
        return _cases_indexed_array(raw, expected)
    if technique_id == "MCTS-T-1018":
        return _cases_simple_array(raw, expected)
    if technique_id == "MCTS-T-1019":
        return _cases_t1308(raw, expected)
    if technique_id == "MCTS-T-1041":
        return _cases_indexed_array(raw, expected)
    if technique_id == "MCTS-T-1035":
        return _cases_t1106(raw, expected)
    if technique_id == "MCTS-T-1036":
        return _cases_t1109(raw, expected)
    if technique_id in {"MCTS-T-1037", "MCTS-T-1038"}:
        return _cases_scenarios(raw, expected)
    if technique_id == "MCTS-T-1039":
        return _cases_simple_array(raw, expected)
    if technique_id in {
        "MCTS-T-1003",
        "MCTS-T-1004",
        "MCTS-T-1005",
        "MCTS-T-1008",
        "MCTS-T-1009",
        "MCTS-T-1010",
        "MCTS-T-1022",
    }:
        return _cases_simple_array(raw, expected)
    if technique_id in {
        "MCTS-T-1042",
        "MCTS-T-1043",
        "MCTS-T-1044",
        "MCTS-T-1045",
        "MCTS-T-1046",
        "MCTS-T-1047",
        "MCTS-T-1048",
        "MCTS-T-1049",
        "MCTS-T-1050",
        "MCTS-T-1051",
        "MCTS-T-1052",
        "MCTS-T-1053",
        "MCTS-T-1054",
        "MCTS-T-1055",
        "MCTS-T-1056",
        "MCTS-T-1057",
        "MCTS-T-1058",
        "MCTS-T-1059",
        "MCTS-T-1060",
        "MCTS-T-1061",
        "MCTS-T-1062",
        "MCTS-T-1063",
        "MCTS-T-1064",
        "MCTS-T-1065",
        "MCTS-T-1066",
        "MCTS-T-1067",
        "MCTS-T-1068",
        "MCTS-T-1069",
        "MCTS-T-1070",
        "MCTS-T-1071",
        "MCTS-T-1072",
        "MCTS-T-1073",
        "MCTS-T-1074",
        "MCTS-T-1075",
        "MCTS-T-1076",
        "MCTS-T-1077",
        "MCTS-T-1078",
        "MCTS-T-1079",
    }:
        return _cases_simple_array(raw, expected)
    return []


def _cases_t1001(expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    logs_path = FIXTURES_ROOT / "MCTS-T-1001" / "test-logs.json"
    for line in logs_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        tool_name = str(row.get("tool_name", "unknown"))
        cases.append(
            RegressionCase(
                case_id=tool_name,
                expect=expected.get(tool_name, False),
                payload={"tool_name": tool_name, "tool_description": row.get("tool_description", "")},
            )
        )
    return cases


def _cases_t1008(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for category, entries in raw.items():
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            case_id = f"{category}:{entry.get('tool_name', index)}:{index}"
            cases.append(
                RegressionCase(
                    case_id=case_id,
                    expect=expected.get(case_id, False),
                    payload=entry,
                )
            )
    return cases


def _cases_t1105(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for bucket in ("positive_test_cases", "negative_test_cases"):
        entries = raw.get(bucket, [])
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            case_id = f"{bucket}:{index}"
            cases.append(
                RegressionCase(
                    case_id=case_id,
                    expect=expected.get(case_id, bucket.startswith("positive")),
                    payload=entry,
                )
            )
    return cases


def _cases_simple_array(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("case_id", f"case_{index}"))
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expect", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1101(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("id", f"case_{index}"))
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1201(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("should_trigger", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1009(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("name", f"case_{index}"))
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(
                    case_id,
                    len(entry.get("expected_alerts") or []) > 0,
                ),
                payload=entry,
            )
        )
    return cases


def _cases_t1502(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_should_trigger_array(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("should_trigger", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1603(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("id", f"case_{index}"))
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, entry.get("expected_result") == "detect"),
                payload=entry,
            )
        )
    return cases


def _cases_t1004(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def _cases_t1106(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    return [
        RegressionCase(
            case_id="batch_positive",
            expect=expected.get("batch_positive", True),
            payload={"events": raw},
        ),
        RegressionCase(
            case_id="single_event",
            expect=expected.get("single_event", False),
            payload={"events": raw[:1]},
        ),
        RegressionCase(
            case_id="two_events",
            expect=expected.get("two_events", False),
            payload={"events": raw[:2]},
        ),
    ]


def _cases_t1109(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        log_entry = entry.get("log_entry", entry)
        cases.append(
            RegressionCase(
                case_id=f"case:{index}",
                expect=expected.get(f"case:{index}", bool(entry.get("should_trigger", False))),
                payload={"log_entry": log_entry} if isinstance(log_entry, dict) else entry,
            )
        )
    return cases


def _cases_scenarios(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for bucket in ("test_scenarios", "benign_scenarios"):
        for scenario in raw.get(bucket, []):
            if not isinstance(scenario, dict):
                continue
            case_id = str(scenario.get("scenario_id", ""))
            cases.append(
                RegressionCase(
                    case_id=case_id,
                    expect=expected.get(case_id, bool(scenario.get("expected_detection", False))),
                    payload={"logs": list(scenario.get("logs") or [])},
                )
            )
    return cases


def _cases_indexed_array(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = f"case:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, False),
                payload=entry,
            )
        )
    return cases


def _cases_t1308(raw: dict[str, Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw.get("test_cases", [])):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("test_id", f"case_{index}"))
        log_entry = entry.get("log_entry", entry)
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_match", False))),
                payload={"log_entry": log_entry} if isinstance(log_entry, dict) else entry,
            )
        )
    return cases


def _cases_ndjson(logs_path: Path, expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, line in enumerate(logs_path.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        case_id = f"line:{index}"
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, False),
                payload=row,
            )
        )
    return cases


def _cases_t1401(raw: list[Any], expected: dict[str, bool]) -> list[RegressionCase]:
    cases: list[RegressionCase] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        case_id = str(entry.get("test_case", f"case_{index}"))
        cases.append(
            RegressionCase(
                case_id=case_id,
                expect=expected.get(case_id, bool(entry.get("expected_detection", False))),
                payload=entry,
            )
        )
    return cases


def detect_case(technique_id: str, case: RegressionCase) -> bool:
    if technique_id == "MCTS-T-1001":
        return detect_metadata_poison(
            str(case.payload.get("tool_name", "")),
            str(case.payload.get("tool_description", "")),
        )
    if technique_id == "MCTS-T-1020":
        return detect_shadowing_case(case.payload)
    if technique_id == "MCTS-T-1002":
        return detect_path_case(case.payload)
    if technique_id == "MCTS-T-1003":
        return detect_command_execution_static(case.payload)
    if technique_id == "MCTS-T-1004":
        return detect_data_leakage_static(case.payload)
    if technique_id == "MCTS-T-1005":
        return detect_attack_chain_static(case.payload)
    if technique_id == "MCTS-T-1008":
        return detect_cross_server_static(case.payload)
    if technique_id == "MCTS-T-1009":
        return detect_fuzz_static(case.payload)
    if technique_id == "MCTS-T-1010":
        return detect_sigma_metadata_static(case.payload)
    if technique_id == "MCTS-T-1022":
        return detect_embedding_secrets_static(case.payload)
    if technique_id == "MCTS-T-1021":
        return detect_line_jumping_case(case.payload)
    if technique_id == "MCTS-T-1023":
        return detect_command_case(case.payload)
    if technique_id == "MCTS-T-1013":
        return detect_rug_pull_case(case.payload)
    if technique_id == "MCTS-T-1011":
        return detect_oauth_case(case.payload)
    if technique_id == "MCTS-T-1001.002":
        return detect_fsp_case(case.payload)
    if technique_id == "MCTS-T-1012":
        return detect_oauth_mixup_case(case.payload)
    if technique_id == "MCTS-T-1016":
        return detect_sampling_case(case.payload)
    if technique_id == "MCTS-T-1024":
        return detect_credential_access_case(case.payload)
    if technique_id == "MCTS-T-1040":
        return detect_tool_redefinition_case(case.payload)
    if technique_id == "MCTS-T-1006":
        return detect_over_privileged_case(case.payload)
    if technique_id == "MCTS-T-1026":
        return detect_behavioral_extraction_case(case.payload)
    if technique_id == "MCTS-T-1027":
        return detect_exposed_endpoint_case(case.payload)
    if technique_id == "MCTS-T-1028":
        return detect_dns_poisoning_case(case.payload)
    if technique_id == "MCTS-T-1014":
        return detect_supply_chain_case({**case.payload, "technique_scenario": "MCTS-T-1014"})
    if technique_id == "MCTS-T-1015":
        return detect_supply_chain_case({**case.payload, "technique_scenario": "MCTS-T-1015"})
    if technique_id == "MCTS-T-1007":
        return detect_tool_output_case(case.payload)
    if technique_id == "MCTS-T-1029":
        return detect_cross_server_registry_case(case.payload)
    if technique_id == "MCTS-T-1030":
        return detect_privilege_tool_case(case.payload)
    if technique_id == "MCTS-T-1031":
        return detect_suspicious_registration_case(case.payload)
    if technique_id == "MCTS-T-1032":
        return detect_fake_tool_case(case.payload)
    if technique_id == "MCTS-T-1033":
        return detect_sandbox_escape_case(case.payload)
    if technique_id == "MCTS-T-1017":
        return detect_rogue_as_case(case.payload)
    if technique_id == "MCTS-T-1018":
        return detect_confused_deputy_case(case.payload)
    if technique_id == "MCTS-T-1019":
        return detect_scope_substitution_case(case.payload)
    if technique_id == "MCTS-T-1041":
        return detect_instruction_steganography_case(case.payload)
    if technique_id == "MCTS-T-1034":
        return detect_vector_poisoning_case(case.payload)
    if technique_id == "MCTS-T-1035":
        return detect_autonomous_loop_case(case.payload)
    if technique_id == "MCTS-T-1036":
        return detect_inspector_rce_case(case.payload)
    if technique_id == "MCTS-T-1037":
        return detect_oauth_token_persistence_case(case.payload)
    if technique_id == "MCTS-T-1038":
        return detect_backdoored_install_case(case.payload)
    if technique_id == "MCTS-T-1039":
        return detect_context_memory_implant_case(case.payload)
    if technique_id == "MCTS-T-1042":
        return detect_tool_enumeration(case.payload)
    if technique_id == "MCTS-T-1043":
        return detect_sql_dump(
            tool_name=str(case.payload.get("tool_name", "")),
            tool_parameters=case.payload.get("tool_parameters"),
            result=case.payload.get("result"),
        )
    if technique_id == "MCTS-T-1044":
        return detect_data_harvesting(case.payload)
    if technique_id == "MCTS-T-1045":
        return detect_tool_chaining(case.payload)
    if technique_id == "MCTS-T-1046":
        return detect_consent_fatigue(case.payload)
    if technique_id == "MCTS-T-1047":
        config = case.payload.get("config", case.payload)
        return detect_oauth_implicit_flow(config) if isinstance(config, dict) else False
    if technique_id == "MCTS-T-1048":
        return detect_data_destruction(
            tool_name=str(case.payload.get("tool_name", "")),
            tool_parameters=case.payload.get("tool_parameters"),
        )
    if technique_id == "MCTS-T-1049":
        return detect_covert_channel(tool_parameters=case.payload.get("tool_parameters"))
    if technique_id == "MCTS-T-1050":
        return detect_multimodal_injection(
            content_type=str(case.payload.get("content_type", "")),
            content=str(case.payload.get("content", "")),
        )
    if technique_id == "MCTS-T-1051":
        return detect_cli_weaponization(command=str(case.payload.get("command", "")))
    if technique_id == "MCTS-T-1052":
        return detect_oauth_code_interception(case.payload)
    if technique_id == "MCTS-T-1053":
        return detect_token_pivot(case.payload)
    if technique_id == "MCTS-T-1054":
        return detect_capability_enumeration(prompt=str(case.payload.get("prompt", "")))
    if technique_id == "MCTS-T-1055":
        return detect_version_enumeration(path=str(case.payload.get("path", "")))
    if technique_id == "MCTS-T-1056":
        return detect_cross_tool_contamination(case.payload)
    if technique_id == "MCTS-T-1057":
        return detect_chat_backchannel(llm_response=str(case.payload.get("llm_response", "")))
    if technique_id == "MCTS-T-1058":
        return detect_stego_exfil(response=str(case.payload.get("response", "")))
    if technique_id == "MCTS-T-1059":
        return detect_credential_relay(case.payload)
    if technique_id == "MCTS-T-1060":
        return detect_rag_backdoor(case.payload)
    if technique_id == "MCTS-T-1061":
        return detect_server_enumeration(case.payload)
    if technique_id == "MCTS-T-1062":
        return detect_cross_agent_injection(case.payload)
    if technique_id == "MCTS-T-1063":
        return detect_csrf_token_relay(case.payload)
    if technique_id == "MCTS-T-1064":
        return detect_compromised_server_pivot(case.payload)
    if technique_id == "MCTS-T-1065":
        return detect_agentic_pr_sabotage(case.payload)
    if technique_id == "MCTS-T-1066":
        return detect_training_data_poisoning(event=case.payload)
    if technique_id == "MCTS-T-1067":
        return detect_env_file_access(
            tool_name=str(case.payload.get("tool_name", "")),
            file_path=str(case.payload.get("file_path") or case.payload.get("path") or ""),
        )
    if technique_id == "MCTS-T-1068":
        return detect_suspicious_directory_listing(
            tool_name=str(case.payload.get("tool_name", "")),
            path=str(case.payload.get("path") or ""),
        )
    if technique_id == "MCTS-T-1069":
        return detect_api_harvest(case.payload)
    if technique_id == "MCTS-T-1070":
        return detect_parameter_exfil_chain(case.payload)
    if technique_id == "MCTS-T-1071":
        return detect_root_privilege_abuse(case.payload)
    if technique_id == "MCTS-T-1072":
        return detect_authority_claim_tool(case.payload)
    if technique_id == "MCTS-T-1073":
        return detect_response_tampering(case.payload)
    if technique_id == "MCTS-T-1074":
        return detect_dns_resolution_anomaly(case.payload)
    if technique_id == "MCTS-T-1075":
        return detect_token_api_theft(case.payload)
    if technique_id == "MCTS-T-1076":
        return detect_shared_memory_poisoning(case.payload)
    if technique_id == "MCTS-T-1077":
        return detect_bridge_hopping(case.payload)
    if technique_id == "MCTS-T-1078":
        return detect_api_flooding(case.payload)
    if technique_id == "MCTS-T-1079":
        return detect_disinformation_output(case.payload)
    return False


def evaluate_technique(technique_id: str) -> RegressionResult:
    cases = load_cases(technique_id)
    false_positives: list[str] = []
    false_negatives: list[str] = []
    correct = 0

    for case in cases:
        detected = detect_case(technique_id, case)
        if detected == case.expect:
            correct += 1
        elif detected and not case.expect:
            false_positives.append(case.case_id)
        else:
            false_negatives.append(case.case_id)

    return RegressionResult(
        technique_id=technique_id,
        total=len(cases),
        correct=correct,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def regression_summary() -> list[RegressionResult]:
    results: list[RegressionResult] = []
    if not FIXTURES_ROOT.exists():
        return results
    for technique_dir in sorted(FIXTURES_ROOT.iterdir()):
        if not technique_dir.is_dir():
            continue
        if not (technique_dir / "test-logs.json").exists():
            continue
        if not (technique_dir / "expected.json").exists():
            continue
        results.append(evaluate_technique(technique_dir.name))
    return results


def write_regression_report(path: Path) -> list[RegressionResult]:
    summary = regression_summary()
    payload = {
        "threshold_pct": REGRESSION_THRESHOLD,
        "techniques": [row.to_dict() for row in summary],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return summary


def scoring_corpus_absolute_risks(*, scoring_mode: str = "v2") -> dict[str, int]:
    """Delegate to corpus_runner — same data path as scripts/run_scoring_corpus.py."""
    from mcts.scoring.corpus_runner import scan_corpus_absolute_risks

    return scan_corpus_absolute_risks(scoring_mode=scoring_mode)
