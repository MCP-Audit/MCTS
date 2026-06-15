"""Runtime telemetry analyzers wired into the main scan pipeline."""

from __future__ import annotations

from typing import Any

from mcts.analyzers.agentic_pr_sabotage import detect_agentic_pr_sabotage
from mcts.analyzers.api_flooding import detect_api_flooding
from mcts.analyzers.api_harvest import detect_api_harvest
from mcts.analyzers.authority_claim_tool import detect_authority_claim_tool
from mcts.analyzers.autonomous_loop import detect_autonomous_loop_event
from mcts.analyzers.backdoored_install import detect_backdoored_install_event
from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.behavioral_extraction import detect_behavioral_extraction
from mcts.analyzers.bridge_hopping import detect_bridge_hopping
from mcts.analyzers.capability_enumeration import detect_capability_enumeration
from mcts.analyzers.chat_backchannel import detect_chat_backchannel
from mcts.analyzers.cli_weaponization import detect_cli_weaponization
from mcts.analyzers.command_injection import detect_command_injection
from mcts.analyzers.compromised_server_pivot import detect_compromised_server_pivot
from mcts.analyzers.consent_fatigue import detect_consent_fatigue
from mcts.analyzers.context_memory_implant import detect_context_memory_implant
from mcts.analyzers.covert_channel import detect_covert_channel
from mcts.analyzers.credential_access import detect_credential_file_access
from mcts.analyzers.credential_relay import detect_credential_relay
from mcts.analyzers.cross_agent_injection import detect_cross_agent_injection
from mcts.analyzers.cross_server_registry import detect_cross_server_shadowing
from mcts.analyzers.cross_tool_contamination import detect_cross_tool_contamination
from mcts.analyzers.csrf_token_relay import detect_csrf_token_relay
from mcts.analyzers.data_destruction import detect_data_destruction
from mcts.analyzers.data_harvesting import detect_data_harvesting
from mcts.analyzers.directory_listing import detect_suspicious_directory_listing
from mcts.analyzers.disinformation_output import detect_disinformation_output
from mcts.analyzers.dns_poisoning import detect_dns_poisoning_event
from mcts.analyzers.dns_resolution_anomaly import detect_dns_resolution_anomaly
from mcts.analyzers.env_file_access import detect_env_file_access
from mcts.analyzers.exposed_endpoint import detect_exposed_endpoint
from mcts.analyzers.fake_tool_invocation import detect_fake_tool_invocation
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.inspector_rce import detect_inspector_rce_event
from mcts.analyzers.instruction_steganography import detect_instruction_steganography
from mcts.analyzers.multimodal_injection import detect_multimodal_injection
from mcts.analyzers.oauth_code_interception import detect_oauth_code_interception
from mcts.analyzers.oauth_escalation_runtime import (
    detect_confused_deputy_event,
    detect_rogue_as_event,
    detect_scope_substitution_event,
)
from mcts.analyzers.oauth_mixup import detect_oauth_mixup_event
from mcts.analyzers.oauth_token_persistence import detect_oauth_token_persistence_event
from mcts.analyzers.over_privileged import detect_over_privileged_process
from mcts.analyzers.parameter_exfil_chain import detect_parameter_exfil_chain
from mcts.analyzers.privilege_tool_abuse import detect_privilege_tool_abuse
from mcts.analyzers.rag_backdoor import detect_rag_backdoor
from mcts.analyzers.response_tampering import detect_response_tampering
from mcts.analyzers.root_privilege_abuse import detect_root_privilege_abuse
from mcts.analyzers.rug_pull import detect_rug_pull_event
from mcts.analyzers.sampling_abuse import detect_sampling_abuse
from mcts.analyzers.sandbox_escape import detect_sandbox_escape
from mcts.analyzers.server_enumeration import detect_server_enumeration
from mcts.analyzers.shared_memory_poisoning import detect_shared_memory_poisoning
from mcts.analyzers.sql_dump import detect_sql_dump
from mcts.analyzers.stego_exfil import detect_stego_exfil
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
from mcts.analyzers.training_data_poisoning import detect_training_data_poisoning
from mcts.analyzers.vector_poisoning import detect_vector_poisoning
from mcts.analyzers.version_enumeration import detect_version_enumeration
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation


class RuntimeEventsAnalyzer(BaseAnalyzer):
    """Analyze runtime/probe telemetry and schema-derived invocation surfaces."""

    name = "runtime_events"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        if server.runtime_events and detect_autonomous_loop_event({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-autonomous-loop",
                    "Repeated identical MCP tool invocations (loop exploit)",
                    None,
                    "MCTS-T-1035",
                    Severity.HIGH,
                    {"type": "autonomous_loop", "event_count": len(server.runtime_events)},
                )
            )
        if server.runtime_events and detect_data_harvesting({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-data-harvest-batch",
                    "High-frequency automated data collection pattern",
                    None,
                    "MCTS-T-1044",
                    Severity.HIGH,
                    {"type": "data_harvesting", "event_count": len(server.runtime_events)},
                )
            )
        if server.runtime_events and detect_tool_enumeration({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-tool-enum-batch",
                    "Abusive MCP tool manifest enumeration",
                    None,
                    "MCTS-T-1042",
                    Severity.MEDIUM,
                    {"type": "tool_enumeration", "event_count": len(server.runtime_events)},
                )
            )
        if server.runtime_events and detect_api_harvest({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-api-harvest-batch",
                    "Coordinated REST/API data harvesting pattern",
                    None,
                    "MCTS-T-1069",
                    Severity.HIGH,
                    {"type": "api_harvest", "event_count": len(server.runtime_events)},
                )
            )
        if server.runtime_events and detect_api_flooding({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-api-flood-batch",
                    "Abusive outbound API request flooding pattern",
                    None,
                    "MCTS-T-1078",
                    Severity.HIGH,
                    {"type": "api_flooding", "event_count": len(server.runtime_events)},
                )
            )
        if server.runtime_events and detect_parameter_exfil_chain({"events": server.runtime_events}):
            findings.append(
                _finding(
                    "runtime-param-exfil-batch",
                    "Collection followed by parameter exfiltration chain",
                    None,
                    "MCTS-T-1070",
                    Severity.CRITICAL,
                    {"type": "parameter_exfil_chain", "event_count": len(server.runtime_events)},
                )
            )
        for index, event in enumerate(server.runtime_events):
            findings.extend(self._analyze_event(event, index))
        for tool in server.tools:
            findings.extend(self._analyze_tool_schema(tool))
        return findings

    def _analyze_event(self, event: dict[str, Any], index: int) -> list[Finding]:
        findings: list[Finding] = []

        tool_name = str(event.get("tool_name", "unknown"))
        params = event.get("tool_parameters")
        if params and detect_command_injection(tool_name=tool_name, tool_parameters=params):
            findings.append(
                _finding(
                    f"runtime-cmd-inject-{index}",
                    "Command injection pattern in tool invocation",
                    tool_name,
                    "MCTS-T-1023",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "command_injection"},
                )
            )

        log = event.get("log_entry", event)
        if isinstance(log, dict) and detect_rug_pull_event(log):
            findings.append(
                _finding(
                    f"runtime-rug-pull-{index}",
                    f"Rug pull behavioral change on {log.get('tool_name', 'tool')}",
                    str(log.get("tool_name", tool_name)),
                    "MCTS-T-1013",
                    Severity.HIGH,
                    {"event_index": index, "type": "rug_pull"},
                )
            )

        if detect_oauth_mixup_event(event):
            findings.append(
                _finding(
                    f"runtime-oauth-mixup-{index}",
                    "OAuth Authorization Server mix-up indicator",
                    None,
                    "MCTS-T-1012",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "oauth_mixup"},
                )
            )

        if detect_sampling_abuse(event):
            findings.append(
                _finding(
                    f"runtime-sampling-abuse-{index}",
                    "Sampling API abuse pattern",
                    str(event.get("server_name", tool_name)),
                    "MCTS-T-1016",
                    Severity.HIGH,
                    {"event_index": index, "type": "sampling_abuse"},
                )
            )

        file_path = str(event.get("file_path") or event.get("path") or "")
        if file_path and detect_credential_file_access(tool_name=tool_name, file_path=file_path):
            findings.append(
                _finding(
                    f"runtime-credential-access-{index}",
                    f"Sensitive credential file access: {file_path}",
                    tool_name,
                    "MCTS-T-1024",
                    Severity.CRITICAL,
                    {"event_index": index, "path": file_path},
                )
            )

        if detect_tool_definition_file_event(event):
            findings.append(
                _finding(
                    f"runtime-tool-redef-{index}",
                    "MCP tool definition file modification",
                    None,
                    "MCTS-T-1040",
                    Severity.HIGH,
                    {"event_index": index, "path": file_path or event.get("name")},
                )
            )

        if detect_tool_redefinition_baseline(
            baseline_tools=list(event.get("baseline_tools") or []),
            current_tools=list(event.get("current_tools") or []),
            metadata_changed=bool(event.get("metadata_changed", False)),
        ):
            findings.append(
                _finding(
                    f"runtime-tool-baseline-{index}",
                    "Tool manifest differs from saved baseline",
                    None,
                    "MCTS-T-1040",
                    Severity.HIGH,
                    {"event_index": index, "type": "baseline_diff"},
                )
            )

        if detect_over_privileged_process(event):
            findings.append(
                _finding(
                    f"runtime-over-priv-{index}",
                    "Over-privileged MCP tool process activity",
                    tool_name,
                    "MCTS-T-1006",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "over_privileged"},
                )
            )

        if detect_behavioral_extraction(event):
            findings.append(
                _finding(
                    f"runtime-behavioral-{index}",
                    "System prompt extraction attempt",
                    None,
                    "MCTS-T-1026",
                    Severity.HIGH,
                    {"event_index": index, "type": "behavioral_extraction"},
                )
            )

        if detect_exposed_endpoint(event):
            findings.append(
                _finding(
                    f"runtime-exposed-endpoint-{index}",
                    "Exposed MCP endpoint access pattern",
                    None,
                    "MCTS-T-1027",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "exposed_endpoint"},
                )
            )

        if detect_dns_poisoning_event(event):
            findings.append(
                _finding(
                    f"runtime-dns-poison-{index}",
                    "DNS or certificate poisoning indicator",
                    None,
                    "MCTS-T-1028",
                    Severity.HIGH,
                    {"event_index": index, "type": "dns_poisoning"},
                )
            )

        tool_output = str(event.get("tool_output") or "")
        if tool_output and detect_tool_output_injection(tool_output=tool_output, tool_name=tool_name):
            findings.append(
                _finding(
                    f"runtime-tool-output-{index}",
                    "Prompt injection pattern in tool output",
                    tool_name,
                    "MCTS-T-1007",
                    Severity.HIGH,
                    {"event_index": index, "type": "tool_output_injection"},
                )
            )

        if detect_cross_server_shadowing(event):
            findings.append(
                _finding(
                    f"runtime-cross-server-{index}",
                    "Cross-server tool shadowing registration",
                    str(event.get("tool_name")),
                    "MCTS-T-1029",
                    Severity.HIGH,
                    {"event_index": index, "type": "cross_server_shadowing"},
                )
            )

        if detect_privilege_tool_abuse(event):
            findings.append(
                _finding(
                    f"runtime-privilege-tool-{index}",
                    "High-privilege MCP tool execution",
                    str(event.get("tool_name", tool_name)),
                    "MCTS-T-1030",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "privilege_tool_abuse"},
                )
            )

        if detect_suspicious_tool_registration(event):
            findings.append(
                _finding(
                    f"runtime-suspicious-reg-{index}",
                    "Suspicious MCP tool registration",
                    None,
                    "MCTS-T-1031",
                    Severity.HIGH,
                    {"event_index": index, "type": "suspicious_registration"},
                )
            )

        if detect_fake_tool_invocation(event):
            findings.append(
                _finding(
                    f"runtime-fake-tool-{index}",
                    "Fake or spoofed MCP tool invocation",
                    str(event.get("tool_name", tool_name)),
                    "MCTS-T-1032",
                    Severity.HIGH,
                    {"event_index": index, "type": "fake_tool_invocation"},
                )
            )

        if detect_sandbox_escape(event):
            findings.append(
                _finding(
                    f"runtime-sandbox-escape-{index}",
                    "Container sandbox escape via runc exec",
                    None,
                    "MCTS-T-1033",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "sandbox_escape"},
                )
            )

        if detect_rogue_as_event(event):
            findings.append(
                _finding(
                    f"runtime-rogue-as-{index}",
                    "Rogue OAuth Authorization Server indicator",
                    None,
                    "MCTS-T-1017",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "rogue_authorization_server"},
                )
            )

        if detect_confused_deputy_event(event):
            findings.append(
                _finding(
                    f"runtime-confused-deputy-{index}",
                    "OAuth confused deputy / token forwarding",
                    None,
                    "MCTS-T-1018",
                    Severity.HIGH,
                    {"event_index": index, "type": "confused_deputy"},
                )
            )

        if detect_scope_substitution_event(event):
            findings.append(
                _finding(
                    f"runtime-scope-substitution-{index}",
                    "OAuth token scope substitution pattern",
                    None,
                    "MCTS-T-1019",
                    Severity.HIGH,
                    {"event_index": index, "type": "scope_substitution"},
                )
            )

        if detect_instruction_steganography(event):
            tool = str(event.get("tool_name") or event.get("tool_id") or tool_name)
            findings.append(
                _finding(
                    f"runtime-steganography-{index}",
                    "Hidden instructions in tool metadata",
                    tool,
                    "MCTS-T-1041",
                    Severity.HIGH,
                    {"event_index": index, "type": "instruction_steganography"},
                )
            )

        if detect_vector_poisoning(event):
            findings.append(
                _finding(
                    f"runtime-vector-poison-{index}",
                    "Vector store embedding metadata contamination",
                    None,
                    "MCTS-T-1034",
                    Severity.HIGH,
                    {"event_index": index, "type": "vector_poisoning"},
                )
            )

        if detect_inspector_rce_event(event):
            findings.append(
                _finding(
                    f"runtime-inspector-rce-{index}",
                    "MCP Inspector remote code execution attempt",
                    None,
                    "MCTS-T-1036",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "inspector_rce"},
                )
            )

        if detect_oauth_token_persistence_event(event):
            findings.append(
                _finding(
                    f"runtime-token-persist-{index}",
                    "OAuth token persistence after logout or rotation",
                    None,
                    "MCTS-T-1037",
                    Severity.HIGH,
                    {"event_index": index, "type": "oauth_token_persistence"},
                )
            )

        if detect_backdoored_install_event(event):
            findings.append(
                _finding(
                    f"runtime-backdoored-install-{index}",
                    "Install-time persistence during MCP package setup",
                    None,
                    "MCTS-T-1038",
                    Severity.HIGH,
                    {"event_index": index, "type": "backdoored_install"},
                )
            )

        if detect_context_memory_implant(event):
            findings.append(
                _finding(
                    f"runtime-memory-implant-{index}",
                    "Context memory implant in vector store",
                    None,
                    "MCTS-T-1039",
                    Severity.HIGH,
                    {"event_index": index, "type": "context_memory_implant"},
                )
            )

        if detect_tool_enumeration(event):
            findings.append(
                _finding(
                    f"runtime-tool-enum-{index}",
                    "MCP tool enumeration abuse",
                    None,
                    "MCTS-T-1042",
                    Severity.MEDIUM,
                    {"event_index": index, "type": "tool_enumeration"},
                )
            )

        if detect_sql_dump(
            tool_name=tool_name,
            tool_parameters=params,
            result=event.get("result"),
        ):
            findings.append(
                _finding(
                    f"runtime-sql-dump-{index}",
                    "SQL database dump pattern via MCP tool",
                    tool_name,
                    "MCTS-T-1043",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "sql_dump"},
                )
            )

        if detect_data_harvesting(event):
            findings.append(
                _finding(
                    f"runtime-data-harvest-{index}",
                    "Automated data harvesting burst",
                    tool_name,
                    "MCTS-T-1044",
                    Severity.HIGH,
                    {"event_index": index, "type": "data_harvesting"},
                )
            )

        if detect_tool_chaining(event):
            findings.append(
                _finding(
                    f"runtime-tool-chain-{index}",
                    "Privilege-escalating tool chain pivot",
                    tool_name,
                    "MCTS-T-1045",
                    Severity.HIGH,
                    {"event_index": index, "type": "tool_chaining"},
                )
            )

        if detect_consent_fatigue(event):
            findings.append(
                _finding(
                    f"runtime-consent-fatigue-{index}",
                    "Consent fatigue approval exploitation",
                    None,
                    "MCTS-T-1046",
                    Severity.HIGH,
                    {"event_index": index, "type": "consent_fatigue"},
                )
            )

        if detect_data_destruction(tool_name=tool_name, tool_parameters=params):
            findings.append(
                _finding(
                    f"runtime-data-destruction-{index}",
                    "Destructive MCP tool invocation",
                    tool_name,
                    "MCTS-T-1048",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "data_destruction"},
                )
            )

        llm_response = str(event.get("llm_response") or event.get("response") or "")
        if detect_covert_channel(tool_parameters=params, tool_output=tool_output):
            findings.append(
                _finding(
                    f"runtime-covert-channel-{index}",
                    "Covert channel / high-entropy exfiltration in tool I/O",
                    tool_name,
                    "MCTS-T-1049",
                    Severity.HIGH,
                    {"event_index": index, "type": "covert_channel"},
                )
            )

        if detect_multimodal_injection(
            content_type=str(event.get("content_type") or ""),
            content=str(event.get("content") or event.get("multimodal_content") or ""),
            metadata=str(event.get("metadata") or ""),
        ):
            findings.append(
                _finding(
                    f"runtime-multimodal-{index}",
                    "Multimodal prompt injection payload",
                    tool_name,
                    "MCTS-T-1050",
                    Severity.HIGH,
                    {"event_index": index, "type": "multimodal_injection"},
                )
            )

        if detect_cli_weaponization(
            command=str(event.get("command") or ""),
            args=event.get("args"),
            tool_parameters=params,
        ):
            findings.append(
                _finding(
                    f"runtime-cli-weapon-{index}",
                    "Dangerous agent CLI flag weaponization",
                    tool_name,
                    "MCTS-T-1051",
                    Severity.HIGH,
                    {"event_index": index, "type": "cli_weaponization"},
                )
            )

        if detect_oauth_code_interception(event):
            findings.append(
                _finding(
                    f"runtime-oauth-code-{index}",
                    "OAuth authorization code interception pattern",
                    None,
                    "MCTS-T-1052",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "oauth_code_interception"},
                )
            )

        if detect_token_pivot(event):
            findings.append(
                _finding(
                    f"runtime-token-pivot-{index}",
                    "Cross-service OAuth token pivot replay",
                    None,
                    "MCTS-T-1053",
                    Severity.HIGH,
                    {"event_index": index, "type": "token_pivot"},
                )
            )

        if detect_capability_enumeration(
            prompt=str(event.get("prompt") or event.get("user_message") or ""),
        ):
            findings.append(
                _finding(
                    f"runtime-capability-enum-{index}",
                    "Capability-mapping prompt enumeration",
                    None,
                    "MCTS-T-1054",
                    Severity.MEDIUM,
                    {"event_index": index, "type": "capability_enumeration"},
                )
            )

        if detect_version_enumeration(
            path=str(event.get("path") or ""),
            url=str(event.get("url") or ""),
            headers=event.get("headers") if isinstance(event.get("headers"), dict) else None,
        ):
            findings.append(
                _finding(
                    f"runtime-version-enum-{index}",
                    "MCP server version fingerprint probing",
                    None,
                    "MCTS-T-1055",
                    Severity.MEDIUM,
                    {"event_index": index, "type": "version_enumeration"},
                )
            )

        if detect_cross_tool_contamination(event):
            findings.append(
                _finding(
                    f"runtime-cross-tool-{index}",
                    "Cross-tool credential contamination",
                    tool_name,
                    "MCTS-T-1056",
                    Severity.HIGH,
                    {"event_index": index, "type": "cross_tool_contamination"},
                )
            )

        llm_response = str(event.get("llm_response") or event.get("response") or "")
        if detect_chat_backchannel(llm_response=llm_response, tool_output=tool_output):
            findings.append(
                _finding(
                    f"runtime-chat-backchannel-{index}",
                    "Chat-based covert backchannel indicator",
                    tool_name,
                    "MCTS-T-1057",
                    Severity.HIGH,
                    {"event_index": index, "type": "chat_backchannel"},
                )
            )

        if detect_stego_exfil(response=llm_response, tool_output=tool_output):
            findings.append(
                _finding(
                    f"runtime-stego-exfil-{index}",
                    "Steganographic exfiltration in code blocks",
                    tool_name,
                    "MCTS-T-1058",
                    Severity.HIGH,
                    {"event_index": index, "type": "stego_exfil"},
                )
            )

        if detect_credential_relay(event):
            findings.append(
                _finding(
                    f"runtime-cred-relay-{index}",
                    "Credential relay chain to privileged tool",
                    tool_name,
                    "MCTS-T-1059",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "credential_relay"},
                )
            )

        if detect_rag_backdoor(event):
            findings.append(
                _finding(
                    f"runtime-rag-backdoor-{index}",
                    "RAG backdoor trigger with skewed retrieval",
                    None,
                    "MCTS-T-1060",
                    Severity.HIGH,
                    {"event_index": index, "type": "rag_backdoor"},
                )
            )

        if detect_server_enumeration(event):
            findings.append(
                _finding(
                    f"runtime-server-enum-{index}",
                    "MCP server network enumeration probing",
                    None,
                    "MCTS-T-1061",
                    Severity.MEDIUM,
                    {"event_index": index, "type": "server_enumeration"},
                )
            )

        if detect_cross_agent_injection(event):
            findings.append(
                _finding(
                    f"runtime-cross-agent-{index}",
                    "Cross-agent instruction injection",
                    None,
                    "MCTS-T-1062",
                    Severity.HIGH,
                    {"event_index": index, "type": "cross_agent_injection"},
                )
            )

        if detect_csrf_token_relay(event):
            findings.append(
                _finding(
                    f"runtime-csrf-relay-{index}",
                    "CSRF-mediated OAuth token relay",
                    None,
                    "MCTS-T-1063",
                    Severity.HIGH,
                    {"event_index": index, "type": "csrf_token_relay"},
                )
            )

        if detect_compromised_server_pivot(event):
            findings.append(
                _finding(
                    f"runtime-server-pivot-{index}",
                    "Compromised MCP server workspace pivot",
                    None,
                    "MCTS-T-1064",
                    Severity.HIGH,
                    {"event_index": index, "type": "compromised_server_pivot"},
                )
            )

        if detect_agentic_pr_sabotage(event):
            findings.append(
                _finding(
                    f"runtime-agentic-pr-{index}",
                    "Suspicious agent/bot pull request touching CI/CD or infra",
                    None,
                    "MCTS-T-1065",
                    Severity.HIGH,
                    {"event_index": index, "type": "agentic_pr_sabotage"},
                )
            )

        if detect_training_data_poisoning(event=event):
            findings.append(
                _finding(
                    f"runtime-training-poison-{index}",
                    "Training pipeline data poisoning marker in MCP output",
                    tool_name,
                    "MCTS-T-1066",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "training_data_poisoning"},
                )
            )

        if file_path and detect_env_file_access(tool_name=tool_name, file_path=file_path):
            findings.append(
                _finding(
                    f"runtime-env-access-{index}",
                    f"Environment or secret file access: {file_path}",
                    tool_name,
                    "MCTS-T-1067",
                    Severity.HIGH,
                    {"event_index": index, "path": file_path, "type": "env_file_access"},
                )
            )

        if detect_suspicious_directory_listing(
            tool_name=tool_name,
            path=file_path,
            directory=str(event.get("directory") or ""),
        ):
            findings.append(
                _finding(
                    f"runtime-dir-list-{index}",
                    "Suspicious directory listing on sensitive path",
                    tool_name,
                    "MCTS-T-1068",
                    Severity.MEDIUM,
                    {"event_index": index, "type": "directory_listing"},
                )
            )

        if detect_api_harvest(event):
            findings.append(
                _finding(
                    f"runtime-api-harvest-{index}",
                    "REST/API endpoint harvesting activity",
                    tool_name,
                    "MCTS-T-1069",
                    Severity.HIGH,
                    {"event_index": index, "type": "api_harvest"},
                )
            )

        if detect_parameter_exfil_chain(event):
            findings.append(
                _finding(
                    f"runtime-param-exfil-{index}",
                    "Sensitive collection followed by outbound exfiltration",
                    tool_name,
                    "MCTS-T-1070",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "parameter_exfil_chain"},
                )
            )

        if detect_root_privilege_abuse(event):
            findings.append(
                _finding(
                    f"runtime-root-priv-{index}",
                    "MCP server root privilege abuse",
                    tool_name,
                    "MCTS-T-1071",
                    Severity.CRITICAL,
                    {"event_index": index, "type": "root_privilege_abuse"},
                )
            )

        if detect_authority_claim_tool(event):
            findings.append(
                _finding(
                    f"runtime-authority-claim-{index}",
                    "Privileged tool invoked after authority-claim pretext",
                    tool_name,
                    "MCTS-T-1072",
                    Severity.HIGH,
                    {"event_index": index, "type": "authority_claim_tool"},
                )
            )

        if detect_response_tampering(event):
            findings.append(
                _finding(
                    f"runtime-response-tamper-{index}",
                    "Response narrative mismatches invoked tool risk",
                    tool_name,
                    "MCTS-T-1073",
                    Severity.HIGH,
                    {"event_index": index, "type": "response_tampering"},
                )
            )

        if detect_dns_resolution_anomaly(event):
            findings.append(
                _finding(
                    f"runtime-dns-anomaly-{index}",
                    "Suspicious DNS resolution for MCP/API endpoint",
                    None,
                    "MCTS-T-1074",
                    Severity.HIGH,
                    {"event_index": index, "type": "dns_resolution_anomaly"},
                )
            )

        if detect_token_api_theft(event):
            findings.append(
                _finding(
                    f"runtime-token-theft-{index}",
                    "OAuth or session token exposed in API response",
                    tool_name,
                    "MCTS-T-1075",
                    Severity.HIGH,
                    {"event_index": index, "type": "token_api_theft"},
                )
            )

        if detect_shared_memory_poisoning(event):
            findings.append(
                _finding(
                    f"runtime-memory-poison-{index}",
                    "Poisoned payload written to shared agent memory",
                    tool_name,
                    "MCTS-T-1076",
                    Severity.HIGH,
                    {"event_index": index, "type": "shared_memory_poisoning"},
                )
            )

        if detect_bridge_hopping(event):
            findings.append(
                _finding(
                    f"runtime-bridge-hop-{index}",
                    "Cross-chain bridge hopping sequence detected",
                    tool_name,
                    "MCTS-T-1077",
                    Severity.HIGH,
                    {"event_index": index, "type": "bridge_hopping"},
                )
            )

        if detect_api_flooding(event):
            findings.append(
                _finding(
                    f"runtime-api-flood-{index}",
                    "External API flooding from MCP agent",
                    tool_name,
                    "MCTS-T-1078",
                    Severity.HIGH,
                    {"event_index": index, "type": "api_flooding"},
                )
            )

        if detect_disinformation_output(event):
            findings.append(
                _finding(
                    f"runtime-disinfo-{index}",
                    "Disinformation or hidden instruction in MCP output",
                    tool_name,
                    "MCTS-T-1079",
                    Severity.HIGH,
                    {"event_index": index, "type": "disinformation_output"},
                )
            )

        return findings

    def _analyze_tool_schema(self, tool: MCPTool) -> list[Finding]:
        defaults = _schema_default_values(tool.input_schema)
        if not defaults:
            return []
        if not detect_command_injection(tool_name=tool.name, tool_parameters=defaults):
            return []
        return [
            _finding(
                f"schema-cmd-inject-{tool.name}",
                f"Command injection pattern in {tool.name} schema defaults",
                tool.name,
                "MCTS-T-1023",
                Severity.HIGH,
                {"type": "schema_default_injection", "defaults": defaults},
                tool=tool,
            )
        ]


def _schema_default_values(schema: Any, prefix: str = "") -> dict[str, str]:
    values: dict[str, str] = {}
    if not isinstance(schema, dict):
        return values
    default = schema.get("default")
    if isinstance(default, str) and default:
        key = prefix or "default"
        values[key] = default
    for prop_name, prop_schema in schema.get("properties", {}).items():
        if isinstance(prop_schema, dict):
            nested = _schema_default_values(prop_schema, prop_name)
            values.update(nested)
    return values


def _finding(
    finding_id: str,
    title: str,
    tool: str | None,
    technique_id: str,
    severity: Severity,
    evidence: dict[str, Any],
    *,
    mcp_tool: MCPTool | None = None,
) -> Finding:
    event_type = str(evidence.get("type") or "runtime_event")
    loc = SourceLocation(
        file=(mcp_tool.source_file if mcp_tool else "") or "",
        line=mcp_tool.source_line if mcp_tool else None,
    )
    rule_id = f"RULE_RUNTIME_{event_type.upper().replace('-', '_')}"
    return build_analyzer_finding(
        finding_id=finding_id,
        analyzer="runtime_events",
        title=title,
        description=title,
        severity=severity,
        recommendation="Review runtime telemetry and tighten tool input validation.",
        rule_id=rule_id,
        match=event_type,
        field="runtime_events",
        tool=tool,
        location=loc if loc.file else None,
        technique_id=technique_id,
        confidence=0.85,
        extra_evidence=evidence,
    )


def events_from_fuzz_findings(findings: list[Any]) -> list[dict[str, Any]]:
    """Convert fuzz findings into runtime event rows for optional scan enrichment."""
    from mcts.probe.events import events_from_fuzz_finding_rows

    return events_from_fuzz_finding_rows(findings)
