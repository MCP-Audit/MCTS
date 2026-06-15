"""Main scan orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime

from mcts import __version__
from mcts.analyzers.attack_chains import AttackChainAnalyzer
from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
from mcts.analyzers.cloud_inspect import CloudInspectAnalyzer
from mcts.analyzers.command_execution import CommandExecutionAnalyzer
from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.analyzers.data_leakage import DataLeakageAnalyzer
from mcts.analyzers.embedding_secrets import EmbeddingSecretsAnalyzer
from mcts.analyzers.jailbreak import JailbreakAnalyzer
from mcts.analyzers.line_jumping import LineJumpingAnalyzer
from mcts.analyzers.llm_judge import LlmJudgeAnalyzer
from mcts.analyzers.llm_metadata_triage import LlmMetadataTriageAnalyzer
from mcts.analyzers.metadata_dedupe import dedupe_metadata_findings
from mcts.analyzers.metadata_diff import MetadataDiffAnalyzer, save_baseline
from mcts.analyzers.metadata_integrity import MetadataIntegrityAnalyzer
from mcts.analyzers.npm_audit import NpmAuditAnalyzer
from mcts.analyzers.oauth_config import OAuthConfigAnalyzer
from mcts.analyzers.path_validation import PathValidationAnalyzer
from mcts.analyzers.permissions import PermissionAnalyzer
from mcts.analyzers.prompt_defense import PromptDefenseAnalyzer
from mcts.analyzers.prompt_injection import PromptInjectionAnalyzer
from mcts.analyzers.runtime_events import RuntimeEventsAnalyzer
from mcts.analyzers.schema_surface import SchemaSurfaceAnalyzer
from mcts.analyzers.semgrep_adapter import SemgrepAdapterAnalyzer
from mcts.analyzers.sigma_dedupe import dedupe_sigma_findings
from mcts.analyzers.sigma_metadata import SigmaMetadataAnalyzer
from mcts.analyzers.skill_md import SkillMdAnalyzer
from mcts.analyzers.supply_chain import SupplyChainAnalyzer
from mcts.analyzers.surface_metadata import SurfaceMetadataAnalyzer
from mcts.analyzers.tool_abuse import ToolAbuseAnalyzer
from mcts.analyzers.tool_shadowing import ToolShadowingAnalyzer
from mcts.analyzers.toxic_flows import ToxicFlowAnalyzer
from mcts.analyzers.virustotal import VirusTotalAnalyzer
from mcts.analyzers.vulnerable_package import VulnerablePackageAnalyzer
from mcts.analyzers.yara_metadata import YaraMetadataAnalyzer
from mcts.compliance.checks import ComplianceChecker
from mcts.core.config import ScanConfig
from mcts.core.surface_analyzers import analyzer_allowed_for_surfaces
from mcts.inventory.models import InventoryEntry
from mcts.mcp.client import MCPClient
from mcts.mcp.models import MCPServerInfo, SurfaceScanOptions
from mcts.probe.protocol_checks import probe_protocol_security
from mcts.report.scan_meta import (
    append_chain_scan_notes,
    build_scan_notes,
    infer_scan_scope,
    is_config_static_scan,
    tool_discovery_notice_text,
)
from mcts.reporting.models import Finding, ScanReport, ScanSummary
from mcts.scoring.context import build_scoring_context
from mcts.scoring.engine import RiskScoringEngine
from mcts.scoring.engine_v2 import RiskScoringEngineV2
from mcts.scoring.partitions import score_partitioned
from mcts.scoring.pipeline_trace import record as _trace_pipeline
from mcts.taxonomy.mapper import enrich_findings


class Scanner:
    """Coordinates analyzers and produces a unified security report."""

    def __init__(
        self,
        config: ScanConfig,
        inventory: list[InventoryEntry] | None = None,
    ) -> None:
        self.config = config
        self.client = MCPClient(config.target, config)
        self.inventory = inventory or []
        self.attack_chains = AttackChainAnalyzer()
        self.analyzers = self._build_analyzers()
        self.compliance = ComplianceChecker()
        self.scoring = RiskScoringEngine()

    def _build_analyzers(self) -> list[object]:
        cfg = self.config
        rows: list[object] = [
            PermissionAnalyzer(),
            MetadataIntegrityAnalyzer(skip_poison_checks=cfg.enable_surface_metadata),
            PromptInjectionAnalyzer(),
            ToolShadowingAnalyzer(),
            LineJumpingAnalyzer(),
            ToolAbuseAnalyzer(),
            SchemaSurfaceAnalyzer(),
            DataLeakageAnalyzer(),
            CommandExecutionAnalyzer(),
            PathValidationAnalyzer(),
            RuntimeEventsAnalyzer(),
            SigmaMetadataAnalyzer(sigma_rules_path=cfg.sigma_rules_path),
            OAuthConfigAnalyzer(target=cfg.target, inventory=self.inventory),
            SupplyChainAnalyzer(target=cfg.target),
            EmbeddingSecretsAnalyzer(semantic_secrets=cfg.semantic_secrets),
            MetadataDiffAnalyzer(baseline_path=cfg.baseline_path),
            JailbreakAnalyzer(),
            CrossServerAnalyzer(inventory=self.inventory),
            self.attack_chains,
        ]
        if len(self.inventory) >= 2:
            rows.append(ToxicFlowAnalyzer(inventory=self.inventory))
        if cfg.enable_surface_metadata:
            rows.insert(1, SurfaceMetadataAnalyzer(surfaces=cfg.surfaces))
        if cfg.enable_prompt_defense:
            rows.append(PromptDefenseAnalyzer())
        rows.append(SkillMdAnalyzer())
        if cfg.enable_behavioral_static:
            rows.append(BehavioralStaticAnalyzer())
        if cfg.pip_audit:
            rows.append(VulnerablePackageAnalyzer(target=cfg.target))
        if cfg.npm_audit:
            rows.append(NpmAuditAnalyzer(target=cfg.target))
        if cfg.enable_yara:
            rows.append(YaraMetadataAnalyzer(rules_path=cfg.yara_rules_path))
        if cfg.enable_llm_judge:
            rows.append(LlmJudgeAnalyzer(model=cfg.llm_model))
        if cfg.enable_llm_triage:
            rows.append(LlmMetadataTriageAnalyzer(model=cfg.llm_model))
        if cfg.enable_semgrep:
            rows.append(
                SemgrepAdapterAnalyzer(
                    target=cfg.target,
                    rules_path=cfg.semgrep_rules_path,
                )
            )
        if cfg.enable_cloud_inspect:
            rows.append(CloudInspectAnalyzer(endpoint=cfg.cloud_endpoint))
        if cfg.enable_virustotal:
            rows.append(VirusTotalAnalyzer(target=cfg.target, max_files=cfg.vt_max_files))
        return rows

    def run(self) -> ScanReport:
        """Execute all enabled analyzers against the target MCP server."""
        server_info = self._attach_surface_options(self.client.discover())
        if is_config_static_scan(self.config):
            server_info = server_info.model_copy(update={"discovery_mode": "config-static"})
        return self.analyze_server(server_info)

    def analyze_server(self, server_info: MCPServerInfo) -> ScanReport:
        """Run analyzers against an already-discovered server snapshot."""
        server_info = self._attach_surface_options(server_info)
        runtime_events = list(self.config.runtime_events)
        if self.config.live or self.config.remote_url:
            from mcts.probe.behavioral import events_from_behavioral_probe
            from mcts.probe.events import events_from_live_server, merge_runtime_events

            groups = [
                runtime_events,
                events_from_live_server(server_info),
                events_from_behavioral_probe(server_info, multi_turn=self.config.behavioral_probe),
            ]
            if self.config.enable_jailbreak_live and self.config.live_consent:
                from mcts.probe.jailbreak import events_from_jailbreak_probe

                groups.append(events_from_jailbreak_probe(server_info))
            runtime_events = merge_runtime_events(*groups)
        elif self.config.behavioral_probe:
            from mcts.probe.behavioral import events_from_behavioral_probe
            from mcts.probe.events import merge_runtime_events

            runtime_events = merge_runtime_events(
                runtime_events,
                events_from_behavioral_probe(server_info, multi_turn=True),
            )
        if runtime_events:
            server_info = server_info.model_copy(
                update={
                    "runtime_events": [
                        *server_info.runtime_events,
                        *runtime_events,
                    ]
                }
            )
        findings: list[Finding] = []
        analyzers_executed: list[str] = []
        if server_info.discovery_warnings:
            from mcts.probe.discovery_meta import discovery_meta_findings

            findings.extend(discovery_meta_findings(server_info))
            analyzers_executed.append("live_discovery")

        if not self.config.live and not self.config.remote_url and not self.config.snapshot_path:
            from mcts.discovery.static_meta import static_discovery_meta_findings

            static_meta = static_discovery_meta_findings(server_info, self.config)
            if static_meta:
                findings.extend(static_meta)
                analyzers_executed.append("static_discovery")

        for analyzer in self.analyzers:
            if not self._is_enabled(analyzer):
                continue
            if not self._analyzer_allowed(analyzer):
                continue
            name = getattr(analyzer, "name", type(analyzer).__name__)
            analyzers_executed.append(name)
            findings.extend(analyzer.analyze(server_info))

        if self.config.protocol_probe and self.config.remote_url:
            findings.extend(probe_protocol_security(self.config.remote_url))

        fuzz_note = self._merge_fuzz_findings(findings, analyzers_executed)
        scan_notes_pre = [fuzz_note] if fuzz_note else []

        findings = dedupe_metadata_findings(findings)
        findings = dedupe_sigma_findings(findings)
        findings = enrich_findings(findings)

        raw_graph = self.attack_chains.last_graph if "attack_chains" in analyzers_executed else {}
        _trace_pipeline("graph")

        scan_scope = infer_scan_scope(self.config)
        from mcts.scoring.evidence_emit import enrich_scoring_evidence

        findings = enrich_scoring_evidence(findings, attack_graph=raw_graph, scan_scope=scan_scope)
        _trace_pipeline("scope")

        from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context

        trust_ctx = build_trust_context(
            mode=self.config.findings_trust_mode,
            scan_scope=scan_scope,
            tools=server_info.tools,
            attack_graph=raw_graph,
        )
        findings = apply_trust_layer(findings, trust_ctx)
        from mcts.reporting.trust_apply import collapse_template_severity_if_requested

        findings = collapse_template_severity_if_requested(findings, self.config)

        findings = self._apply_filters(findings)
        from mcts.reporting.finding_validator import validate_findings
        from mcts.reporting.rule_stability import apply_rule_stability

        compliance_raw = self.compliance.check(
            findings,
            tools_discovered=len(server_info.tools),
            findings_trust_mode=self.config.findings_trust_mode,
        )
        if self.config.findings_trust_mode != "off":
            compliance_rows = validate_findings(compliance_raw, trust_ctx)
        else:
            compliance_rows = [apply_rule_stability(row) for row in compliance_raw]
        findings.extend(compliance_rows)
        analyzers_executed.append("compliance")
        scan_notes = build_scan_notes(self.config)
        scan_notes = scan_notes_pre + scan_notes

        use_display_score = self.config.findings_trust_mode == "enforce"
        score = self.scoring.score(findings, use_display=use_display_score)
        _trace_pipeline("v1")
        if not RiskScoringEngine.verify(findings, score, use_display=use_display_score):
            raise RuntimeError("Risk score does not match findings — scoring regression")

        score_v2 = None
        report_attack_graph = raw_graph
        if self.config.scoring_mode in {"v2", "both"}:
            chain_factor_mode = "paths_v1" if self.config.enable_attack_chains else "disabled"
            ctx = build_scoring_context(
                findings=findings,
                server=server_info,
                attack_graph=raw_graph,
                scan_scope=scan_scope,
                config=self.config,
                chain_factor_mode=chain_factor_mode,
            )
            score_v2 = RiskScoringEngineV2().score(ctx, legacy_overall=score.overall)
            if not RiskScoringEngineV2.verify(ctx, score_v2):
                raise RuntimeError("Risk score v2 does not match context — scoring regression")
            report_attack_graph = ctx.attack_graph
            _trace_pipeline("v2")

        summary = ScanSummary.from_findings(findings)
        display_summary = (
            ScanSummary.from_display(findings, security_only=True)
            if self.config.findings_trust_mode != "off"
            else None
        )

        if self.config.save_baseline_path is not None:
            save_baseline(server_info, self.config.save_baseline_path, target=str(self.config.target))
        if server_info.agent_skills or server_info.instruction_sources:
            scan_notes.append(
                "Instruction discovery: found "
                f"{len(server_info.prompts)} prompt surface(s), "
                f"{len(server_info.agent_skills)} SKILL.md file(s), "
                f"{len(server_info.instruction_sources)} system instruction file(s) in repository markdown."
            )

        report = ScanReport(
            version=__version__,
            target=str(self.config.target),
            scanned_at=datetime.now(UTC),
            server=server_info,
            findings=findings,
            summary=summary,
            display_summary=display_summary,
            findings_trust_mode=self.config.findings_trust_mode,
            score=score,
            score_v2=score_v2,
            scoring_version=self.config.scoring_mode,
            attack_graph=report_attack_graph,
            scan_scope=scan_scope,
            scan_notes=scan_notes,
            score_breakdown=score_partitioned(findings, use_display=use_display_score),
            tool_discovery_notice=tool_discovery_notice_text(server_info, scan_scope=scan_scope),
            analyzers_executed=analyzers_executed,
        )
        append_chain_scan_notes(report.scan_notes, report, self.config)
        return report

    def _merge_fuzz_findings(self, findings: list[Finding], analyzers_executed: list[str]) -> str | None:
        """Run protocol fuzz on live scans and merge findings into the static score path."""
        if not (self.config.live or self.config.remote_url):
            return None
        if not self.config.live_consent:
            return None

        from mcts.fuzz.payloads import FuzzLevel
        from mcts.probe.startup_errors import MCPStartupError
        from mcts.taxonomy.mapper import enrich_findings

        level = FuzzLevel(self.config.fuzz_level)
        if level == FuzzLevel.AGGRESSIVE and not self.config.fuzz_consent:
            return None

        try:
            from mcts.fuzz.runner import FuzzRunner

            result = FuzzRunner(self.config).run()
        except MCPStartupError:
            return "Protocol fuzz skipped — live server failed to start."
        except (ValueError, RuntimeError):
            return None

        if not result.findings:
            return f"Protocol fuzz ({result.level.value}): {result.probes_run} probes — no findings."

        fuzz_rows = enrich_findings(list(result.findings))
        findings.extend(fuzz_rows)
        analyzers_executed.append("fuzz")
        return (
            f"Protocol fuzz ({result.level.value}): {result.probes_run} probes — "
            f"{len(fuzz_rows)} finding(s) merged into scan score."
        )

    def _attach_surface_options(self, server_info: MCPServerInfo) -> MCPServerInfo:
        cfg = self.config
        return server_info.model_copy(
            update={
                "surface_scan": SurfaceScanOptions(
                    surfaces=list(cfg.surfaces),
                    resource_mime_allowlist=list(cfg.resource_mime_allowlist),
                )
            }
        )

    def analyzers_run_count(self) -> int:
        """Return the number of security analyzers executed."""
        return sum(
            1
            for analyzer in self.analyzers
            if self._is_enabled(analyzer) and self._analyzer_allowed(analyzer)
        )

    def _is_enabled(self, analyzer: object) -> bool:
        name = type(analyzer).__name__
        if name == "JailbreakAnalyzer":
            return self.config.enable_jailbreak
        if name == "AttackChainAnalyzer":
            if self.config.scoring_mode in {"v2", "both"}:
                return True
            return self.config.enable_attack_chains
        if name == "MetadataDiffAnalyzer":
            return self.config.baseline_path is not None
        if name == "EmbeddingSecretsAnalyzer":
            return self.config.semantic_secrets
        if name == "CrossServerAnalyzer":
            return len(self.inventory) >= 2
        return True

    def _analyzer_allowed(self, analyzer: object) -> bool:
        if self.config.scoring_mode in {"v2", "both"} and getattr(analyzer, "name", None) == "attack_chains":
            return True
        if self.config.analyzers:
            name = getattr(analyzer, "name", type(analyzer).__name__)
            if name not in self.config.analyzers and type(analyzer).__name__ not in self.config.analyzers:
                return False
        return analyzer_allowed_for_surfaces(
            analyzer,
            self.config.surfaces,
            enabled=self.config.surface_scoped_analyzers,
        )

    def _apply_filters(self, findings: list[Finding]) -> list[Finding]:
        rows = findings
        if self.config.analyzer_filter:
            allowed = set(self.config.analyzer_filter)
            rows = [f for f in rows if f.analyzer in allowed]
        if self.config.severity_filter:
            allowed = {s.lower() for s in self.config.severity_filter}
            if self.config.findings_trust_mode == "enforce":
                from mcts.reporting.display import effective_severity

                rows = [f for f in rows if effective_severity(f).value in allowed]
            else:
                rows = [f for f in rows if f.severity.value in allowed]
        if self.config.tool_filter:
            allowed = set(self.config.tool_filter)
            rows = [f for f in rows if f.tool is None or f.tool in allowed]
        if self.config.technique_filter:
            allowed = set(self.config.technique_filter)
            rows = [f for f in rows if f.technique_id in allowed]
        return rows
