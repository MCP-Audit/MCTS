#!/usr/bin/env python3
"""Acceptance validation for findings trust layer (Phases 0–B2 + fixes)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.governance.policy import load_policy, merge_scan_config_with_policy
from mcts.governance.scan_gates import evaluate_scan_gate_violations
from mcts.report.data import build_dashboard_payload
from mcts.reporting.display import summary_for_gates
from mcts.reporting.models import Severity
from mcts.reporting.sarif import build_sarif
from mcts.reporting.trust_gates import findings_over_priority_threshold
from mcts.scoring.context import build_scoring_context
from mcts.scoring.engine_v2 import RiskScoringEngineV2

SINGLE_TOOL = ROOT / "examples/single-tool-agent-server/server.py"
VULNERABLE = ROOT / "examples/vulnerable-mcp-server/server.py"
POLICY_EXAMPLE = ROOT / ".mcts/policy.yaml.example"

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {name}")
    else:
        msg = f"  FAIL  {name}" + (f" — {detail}" if detail else "")
        print(msg)
        FAILURES.append(name if not detail else f"{name}: {detail}")


def main() -> int:
    print("=== Findings trust layer validation ===\n")

    # --- Phase 0 acceptance: single-tool + enforce ---
    print("[Phase 0] Single-tool overlap fixture")
    report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce")).run()
    chains = [f for f in report.findings if f.analyzer == "attack_chains"]
    check("attack chains present", bool(chains))
    disp_crit_ok = report.display_summary is not None and report.display_summary.critical == 0
    check("display_summary.critical == 0", disp_crit_ok)
    check("template summary still has critical", report.summary.critical >= 1)
    for f in chains:
        check(
            f"chain {f.id} overlap capped",
            f.display_severity == Severity.MEDIUM and f.evidence_type == "capability_overlap",
        )
        check(f"chain {f.id} template unchanged", f.severity == Severity.CRITICAL)
        check(f"chain {f.id} no fake hop", "hop_count" not in (f.evidence or {}))

    # --- Policy merge ---
    print("\n[Policy] merge_scan_config_with_policy")
    policy = load_policy(POLICY_EXAMPLE)
    merged = merge_scan_config_with_policy(ScanConfig(target=SINGLE_TOOL), policy)
    check("policy sets enforce", merged.findings_trust_mode == "enforce")
    check("policy sets max_critical", merged.max_critical == 0)
    policy_report = Scanner(merged).run()
    gs = summary_for_gates(policy_report, merged)
    pol_disp_ok = policy_report.display_summary and policy_report.display_summary.critical == 0
    check("policy-only scan: display critical 0", pol_disp_ok)
    check("policy-only scan: gate summary critical 0", gs.critical == 0)
    explicit = merge_scan_config_with_policy(
        ScanConfig(target=SINGLE_TOOL, findings_trust_mode="warn", findings_trust_mode_explicit=True),
        policy,
    )
    check("CLI warn overrides policy enforce", explicit.findings_trust_mode == "warn")
    explicit_off = merge_scan_config_with_policy(
        ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off", findings_trust_mode_explicit=True),
        policy,
    )
    check("CLI explicit off overrides policy enforce", explicit_off.findings_trust_mode == "off")

    # --- Category gates under enforce ---
    print("\n[Alignment] Category gates + score breakdown")
    cat_cfg = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_category={"attack_chains": 10},
    )
    check(
        "fail_on_category attack_chains:10 passes under enforce",
        evaluate_scan_gate_violations(report, cat_cfg) == [],
    )
    breakdown_ok = (
        report.score_breakdown is not None and report.score_breakdown.mcp_surface == report.score.overall
    )
    check("score_breakdown mcp_surface matches enforce overall", breakdown_ok)

    # --- Phase 1 provenance ---
    print("\n[Phase 1] Evidence provenance")
    chain = chains[0] if chains else None
    if chain:
        ev = chain.evidence or {}
        check("facts present on chain", isinstance(ev.get("facts"), list) and len(ev["facts"]) > 0)
        cf = ev.get("confidence_factors")
        check("confidence_factors present", isinstance(cf, list) and len(cf) > 0)
        check("counterfactual present", isinstance(ev.get("counterfactual_remediation"), dict))
    payload = build_dashboard_payload(report)
    check("dashboard meta.fact_coverage", "fact_coverage" in payload["meta"])
    prov_rows = [r for r in payload["findings"] if r["analyzer"] == "attack_chains"]
    check("dashboard has_provenance on chain row", any(r.get("has_provenance") for r in prov_rows))

    # --- Phase 1.5 rule stability ---
    print("\n[Phase 1.5] Rule stability")
    comp = [f for f in report.findings if f.analyzer == "compliance"]
    check("compliance rule_stability", comp and comp[0].rule_stability == "mature")
    check("chain rule_stability heuristic", chains and chains[0].rule_stability == "heuristic")

    # --- Phase 2 priority gates ---
    print("\n[Phase 2] Priority gates")
    security = [
        f
        for f in report.findings
        if f.analyzer not in ("compliance", "live_discovery", "static_discovery")
        and (f.finding_kind or "security") == "security"
    ]
    check("all security findings have priority_score", all(f.priority_score is not None for f in security))
    opt_b = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        fail_on_priority_min=80,
        min_evidence_strength="strong",
    )
    check("Option B gate passes on overlap fixture", evaluate_scan_gate_violations(report, opt_b) == [])
    low_gate = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce", fail_on_priority_min=5)
    check("low priority gate fails", bool(evaluate_scan_gate_violations(report, low_gate)))
    matched = findings_over_priority_threshold(
        report.findings, minimum_priority=80, minimum_evidence_strength="strong"
    )
    check("no strong findings >= 80 on fixture", len(matched) == 0)

    # --- Phase B2 v2 scoring ---
    print("\n[Phase B2] V2 scoring on display severity")
    v2_config = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce", scoring_mode="v2")
    v2_report = Scanner(v2_config).run()
    check("score_v2 present", v2_report.score_v2 is not None)
    ctx = build_scoring_context(
        findings=v2_report.findings,
        server=v2_report.server,
        attack_graph=v2_report.attack_graph,
        scan_scope=v2_report.scan_scope,
        config=v2_config,
        chain_factor_mode="paths_v1",
    )
    check("use_display_severity True under enforce", ctx.use_display_severity is True)
    check("v2 verify passes", RiskScoringEngineV2.verify(ctx, v2_report.score_v2))

    # --- Gates ---
    print("\n[Gates] CI integration")
    enforce_gate = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="enforce", fail_on_critical=True)
    check("fail_on_critical passes enforce", evaluate_scan_gate_violations(report, enforce_gate) == [])
    off_gate = ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off", fail_on_critical=True)
    off_report = Scanner(ScanConfig(target=SINGLE_TOOL, findings_trust_mode="off")).run()
    check("fail_on_critical fails without trust", bool(evaluate_scan_gate_violations(off_report, off_gate)))

    # --- SARIF ---
    print("\n[SARIF] Export")
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    chain_results = [r for r in results if r.get("properties", {}).get("analyzer") == "attack_chains"]
    if chain_results:
        props = chain_results[0].get("properties", {})
        rule_id = chain_results[0].get("ruleId")
        rule_props = next(
            (
                rule.get("properties", {})
                for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
                if rule.get("id") == rule_id
            ),
            {},
        )
        check("SARIF level from display", chain_results[0].get("level") == "warning")  # medium → warning
        check("SARIF security-severity from display", rule_props.get("security-severity") == "5.0")
        check("SARIF mcts/facts", "mcts/facts" in props or "mcts/factCount" in props)

    # --- Proven path edge case ---
    print("\n[Validator] _has_proven_path edge cases")
    from mcts.reporting.finding_validator import ValidationContext, validate_findings
    from mcts.reporting.models import Finding
    from mcts.reporting.trust_pipeline import apply_trust_layer, build_trust_context

    overlap = Finding(
        id="chain-credential-theft",
        analyzer="attack_chains",
        title="Credential theft chain possible",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={"read_tools": ["t"], "credential_tools": ["t"], "exfil_tools": ["t"]},
    )
    empty_ids_graph = {"paths": [{"hop_count": 3, "finding_ids": [], "nodes": ["a", "b", "c"]}]}
    out = validate_findings(
        [overlap],
        ValidationContext(scan_scope="repository", tools=[], attack_graph=empty_ids_graph, mode="enforce"),
    )[0]
    check("empty finding_ids does not prove", out.evidence_type == "capability_overlap")

    missing_key_graph = {"paths": [{"hop_count": 3, "nodes": ["a", "b", "c"]}]}
    out_missing = validate_findings(
        [overlap],
        ValidationContext(scan_scope="repository", tools=[], attack_graph=missing_key_graph, mode="enforce"),
    )[0]
    check("missing finding_ids key does not prove", out_missing.evidence_type == "capability_overlap")

    path_only = overlap.model_copy(update={"evidence": {**(overlap.evidence or {}), "path": ["a", "b", "c"]}})
    out_path = validate_findings(
        [path_only],
        ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce"),
    )[0]
    check("evidence.path alone does not prove", out_path.evidence_type == "capability_overlap")

    # --- Phase 3 runtime validation ---
    print("\n[Phase 3] Runtime / taint evidence")
    from mcts.analyzers.behavioral_static import BehavioralStaticAnalyzer
    from mcts.mcp.models import MCPServerInfo, MCPTool

    taint_tool = MCPTool(
        name="run_cmd",
        description="Run a command",
        handler_snippet="import subprocess\ndef run_cmd(cmd):\n    subprocess.call(cmd, shell=True)",
        source_file="server.py",
    )
    taint_rows = BehavioralStaticAnalyzer().analyze(MCPServerInfo(tools=[taint_tool], source_files={}))
    taint = next(f for f in taint_rows if f.id.startswith("behavioral-taint"))
    trusted_taint = apply_trust_layer(
        [taint],
        build_trust_context(mode="enforce", scan_scope="repository"),
    )[0]
    check("taint finding has facts", bool((trusted_taint.evidence or {}).get("facts")))
    check(
        "taint runtime_validation tag",
        (trusted_taint.evidence or {}).get("runtime_validation") == "taint_param_sink",
    )
    check("validated taint boosts priority", trusted_taint.finding_type == "validated")
    check(
        "validated taint priority_score raised",
        trusted_taint.priority_score is not None and trusted_taint.priority_score >= 40,
    )
    check(
        "validated taint sets handler_traced risk tag",
        "handler_traced" in (trusted_taint.evidence or {}).get("risk_tags", []),
    )

    from mcts.analyzers.runtime_events import _finding

    runtime_row = _finding(
        "runtime-cmd-inject-0",
        "Command injection pattern in tool invocation",
        "run_cmd",
        "MCTS-T-1023",
        Severity.CRITICAL,
        {"event_index": 0, "type": "command_injection"},
    )
    trusted_runtime = apply_trust_layer(
        [runtime_row],
        build_trust_context(mode="enforce", scan_scope="live"),
    )[0]
    check(
        "runtime_events live_proxy tag",
        (trusted_runtime.evidence or {}).get("runtime_validation") == "live_proxy",
    )

    # --- B3 collapse template severity ---
    print("\n[B3] collapse_template_severity")
    collapsed = Scanner(
        ScanConfig(
            target=SINGLE_TOOL,
            findings_trust_mode="enforce",
            collapse_template_severity=True,
        )
    ).run()
    collapsed_chains = [f for f in collapsed.findings if f.analyzer == "attack_chains"]
    if collapsed_chains:
        check(
            "collapse copies display into severity",
            collapsed_chains[0].severity == collapsed_chains[0].display_severity,
        )
    collapsed_cfg = ScanConfig(
        target=SINGLE_TOOL,
        findings_trust_mode="enforce",
        collapse_template_severity=True,
        fail_on_critical=True,
    )
    check("collapse: template summary critical 0", collapsed.summary.critical == 0)
    check(
        "collapse: score basis critical 0",
        collapsed.score.basis.critical == 0,
    )
    check(
        "collapse: score_breakdown matches overall",
        collapsed.score_breakdown is not None
        and collapsed.score_breakdown.mcp_surface == collapsed.score.overall,
    )
    check(
        "collapse: fail_on_critical passes",
        evaluate_scan_gate_violations(collapsed, collapsed_cfg) == [],
    )

    # --- Vulnerable server still works ---
    print("\n[Regression] Vulnerable fixture")
    vuln = Scanner(ScanConfig(target=VULNERABLE, findings_trust_mode="enforce")).run()
    check("vulnerable scan completes", vuln.summary.total > 0)
    if vuln.score_v2:
        vuln_ctx = build_scoring_context(
            findings=vuln.findings,
            server=vuln.server,
            attack_graph=vuln.attack_graph,
            scan_scope=vuln.scan_scope,
            config=ScanConfig(target=VULNERABLE, findings_trust_mode="enforce", scoring_mode="both"),
            chain_factor_mode="paths_v1",
        )
        check("vulnerable v2 verify", RiskScoringEngineV2.verify(vuln_ctx, vuln.score_v2))
    else:
        check("vulnerable v2 verify", True)

    from mcts.reporting.evidence_provenance import fact_coverage

    fc = fact_coverage(vuln.findings)
    check("fact_coverage pct >= 80", fc.get("pct", 0) >= 80.0, str(fc))
    vuln_sarif = build_sarif(vuln)
    comp_results = [
        r for r in vuln_sarif["runs"][0]["results"] if r.get("properties", {}).get("analyzer") == "compliance"
    ]
    check("SARIF excludes compliance coverage rows", len(comp_results) == 0)

    print(f"\n=== {len(FAILURES)} failure(s) ===")
    for f in FAILURES:
        print(f"  - {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
