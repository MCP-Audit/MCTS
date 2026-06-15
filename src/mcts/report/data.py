"""Transform ScanReport models into dashboard JSON payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mcts.compliance.checks import MCP_ANALYZER_MAP, OWASP_LLM_ANALYZER_MAP, OWASP_MCP_TOP10
from mcts.mcp.models import CapabilityProfile
from mcts.report.analyzer_catalog import analyzer_info
from mcts.report.scan_meta import tool_discovery_context
from mcts.reporting.display import effective_impact, effective_severity, report_trust_enforced
from mcts.reporting.evidence_provenance import fact_coverage
from mcts.reporting.models import Finding, ScanReport, ScanSummary, Severity, SourceLocation
from mcts.scoring.engine import RISK_WEIGHTS
from mcts.taxonomy.mapper import technique_catalog
from mcts.taxonomy.mitigation_urls import mitigation_links, technique_url

CAPABILITY_DIMS: tuple[tuple[str, str], ...] = (
    ("reads_untrusted_input", "Reads Input"),
    ("accesses_sensitive_data", "Sensitive Data"),
    ("mutates_state", "Mutates State"),
    ("egresses_network", "Network Egress"),
    ("executes_commands", "Executes Commands"),
)

SCAN_SCOPE_LABELS: dict[str, str] = {
    "repository": "Static repository",
    "entrypoint": "Entrypoint static",
    "live": "Live probe",
    "snapshot": "Snapshot",
}


def _llm_owasp_catalog() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Build LLM Top 10 catalog from compliance analyzer map."""
    grouped: dict[str, tuple[str, set[str]]] = {}
    for analyzer, full_label in OWASP_LLM_ANALYZER_MAP.items():
        owasp_id = full_label.split()[0]
        short_label = full_label[len(owasp_id) + 1 :]
        if owasp_id not in grouped:
            grouped[owasp_id] = (short_label, set())
        grouped[owasp_id][1].add(analyzer)
    return tuple(
        (owasp_id, grouped[owasp_id][0], tuple(sorted(grouped[owasp_id][1])))
        for owasp_id in sorted(grouped.keys())
    )


OWASP_CATALOG = _llm_owasp_catalog()

CATEGORY_DEFS: tuple[tuple[str, str, int, tuple[str, ...]], ...] = (
    ("permissions", "Excessive Permissions", 20, ("permission_analyzer",)),
    ("injection", "Injection & Metadata", 20, ("prompt_injection", "metadata_integrity", "schema_surface")),
    ("execution", "Execution & Path Risk", 15, ("command_execution", "path_validation", "tool_abuse")),
    ("data_leakage", "Data Leakage Risk", 15, ("data_leakage",)),
    ("attack_chains", "Attack Chain Risk", 15, ("attack_chains",)),
    ("shadowing", "Cross-Server Shadowing", 5, ("cross_server",)),
    ("jailbreak", "Jailbreak Resistance", 10, ("jailbreak",)),
)

ANALYZER_LABELS: dict[str, str] = {
    "permission_analyzer": "Permission Analyzer",
    "prompt_injection": "Prompt Injection",
    "tool_abuse": "Tool Abuse",
    "data_leakage": "Data Leakage",
    "schema_surface": "Schema Surface",
    "command_execution": "Command Execution",
    "path_validation": "Path Validation",
    "metadata_integrity": "Metadata Integrity",
    "cross_server": "Cross-Server Shadowing",
    "jailbreak": "Jailbreak",
    "attack_chains": "Attack Chains",
    "fuzz": "Protocol Fuzzing",
    "compliance": "Compliance",
    "sigma_metadata": "Sigma Metadata Rules",
    "oauth_config": "OAuth Configuration",
    "metadata_diff": "Metadata Baseline Diff",
    "supply_chain": "Supply Chain",
    "live_discovery": "Live Discovery",
    "surface_metadata": "Surface Metadata",
    "prompt_defense": "Prompt Defense",
    "behavioral_static": "Behavioral Static",
    "embedding_secrets": "Embedding Secrets",
    "runtime_events": "Runtime Events",
    "vulnerable_package": "Vulnerable Packages",
    "npm_audit": "npm Audit",
    "semgrep_sast": "Semgrep SAST",
    "llm_metadata_triage": "LLM Metadata Triage",
    "llm_judge": "LLM Judge",
    "toxic_flows": "Toxic Flows",
    "tool_shadowing": "Tool Shadowing",
    "line_jumping": "Line Jumping",
    "yara_metadata": "YARA Metadata",
    "skill_md": "Skill / Instruction Files",
    "cloud_inspect": "Cloud Inspect",
    "virustotal": "VirusTotal",
    "protocol_probe": "Protocol Probe",
    "discovery_meta": "Discovery Metadata",
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

INDUSTRY_BENCHMARK: dict[str, float] = {
    "permissions": 8,
    "injection": 6,
    "execution": 5,
    "data_leakage": 5,
    "attack_chains": 4,
    "shadowing": 2,
    "jailbreak": 3,
}

# v2 OWASP tile health benchmarks (100 = good) — corpus-informed defaults for dashboard overlay.
INDUSTRY_BENCHMARK_V2: dict[str, int] = {
    "injection": 82,
    "exfiltration": 80,
    "privilege": 78,
    "supply_chain": 88,
    "protocol": 80,
}

RISK_GUIDE = (
    {
        "key": "critical",
        "label": "Critical",
        "range": "0–25",
        "badge": "CRITICAL RISK",
        "color": "#ef4444",
        "description": "Immediate remediation required. Severe exposure to exploitation.",
    },
    {
        "key": "high",
        "label": "High",
        "range": "26–50",
        "badge": "HIGH RISK",
        "color": "#f97316",
        "description": "Significant weaknesses present. Prioritize fixes this sprint.",
    },
    {
        "key": "medium",
        "label": "Medium",
        "range": "51–75",
        "badge": "MEDIUM RISK",
        "color": "#facc15",
        "description": "Moderate risk posture. Schedule hardening within 30 days.",
    },
    {
        "key": "low",
        "label": "Low",
        "range": "76–100",
        "badge": "LOW RISK",
        "color": "#22c55e",
        "description": "Strong security posture. Maintain monitoring and regression scans.",
    },
)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -(f.priority_score if f.priority_score is not None else -1),
            SEVERITY_ORDER[effective_severity(f)],
            f.title,
        ),
    )


def format_location(location: SourceLocation | None) -> str:
    """Human-readable file:line for dashboard tables."""
    if location is None:
        return "—"
    if location.line is not None:
        return f"{location.file}:{location.line}"
    return location.file


def format_confidence(confidence: float) -> str:
    pct = round(confidence * 100)
    return f"{pct}%"


def format_evidence_summary(evidence: dict[str, Any]) -> str:
    """One-line preview for findings table."""
    if not evidence:
        return ""
    facts = evidence.get("facts")
    if isinstance(facts, list) and facts:
        first = facts[0]
        if isinstance(first, dict):
            rule = first.get("rule_id", "")
            match = first.get("match", "")
            tool = first.get("tool", "")
            lead = f"{rule}: {match}" if rule else str(match)
            if tool:
                lead = f"{tool} — {lead}"
            if len(facts) > 1:
                lead += f" (+{len(facts) - 1} signal(s))"
            return lead
    parts: list[str] = []
    for key in ("rule_id", "matched", "missing_mcp_categories", "read_tools", "exfil_tools"):
        if key in evidence and evidence[key]:
            value = evidence[key]
            if isinstance(value, list):
                text = ", ".join(str(item) for item in value[:3])
                if len(value) > 3:
                    text += f" (+{len(value) - 3})"
            else:
                text = str(value)
            parts.append(f"{key}: {text}")
    if parts:
        return "; ".join(parts)
    return f"{len(evidence)} field(s)"


def owasp_ids_for_analyzer(analyzer: str) -> list[str]:
    full = OWASP_LLM_ANALYZER_MAP.get(analyzer)
    if full:
        return [full.split()[0]]
    return [oid for oid, _, names in OWASP_CATALOG if analyzer in names]


def _mcp_catalog() -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    """MCP Top 10 rows: (id, short label, full label, mapped analyzers)."""
    rows: list[tuple[str, str, str, tuple[str, ...]]] = []
    for full_label in OWASP_MCP_TOP10:
        mcp_id = full_label.split()[0]
        short_label = full_label[len(mcp_id) + 1 :]
        analyzers = tuple(
            analyzer for analyzer, category in MCP_ANALYZER_MAP.items() if category == full_label
        )
        rows.append((mcp_id, short_label, full_label, analyzers))
    return tuple(rows)


def risk_rating(score: int) -> tuple[str, str]:
    if score <= 25:
        return "CRITICAL RISK", "critical"
    if score <= 50:
        return "HIGH RISK", "high"
    if score <= 75:
        return "MEDIUM RISK", "medium"
    return "LOW RISK", "low"


def _score_brief(score: int) -> str:
    if score <= 25:
        return "Critical security posture detected"
    if score <= 50:
        return "Elevated risk — urgent remediation advised"
    if score <= 75:
        return "Moderate risk — schedule hardening activities"
    return "Strong security posture maintained"


def risk_description_v2(risk_level: str, absolute_risk: int) -> str:
    level = risk_level.lower()
    if level == "critical":
        return (
            f"Critical multi-factor risk (absolute risk {absolute_risk}). "
            "Remediate tool-attributed findings on attack paths immediately."
        )
    if level == "high":
        return (
            f"High multi-factor risk (absolute risk {absolute_risk}). "
            "Prioritize high-severity tool findings and chain-exposed tools."
        )
    if level == "medium":
        return (
            f"Moderate multi-factor risk (absolute risk {absolute_risk}). "
            "Schedule hardening for elevated factor dimensions."
        )
    return (
        f"Low multi-factor risk (absolute risk {absolute_risk}). "
        "Maintain controls; re-scan after material changes."
    )


def risk_description(score: int) -> str:
    if score <= 25:
        return "Your MCP server has critical security issues that require immediate attention."
    if score <= 50:
        return "Your MCP server has high-severity issues that should be remediated urgently."
    if score <= 75:
        return "Your MCP server has moderate security gaps worth addressing soon."
    return "Your MCP server shows a strong security posture with minor or no issues."


def security_grade(score: int) -> dict[str, str]:
    """Letter grade and posture label for executive reporting."""
    if score >= 90:
        return {"letter": "A", "label": "Excellent", "posture": "Low Risk"}
    if score >= 80:
        return {"letter": "B", "label": "Good", "posture": "Low Risk"}
    if score >= 70:
        return {"letter": "C", "label": "Fair", "posture": "Medium Risk"}
    if score >= 60:
        return {"letter": "D", "label": "Poor", "posture": "High Risk"}
    return {"letter": "F", "label": "Critical", "posture": "Critical"}


def _include_in_executive_heuristics(finding: Finding) -> bool:
    """Exclude overlap-only attack chain meta-findings from alarm heuristics."""
    return not (finding.analyzer == "attack_chains" and finding.evidence_type == "capability_overlap")


def build_executive_summary(findings: list[Finding], summary: ScanSummary) -> dict[str, Any]:
    """Executive narrative and prioritized actions derived from findings."""
    paragraphs: list[str] = []
    bullets: list[str] = []

    chain_findings = [f for f in findings if f.analyzer == "attack_chains"]
    has_proven = False
    has_overlap = False
    if chain_findings:
        has_proven = any(f.evidence_type == "graph_path" for f in chain_findings)
        has_overlap = any(f.evidence_type == "capability_overlap" for f in chain_findings)
        if has_overlap and not has_proven:
            paragraphs.append(
                "Potential tool capability overlaps were detected (no proven multi-step paths)."
            )
        else:
            paragraphs.append("Critical attack chains were detected.")
    elif summary.critical:
        paragraphs.append("Critical-severity findings require immediate remediation.")

    heuristic_findings = [f for f in findings if _include_in_executive_heuristics(f)]

    shell_findings = [
        f
        for f in heuristic_findings
        if (f.tool and "shell" in f.tool.lower())
        or "shell" in f.title.lower()
        or "run_shell" in (f.tool or "")
    ]
    if shell_findings:
        paragraphs.append("Multiple tools enable arbitrary command execution on the host.")

    exfil_findings = [
        f
        for f in heuristic_findings
        if "exfil" in f.title.lower() or "webhook" in f.title.lower() or "send_webhook" in (f.tool or "")
    ]
    chain_exfil = any(
        "exfil_tools" in (f.evidence or {}) for f in chain_findings if f.evidence_type != "capability_overlap"
    )
    if exfil_findings or chain_exfil:
        paragraphs.append("Sensitive data exfiltration paths were identified.")

    file_findings = [
        f
        for f in findings
        if f.analyzer in ("tool_abuse", "permission_analyzer")
        and ("file" in f.title.lower() or "path" in f.title.lower() or "read" in f.title.lower())
    ]
    if file_findings:
        paragraphs.append("File and environment access controls are insufficiently restricted.")

    if not paragraphs:
        if summary.total == 0:
            paragraphs.append("No significant security issues were detected in this scan.")
        else:
            paragraphs.append(f"The scan identified {summary.total} finding(s) across severity levels.")

    recs = build_recommendations(findings)
    action_map = [
        ("shell", "Remove unrestricted shell access"),
        ("exfil", "Restrict outbound requests and webhook egress"),
        ("webhook", "Restrict outbound requests and webhook egress"),
        ("path", "Harden file access controls and path validation"),
        ("traversal", "Harden file access controls and path validation"),
        ("destructive", "Require confirmation for destructive operations"),
        ("credential", "Block credential tools from autonomous agent access"),
        ("injection", "Sanitize tool inputs and enforce instruction boundaries"),
    ]
    seen_bullets: set[str] = set()
    suppress_chain_recs = bool(chain_findings) and has_overlap and not has_proven
    for rec in recs:
        if suppress_chain_recs and rec.get("analyzer") == "attack_chains":
            continue
        text = rec["recommendation"]
        if text not in seen_bullets and len(bullets) < 5:
            seen_bullets.add(text)
            bullets.append(text)
    for _keyword, action in action_map:
        if len(bullets) >= 3:
            break
        if action in seen_bullets:
            continue
        if any(
            _keyword in f.title.lower() or _keyword in f.recommendation.lower() for f in heuristic_findings
        ):
            bullets.append(action)
            seen_bullets.add(action)

    if not bullets and recs:
        bullets = [r["recommendation"] for r in recs[:3]]

    return {"paragraphs": paragraphs, "recommended": bullets[:3]}


def _append_passed_checks_summary(
    paragraphs: list[str],
    *,
    analyzers_executed: list[str],
    analyzer_results: list[dict[str, Any]],
) -> None:
    if not analyzers_executed or not analyzer_results:
        return
    passed = sum(1 for row in analyzer_results if row.get("status") == "passed")
    total = len(analyzer_results)
    if passed <= 0:
        return
    lead = f"{passed} of {total} security analyzers completed with no findings."
    if paragraphs and lead in paragraphs[0]:
        return
    paragraphs.insert(0, lead)


def _finding_risk_points(finding: Finding, *, use_display: bool = False) -> int:
    severity = effective_severity(finding) if use_display else finding.severity
    return RISK_WEIGHTS[severity]


def category_scores(findings: list[Finding], *, use_display: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, label, maximum, analyzers in CATEGORY_DEFS:
        matched = [f for f in findings if f.analyzer in analyzers]
        points = sum(_finding_risk_points(f, use_display=use_display) for f in matched)
        score = min(maximum, points)
        passed = len(matched) == 0
        rows.append(
            {
                "key": key,
                "label": label,
                "maximum": maximum,
                "score": score,
                "display": "Passed" if passed else f"{score}/{maximum}",
                "findings_count": len(matched),
                "passed": passed,
                "benchmark": INDUSTRY_BENCHMARK.get(key, 0),
            }
        )
    return rows


def category_gate_keys() -> frozenset[str]:
    return frozenset(key for key, _, _, _ in CATEGORY_DEFS)


def parse_category_gates(raw_values: list[str] | None) -> dict[str, int]:
    """Parse `--fail-on-category permissions:10` style thresholds."""
    gates: dict[str, int] = {}
    if not raw_values:
        return gates
    valid = category_gate_keys()
    for raw in raw_values:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                raise ValueError(f"Invalid --fail-on-category value {part!r}. Use category:max_score.")
            category, limit_text = part.split(":", 1)
            category = category.strip()
            if category not in valid:
                valid_list = ", ".join(sorted(valid))
                raise ValueError(f"Unknown category {category!r}. Valid categories: {valid_list}")
            limit = int(limit_text.strip())
            if limit < 0:
                raise ValueError(f"Category limit must be >= 0, got {limit}")
            gates[category] = limit
    return gates


CATEGORY_TAGS_V2: dict[str, frozenset[str]] = {
    "injection": frozenset(
        {
            "prompt_injection",
            "jailbreak",
            "schema_surface",
            "metadata_integrity",
            "skill_md",
            "sigma_metadata",
            "surface_metadata",
        }
    ),
    "exfiltration": frozenset({"data_leakage", "embedding_secrets"}),
    "privilege": frozenset(
        {
            "permission_analyzer",
            "command_execution",
            "path_validation",
            "tool_abuse",
        }
    ),
    "supply_chain": frozenset(
        {
            "supply_chain",
            "vulnerable_package",
            "npm_audit",
            "virustotal",
            "semgrep_sast",
        }
    ),
    "protocol": frozenset({"oauth_config", "runtime_events", "cloud_inspect"}),
}
CATEGORY_PRIORITY_V2 = ("injection", "exfiltration", "privilege", "supply_chain", "protocol")
CATEGORY_LABELS_V2: dict[str, str] = {
    "injection": "Injection & Metadata",
    "exfiltration": "Data Exfiltration",
    "privilege": "Privilege & Execution",
    "supply_chain": "Supply Chain",
    "protocol": "Protocol & Runtime",
}
_CATEGORY_V2_PENALTY = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
}


def assign_category_v2(analyzer: str) -> str | None:
    """First-match category assignment for v2 OWASP tiles."""
    for cat in CATEGORY_PRIORITY_V2:
        if analyzer in CATEGORY_TAGS_V2[cat]:
            return cat
    return None


def category_scores_v2_gate_keys() -> frozenset[str]:
    return frozenset(CATEGORY_PRIORITY_V2)


def parse_min_category_score_v2(raw_values: list[str] | None) -> dict[str, int]:
    """Parse `--min-category-score-v2 injection:80` style minimum health scores."""
    gates: dict[str, int] = {}
    if not raw_values:
        return gates
    valid = category_scores_v2_gate_keys()
    for raw in raw_values:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if ":" not in part:
                raise ValueError(f"Invalid --min-category-score-v2 value {part!r}. Use category:min_score.")
            category, limit_text = part.split(":", 1)
            category = category.strip()
            if category not in valid:
                valid_list = ", ".join(sorted(valid))
                raise ValueError(f"Unknown v2 category {category!r}. Valid categories: {valid_list}")
            minimum = int(limit_text.strip())
            if not 0 <= minimum <= 100:
                raise ValueError(f"v2 category minimum must be 0–100, got {minimum}")
            gates[category] = minimum
    return gates


def category_scores_v2_gate_failures(
    findings: list[Finding],
    gates: dict[str, int],
    *,
    use_display: bool = False,
) -> list[str]:
    """Fail when OWASP v2 tile score falls below minimum (100 = good polarity)."""
    if not gates:
        return []
    by_key = {row["key"]: row for row in category_scores_v2(findings, use_display=use_display)}
    failures: list[str] = []
    for category, minimum in gates.items():
        row = by_key.get(category)
        if not row:
            continue
        if row["score"] < minimum:
            failures.append(
                f"{row['label']}: v2 category score {row['score']} below minimum {minimum} "
                f"(100=good; {row['findings_count']} findings)"
            )
    return failures


def category_scores_v2(findings: list[Finding], *, use_display: bool = False) -> list[dict[str, Any]]:
    """OWASP category health scores — 100 = good (RFC §4.15 polarity)."""
    from mcts.scoring.context import scorable_findings_v2

    scorable = scorable_findings_v2(findings)
    rows: list[dict[str, Any]] = []
    for key in CATEGORY_PRIORITY_V2:
        matched = [f for f in scorable if assign_category_v2(f.analyzer) == key]
        penalty = sum(
            _CATEGORY_V2_PENALTY.get(
                effective_severity(f) if use_display else f.severity,
                5,
            )
            for f in matched
        )
        score = max(0, 100 - min(100, penalty))
        passed = len(matched) == 0
        benchmark = INDUSTRY_BENCHMARK_V2.get(key, 80)
        rows.append(
            {
                "key": key,
                "label": CATEGORY_LABELS_V2[key],
                "score": score,
                "display": "100/100" if passed else f"{score}/100",
                "findings_count": len(matched),
                "passed": passed,
                "benchmark": benchmark,
            }
        )
    return rows


def category_gate_failures(
    findings: list[Finding],
    gates: dict[str, int],
    *,
    use_display: bool = False,
) -> list[str]:
    """Return human-readable failures when a category score meets/exceeds its gate."""
    if not gates:
        return []
    by_key = {row["key"]: row for row in category_scores(findings, use_display=use_display)}
    failures: list[str] = []
    for category, limit in gates.items():
        row = by_key.get(category)
        if not row:
            continue
        if row["score"] >= limit:
            failures.append(
                f"{row['label']}: risk score {row['score']} >= limit {limit} "
                f"(inclusive gate — '{row['display']}' is category label, not CI result)"
            )
    return failures


def owasp_mappings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Backward-compatible list of LLM categories with findings only."""
    return [row for row in llm_owasp_mappings(findings)["categories"] if row["status"] == "findings"]


def llm_owasp_mappings(findings: list[Finding], *, use_display: bool = False) -> dict[str, Any]:
    """OWASP LLM Top 10 coverage — mirrors compliance meta-findings."""
    scorable = [f for f in findings if f.analyzer != "compliance"]
    covered = {OWASP_LLM_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in OWASP_LLM_ANALYZER_MAP}
    expected = set(OWASP_LLM_ANALYZER_MAP.values())
    missing = sorted(expected - covered)

    for finding in findings:
        if finding.analyzer != "compliance":
            continue
        evidence = finding.evidence
        if evidence.get("owasp_llm_gaps"):
            missing = sorted(evidence["owasp_llm_gaps"])
            break

    rows: list[dict[str, Any]] = []
    for owasp_id, label, analyzers in OWASP_CATALOG:
        full_label = next(
            (value for value in OWASP_LLM_ANALYZER_MAP.values() if value.startswith(owasp_id)),
            f"{owasp_id} {label}",
        )
        matched = [f for f in scorable if f.analyzer in analyzers]
        if matched:
            max_sev = min(
                SEVERITY_ORDER[effective_severity(f) if use_display else f.severity] for f in matched
            )
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            affected: set[str] = set()
            for finding in matched:
                if finding.tool:
                    affected.add(finding.tool)
            rows.append(
                {
                    "id": owasp_id,
                    "label": label,
                    "full_label": full_label,
                    "status": "findings",
                    "finding_count": len(matched),
                    "risk_level": severity.value,
                    "affected_tools": sorted(affected),
                }
            )
        elif scorable and full_label in missing:
            rows.append(
                {
                    "id": owasp_id,
                    "label": label,
                    "full_label": full_label,
                    "status": "gap",
                    "finding_count": 0,
                    "risk_level": "low",
                    "affected_tools": [],
                }
            )

    rows.sort(key=lambda r: (0 if r["status"] == "findings" else 1, -r["finding_count"], r["id"]))
    return {
        "categories": rows,
        "gaps": missing,
        "gap_count": len(missing),
        "has_scorable_findings": bool(scorable),
    }


def mcp_owasp_mappings(
    findings: list[Finding],
    *,
    tools_discovered: int | None = None,
    use_display: bool = False,
) -> dict[str, Any]:
    """OWASP MCP Top 10 coverage — mirrors compliance meta-findings."""
    scorable = [f for f in findings if f.analyzer != "compliance"]
    covered = {MCP_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in MCP_ANALYZER_MAP}
    missing = sorted(set(OWASP_MCP_TOP10) - covered)
    assessable_gaps = tools_discovered is None or tools_discovered > 0

    for finding in findings:
        if finding.analyzer != "compliance":
            continue
        evidence = finding.evidence
        if evidence.get("missing_mcp_categories"):
            missing = sorted(evidence["missing_mcp_categories"])
            break
        if evidence.get("owasp_mcp_gaps"):
            missing = sorted(evidence["owasp_mcp_gaps"])
            break

    rows: list[dict[str, Any]] = []
    for mcp_id, short_label, full_label, analyzers in _mcp_catalog():
        matched = [f for f in scorable if f.analyzer in analyzers]
        if matched:
            max_sev = min(
                SEVERITY_ORDER[effective_severity(f) if use_display else f.severity] for f in matched
            )
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            affected: set[str] = set()
            for finding in matched:
                if finding.tool:
                    affected.add(finding.tool)
            rows.append(
                {
                    "id": mcp_id,
                    "label": short_label,
                    "full_label": full_label,
                    "status": "findings",
                    "finding_count": len(matched),
                    "risk_level": severity.value,
                    "affected_tools": sorted(affected),
                }
            )
        elif scorable and full_label in missing and assessable_gaps:
            rows.append(
                {
                    "id": mcp_id,
                    "label": short_label,
                    "full_label": full_label,
                    "status": "gap",
                    "finding_count": 0,
                    "risk_level": "low",
                    "affected_tools": [],
                }
            )

    rows.sort(key=lambda r: (0 if r["status"] == "findings" else 1, -r["finding_count"], r["id"]))
    display_gaps = missing if assessable_gaps else []
    return {
        "categories": rows,
        "gaps": display_gaps,
        "gap_count": len(display_gaps),
        "has_scorable_findings": bool(scorable),
    }


def build_capability_matrix(report: ScanReport) -> dict[str, Any]:
    """Tool × capability grid from inferred CapabilityProfile."""
    tools: list[dict[str, Any]] = []
    for tool in report.server.tools:
        cap = tool.capability or CapabilityProfile()
        tools.append(
            {
                "name": tool.name,
                "description": tool.description,
                "flags": {key: bool(getattr(cap, key)) for key, _ in CAPABILITY_DIMS},
            }
        )
    return {
        "dimensions": [{"key": key, "label": label} for key, label in CAPABILITY_DIMS],
        "tools": tools,
        "tool_count": len(tools),
    }


def build_technique_map(findings: list[Finding], *, use_display: bool = False) -> dict[str, Any]:
    """Full MCTS-T catalog annotated with finding counts from this scan."""
    by_technique: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.analyzer == "compliance" or not finding.technique_id:
            continue
        by_technique.setdefault(finding.technique_id, []).append(finding)

    rows: list[dict[str, Any]] = []
    for entry in technique_catalog():
        tech_id = entry["id"]
        matched = by_technique.get(tech_id, [])
        row: dict[str, Any] = {
            **entry,
            "technique_url": technique_url(tech_id),
            "finding_count": len(matched),
            "status": "detected" if matched else "clear",
        }
        if matched:
            max_sev = min(
                SEVERITY_ORDER[effective_severity(f) if use_display else f.severity] for f in matched
            )
            severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
            row["risk_level"] = severity.value
        else:
            row["risk_level"] = None
        rows.append(row)

    catalog_ids = {entry["id"] for entry in technique_catalog()}
    for tech_id, matched in sorted(by_technique.items()):
        if tech_id in catalog_ids:
            continue
        max_sev = min(SEVERITY_ORDER[effective_severity(f) if use_display else f.severity] for f in matched)
        severity = next(s for s in Severity if SEVERITY_ORDER[s] == max_sev)
        rows.append(
            {
                "id": tech_id,
                "name": tech_id,
                "tactic": None,
                "owasp": None,
                "cwe": matched[0].cwe_id,
                "analyzers": sorted({f.analyzer for f in matched}),
                "technique_url": technique_url(tech_id),
                "finding_count": len(matched),
                "status": "detected",
                "risk_level": severity.value,
            }
        )

    rows.sort(key=lambda r: (0 if r["finding_count"] else 1, -r["finding_count"], r["id"]))
    detected_count = sum(1 for row in rows if row["finding_count"] > 0)
    return {
        "techniques": rows,
        "total": len(rows),
        "detected_count": detected_count,
        "clear_count": len(rows) - detected_count,
    }


def analyzer_summaries(findings: list[Finding]) -> list[dict[str, Any]]:
    """Backward-compatible wrapper — only analyzers with findings."""
    executed = sorted({f.analyzer for f in findings})
    return build_analyzer_results(findings, executed)


def _enrich_analyzer_row(
    name: str,
    items: list[Finding],
    *,
    status: str,
    report: ScanReport | None = None,
) -> dict[str, Any]:
    counts = {s.value: 0 for s in Severity}
    for item in items:
        counts[effective_severity(item).value] += 1
    info = analyzer_info(name)
    llm_full = OWASP_LLM_ANALYZER_MAP.get(name)
    mcp_full = MCP_ANALYZER_MAP.get(name)
    scope_bits: list[str] = []
    if report is not None:
        scope_bits.append(
            SCAN_SCOPE_LABELS.get(report.scan_scope, report.scan_scope.replace("_", " ").title())
        )
        tool_count = len(report.server.tools)
        scope_bits.append(f"{tool_count} tool{'s' if tool_count != 1 else ''}")
    scope_text = ", ".join(scope_bits) if scope_bits else "current scan scope"
    passed_note = (
        f"No issues matched this check's patterns ({scope_text}). "
        "A pass lowers risk in this area but does not prove the server is fully secure — "
        "try --live, broader surfaces, or optional analyzers for deeper coverage."
    )
    return {
        "name": name,
        "label": ANALYZER_LABELS.get(name, name.replace("_", " ").title()),
        "status": status,
        "finding_count": len(items),
        "severity_counts": counts,
        "summary": info["summary"],
        "looks_for": info["looks_for"],
        "techniques": info["techniques"],
        "technique_urls": [
            {"id": tid, "url": technique_url(tid)} for tid in info["techniques"] if technique_url(tid)
        ],
        "owasp_llm": llm_full.split()[0] if llm_full else None,
        "owasp_mcp": mcp_full.split()[0] if mcp_full else None,
        "passed_note": passed_note if status == "passed" else None,
        "finding_titles": [f.title for f in sort_findings(items)[:5]],
    }


def build_analyzer_results(
    findings: list[Finding],
    executed: list[str],
    *,
    report: ScanReport | None = None,
) -> list[dict[str, Any]]:
    """Full analyzer roster with passed vs issues status for HTML dashboard."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.analyzer, []).append(finding)

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in executed:
        if name in seen:
            continue
        seen.add(name)
        items = grouped.get(name, [])
        rows.append(
            _enrich_analyzer_row(
                name,
                items,
                status="passed" if not items else "issues",
                report=report,
            )
        )

    for name, items in sorted(grouped.items()):
        if name in seen:
            continue
        rows.append(_enrich_analyzer_row(name, items, status="issues", report=report))

    rows.sort(key=lambda row: (0 if row["status"] == "issues" else 1, row["label"]))
    return rows


def build_checks_summary(
    analyzer_results: list[dict[str, Any]],
    categories: list[dict[str, Any]],
) -> dict[str, int]:
    analyzers_passed = sum(1 for row in analyzer_results if row.get("status") == "passed")
    categories_passed = sum(1 for row in categories if row.get("passed"))
    return {
        "analyzers_run": len(analyzer_results),
        "analyzers_passed": analyzers_passed,
        "analyzers_with_findings": len(analyzer_results) - analyzers_passed,
        "categories_total": len(categories),
        "categories_passed": categories_passed,
        "categories_with_findings": len(categories) - categories_passed,
    }


def build_recommendations(findings: list[Finding]) -> list[dict[str, Any]]:
    priority_map = {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }
    effort_map = {
        Severity.CRITICAL: "High",
        Severity.HIGH: "Medium",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
    }
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for finding in sort_findings(findings):
        key = finding.recommendation.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        display = effective_severity(finding)
        rows.append(
            {
                "priority": priority_map[display],
                "title": finding.title,
                "recommendation": finding.recommendation,
                "impact": display.value.title(),
                "effort": effort_map[display],
                "analyzer": finding.analyzer,
                "tool": finding.tool,
                "mitigation_links": mitigation_links(finding.mitigation_ids),
                "technique_url": technique_url(finding.technique_id) if finding.technique_id else None,
            }
        )
    return rows


def build_attack_graph(report: ScanReport) -> dict[str, Any]:
    from mcts.scoring.graph import canonical_attack_graph

    return canonical_attack_graph(report)


def _trend_series_key(points: list[dict[str, Any]]) -> str:
    """Pick Y-axis metric — never mix legacy score with v2 absolute_risk."""
    if not points:
        return "score"
    versions = {str(row.get("scoring_version", "legacy")) for row in points}
    if versions == {"legacy"}:
        return "score"
    if versions.isdisjoint({"legacy"}) and all("absolute_risk" in row for row in points):
        return "absolute_risk"
    if versions.isdisjoint({"legacy"}) and all(row.get("security_score") is not None for row in points):
        return "security_score"
    return "score"


def _trend_value(row: dict[str, Any], series_key: str) -> int:
    if series_key == "absolute_risk":
        return int(row.get("absolute_risk", 0))
    if series_key == "security_score":
        return int(row.get("security_score", 0))
    return int(row.get("score", 0))


def score_trend(report: ScanReport) -> list[dict[str, Any]]:
    if report.scan_history:
        points = list(report.scan_history)
    else:
        from mcts.output.history import trend_points_for_target

        points = trend_points_for_target(report.target)
    if points:
        series_key = _trend_series_key(points)
        for row in points:
            row["trend_value"] = _trend_value(row, series_key)
        return points
    label = report.scanned_at.strftime("%b %d")
    trend_summary = (
        (report.display_summary or report.summary) if report_trust_enforced(report) else report.summary
    )
    row: dict[str, Any] = {
        "date": label,
        "score": report.score.overall,
        "scoring_version": report.scoring_version,
        "trend_value": report.score.overall,
        "findings_total": trend_summary.total,
        "critical": trend_summary.critical,
        "high": trend_summary.high,
        "findings_trust_mode": report.findings_trust_mode,
    }
    if report.display_summary is not None:
        row["display_critical"] = report.display_summary.critical
        row["display_high"] = report.display_summary.high
    if report.score_v2 is not None:
        row["absolute_risk"] = report.score_v2.absolute_risk
        if report.score_v2.security_score is not None:
            row["security_score"] = report.score_v2.security_score
        row["risk_level"] = report.score_v2.risk_level
        series_key = _trend_series_key([row])
        row["trend_value"] = _trend_value(row, series_key)
    return [row]


def trend_meta(report: ScanReport, points: list[dict[str, Any]]) -> dict[str, Any]:
    series_key = _trend_series_key(points)
    values = [_trend_value(row, series_key) for row in points]
    unique_values = sorted(set(values))
    latest = (
        values[-1]
        if values
        else (
            report.score_v2.absolute_risk
            if series_key == "absolute_risk" and report.score_v2 is not None
            else report.score.overall
        )
    )
    labels = {
        "score": "Security score (legacy, 0–100 pts, higher=better)",
        "absolute_risk": "Absolute risk (v2, higher=worse)",
        "security_score": "Security score (v2 benchmark, 0–100, higher=better)",
    }
    return {
        "runs": len(points),
        "unique_scores": len(unique_values),
        "latest_score": latest,
        "score_unchanged": len(unique_values) <= 1 and len(points) > 1,
        "series_key": series_key,
        "series_label": labels.get(series_key, labels["score"]),
        "mixed_metrics": len({str(row.get("scoring_version", "legacy")) for row in points}) > 1
        if points
        else False,
    }


def _score_v2_payload(report: ScanReport) -> dict[str, Any] | None:
    if report.score_v2 is None:
        return None
    score = report.score_v2
    grade_score = score.security_score if score.security_score is not None else report.score.overall
    return {
        "absolute_risk": score.absolute_risk,
        "risk_range": list(score.risk_range),
        "risk_range_confidence": score.risk_range_confidence,
        "risk_level": score.risk_level,
        "security_score": score.security_score,
        "risk_percentile": score.risk_percentile,
        "confidence_score": score.confidence_score,
        "legacy_overall": score.legacy_overall,
        "dimension_scores": score.dimension_scores,
        "top_contributors": [c.model_dump() for c in score.top_contributors[:10]],
        "weights_profile": score.weights_profile,
        "chain_factor_mode": score.chain_factor_mode,
        "benchmark_corpus_version": score.benchmark_corpus_version,
        "basis": score.basis.model_dump(),
        "grade": security_grade(grade_score),
    }


def _build_score_help(report: ScanReport) -> dict[str, Any]:
    items = [
        "Security points from 0–100 (not a percentage of tests passed)",
        "Critical, High, Medium, and Low findings (severity-weighted)",
        "Attack chain detections",
        "Exponential decay: more severe findings lower the score",
    ]
    if report.score_v2 is not None:
        items.extend(
            [
                "Absolute risk: multi-factor sum on tool-attributed findings (higher = worse)",
                "Security score: benchmark percentile when corpus stats are available",
                "Chain multiplier applies to tool findings on validated attack paths only",
            ]
        )
    title = "Score derived from:"
    if report.score_v2 is not None:
        title = "Scores derived from:"
    return {"title": title, "items": items}


def _primary_risk_header(report: ScanReport) -> tuple[str, str, str]:
    if report.score_v2 is not None:
        level = report.score_v2.risk_level.upper()
        badge = f"{level} RISK"
        brief = (
            f"Absolute risk {report.score_v2.absolute_risk} "
            f"(range {report.score_v2.risk_range[0]}–{report.score_v2.risk_range[1]})"
        )
        return badge, level.lower(), brief
    return (
        risk_rating(report.score.overall)[0],
        risk_rating(report.score.overall)[1],
        _score_brief(report.score.overall),
    )


def build_dashboard_payload(report: ScanReport) -> dict[str, Any]:
    scanned_at: datetime = report.scanned_at
    badge, level, score_brief = _primary_risk_header(report)
    executed = list(report.analyzers_executed) or sorted({f.analyzer for f in report.findings})
    analyzer_results = build_analyzer_results(report.findings, executed, report=report)
    use_display = report_trust_enforced(report)
    categories = category_scores(report.findings, use_display=use_display)
    fact_cov = fact_coverage(report.findings) if report.findings_trust_mode != "off" else None
    checks_summary = build_checks_summary(analyzer_results, categories)
    analyzers_run = checks_summary["analyzers_run"] or max(len({f.analyzer for f in report.findings}), 6)
    exec_summary = report.display_summary or report.summary
    executive = build_executive_summary(report.findings, exec_summary)
    _append_passed_checks_summary(
        executive["paragraphs"],
        analyzers_executed=executed,
        analyzer_results=analyzer_results,
    )

    findings_rows = []
    for finding in sort_findings(report.findings):
        owasp_ids = owasp_ids_for_analyzer(finding.analyzer)
        tid = finding.technique_id
        evidence = finding.evidence or {}
        findings_rows.append(
            {
                "id": finding.id,
                "severity": effective_severity(finding).value,
                "template_severity": finding.severity.value,
                "display_severity": effective_severity(finding).value,
                "impact": effective_impact(finding).value,
                "evidence_strength": finding.evidence_strength,
                "evidence_type": finding.evidence_type,
                "finding_type": finding.finding_type,
                "rule_stability": finding.rule_stability,
                "priority_score": finding.priority_score,
                "title": finding.title,
                "description": finding.description,
                "category": ANALYZER_LABELS.get(finding.analyzer, finding.analyzer),
                "analyzer": finding.analyzer,
                "owasp": ", ".join(owasp_ids) if owasp_ids else "—",
                "tool": finding.tool or "—",
                "location": format_location(finding.location),
                "cwe_id": finding.cwe_id or "—",
                "confidence": finding.confidence,
                "confidence_display": format_confidence(finding.confidence),
                "evidence": evidence,
                "facts": evidence.get("facts") if isinstance(evidence.get("facts"), list) else [],
                "confidence_factors": (
                    evidence.get("confidence_factors")
                    if isinstance(evidence.get("confidence_factors"), list)
                    else []
                ),
                "interpretation": evidence.get("interpretation")
                if isinstance(evidence.get("interpretation"), dict)
                else None,
                "evidence_summary": format_evidence_summary(evidence),
                "counterfactual_remediation": (
                    evidence.get("counterfactual_remediation")
                    if isinstance(evidence.get("counterfactual_remediation"), dict)
                    else None
                ),
                "false_positive_conditions": (
                    evidence.get("false_positive_conditions")
                    if isinstance(evidence.get("false_positive_conditions"), list)
                    else []
                ),
                "evidence_tier": evidence.get("evidence_tier"),
                "has_evidence": bool(evidence),
                "has_provenance": bool(evidence.get("facts")),
                "recommendation": finding.recommendation,
                "technique_id": tid or "—",
                "technique_url": technique_url(tid) if tid else None,
                "mitigation_links": mitigation_links(finding.mitigation_ids),
            }
        )

    live = report.scan_scope == "live"
    snapshot = report.scan_scope == "snapshot"
    tool_ctx = tool_discovery_context(report, live=live, snapshot=snapshot)
    breakdown_payload = None
    if report.score_breakdown is not None:
        breakdown_payload = report.score_breakdown.model_dump()

    trend_points = score_trend(report)
    scope_label = SCAN_SCOPE_LABELS.get(
        report.scan_scope,
        report.scan_scope.replace("_", " ").title(),
    )
    grade_score = report.score.overall
    if report.score_v2 is not None and report.score_v2.security_score is not None:
        grade_score = report.score_v2.security_score

    return {
        "meta": {
            "version": report.version,
            "target": report.target,
            "scanned_at": scanned_at.isoformat(),
            "scan_date": scanned_at.strftime("%Y-%m-%d"),
            "scan_time": scanned_at.strftime("%H:%M:%S UTC"),
            "tools_discovered": len(report.server.tools),
            "analyzers_run": analyzers_run,
            "server_name": report.server.name,
            "scan_scope": report.scan_scope,
            "scan_scope_label": scope_label,
            "tool_discovery_notice": report.tool_discovery_notice,
            "findings_trust_mode": report.findings_trust_mode,
            **({"fact_coverage": fact_cov} if fact_cov is not None else {}),
        },
        "scan_notes": list(report.scan_notes),
        "tool_discovery": tool_ctx,
        "score": {
            "overall": report.score.overall,
            "risk_index": report.score.risk_index,
            "raw_risk": report.score.raw_risk,
            "basis": report.score.basis.model_dump(),
            "grade": security_grade(grade_score),
            "breakdown": breakdown_payload,
        },
        **({"score_v2": _score_v2_payload(report)} if report.score_v2 is not None else {}),
        **(
            {"category_scores_v2": category_scores_v2(report.findings, use_display=use_display)}
            if report.score_v2 is not None
            else {}
        ),
        "scoring_version": report.scoring_version,
        "summary": report.summary.model_dump(),
        "display_summary": (
            report.display_summary.model_dump() if report.display_summary is not None else None
        ),
        "risk": {
            "badge": badge,
            "level": level,
            "description": (
                risk_description_v2(report.score_v2.risk_level, report.score_v2.absolute_risk)
                if report.score_v2 is not None
                else risk_description(report.score.overall)
            ),
            "brief": score_brief,
        },
        "executive_summary": executive,
        "checks_summary": checks_summary,
        "score_help": _build_score_help(report),
        "categories": categories,
        "trend": trend_points,
        "trend_meta": trend_meta(report, trend_points),
        "findings": findings_rows,
        "tools": [{"name": t.name, "description": t.description} for t in report.server.tools],
        "analyzers": analyzer_results,
        "attack_graph": build_attack_graph(report),
        "owasp": llm_owasp_mappings(report.findings, use_display=use_display),
        "owasp_mcp": mcp_owasp_mappings(
            report.findings,
            tools_discovered=len(report.server.tools),
            use_display=use_display,
        ),
        "technique_map": build_technique_map(report.findings, use_display=use_display),
        "capability_matrix": build_capability_matrix(report),
        "recommendations": build_recommendations(report.findings),
        "techniques": technique_catalog(),
        "risk_guide": list(RISK_GUIDE),
        "raw_report": report.model_dump(mode="json"),
    }
