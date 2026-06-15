"""Rule-class stability defaults (Phase 1.5)."""

from __future__ import annotations

from mcts.reporting.models import Finding

VALID_STABILITY = frozenset({"experimental", "heuristic", "mature", "verified"})

# Analyzer-level defaults — distinct from per-finding confidence.
RULE_STABILITY_BY_ANALYZER: dict[str, str] = {
    "attack_chains": "heuristic",
    "behavioral_static": "heuristic",
    "jailbreak": "heuristic",
    "llm_judge": "experimental",
    "llm_metadata_triage": "experimental",
    "live_discovery": "mature",
    "static_discovery": "mature",
    "compliance": "mature",
    "readiness": "mature",
    "vet": "mature",
    "prompt_injection": "mature",
    "permission_analyzer": "mature",
    "data_leakage": "mature",
    "command_execution": "mature",
    "tool_abuse": "mature",
    "sigma_metadata": "mature",
    "semgrep_sast": "mature",
}


def default_rule_stability(analyzer: str) -> str:
    return RULE_STABILITY_BY_ANALYZER.get(analyzer, "mature")


def apply_rule_stability(finding: Finding) -> Finding:
    if finding.rule_stability:
        return finding
    return finding.model_copy(update={"rule_stability": default_rule_stability(finding.analyzer)})
