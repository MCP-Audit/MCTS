"""Pre-scan gates for sensitive analyzers that require API credentials."""

from __future__ import annotations

import os

from mcts.core.config import ScanConfig

_SENSITIVE_FLAG_ENV: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("enable_llm_judge", ("MCTS_LLM_API_KEY",), "--enable-llm-judge"),
    ("enable_llm_triage", ("MCTS_LLM_API_KEY",), "--enable-llm-triage"),
    ("enable_cloud_inspect", ("MCTS_CLOUD_API_KEY",), "--enable-cloud-inspect"),
    ("enable_virustotal", ("MCTS_VT_API_KEY", "VIRUSTOTAL_API_KEY"), "--enable-virustotal"),
)


def _env_set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def evaluate_auth_env_violations(config: ScanConfig) -> list[str]:
    """Fail when policy requires credentials for enabled sensitive analyzers."""
    if not config.require_auth_env_for_sensitive:
        return []
    violations: list[str] = []
    for field, env_names, label in _SENSITIVE_FLAG_ENV:
        if not getattr(config, field, False):
            continue
        if any(_env_set(name) for name in env_names):
            continue
        env_list = ", ".join(env_names)
        violations.append(
            f"{label} enabled but required env not set ({env_list}) (require_auth_env_for_sensitive)"
        )
    return violations
