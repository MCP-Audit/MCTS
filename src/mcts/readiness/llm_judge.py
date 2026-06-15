"""Optional LLM semantic readiness checks (opt-in)."""

from __future__ import annotations

import json
import os
from typing import Any

from mcts.analyzers.finding_facts import build_hygiene_finding
from mcts.reporting.models import Severity

_PROMPT = (
    "Review this MCP tool definition for production readiness. "
    'Reply JSON only: {"issues": [{"id": "actionable_errors|failure_modes|scope_clarity", '
    '"severity": "low|medium|high", "summary": "..."}]}\n\n'
    "Evaluate: actionable error handling, documented failure modes, focused scope.\n\n"
    "Tool JSON:\n"
)


class ReadinessLlmJudge:
    """Semantic readiness review via LiteLLM (requires MCTS_LLM_API_KEY)."""

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("MCTS_LLM_MODEL", "gpt-4o-mini")

    def is_available(self) -> bool:
        if not os.environ.get("MCTS_LLM_API_KEY"):
            return False
        try:
            import litellm  # noqa: F401
        except ImportError:
            return False
        return True

    def analyze_tool(self, tool_def: dict[str, Any], tool_name: str) -> list:
        if not self.is_available():
            return []
        import litellm

        try:
            resp = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": _PROMPT + json.dumps(tool_def)[:6000]}],
                timeout=30,
                api_key=os.environ.get("MCTS_LLM_API_KEY"),
            )
            content = resp.choices[0].message.content or "{}"
            payload = json.loads(content)
        except (json.JSONDecodeError, KeyError, IndexError, Exception):
            return []

        findings: list = []
        for issue in payload.get("issues", []):
            if not isinstance(issue, dict):
                continue
            issue_id = str(issue.get("id", "readiness_llm"))
            severity = _map_severity(str(issue.get("severity", "medium")))
            summary = str(issue.get("summary", "LLM readiness concern"))
            findings.append(
                build_hygiene_finding(
                    finding_id=f"readiness-llm-{issue_id}-{tool_name}",
                    analyzer="readiness",
                    title=f"LLM readiness: {summary} ({tool_name})",
                    description=summary,
                    severity=severity,
                    recommendation="Improve tool operational documentation per LLM readiness review.",
                    rule_id=f"LLM-{issue_id}",
                    match=summary,
                    field="llm_judge",
                    tool=tool_name,
                    confidence=0.65,
                    extra_evidence={"readiness_rule": f"LLM-{issue_id}", "source": "llm_judge"},
                )
            )
        return findings


def _map_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(raw.lower(), Severity.MEDIUM)
