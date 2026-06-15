"""Tests for post-scan finding validation."""

from mcts.reporting.finding_validator import ValidationContext, validate_findings
from mcts.reporting.models import Finding, Severity


def _chain_finding(**evidence) -> Finding:
    return Finding(
        id="chain-credential-theft",
        analyzer="attack_chains",
        title="Credential theft chain possible",
        description="overlap",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={
            "read_tools": ["ask_sales_agent_tool"],
            "credential_tools": ["ask_sales_agent_tool"],
            "exfil_tools": ["ask_sales_agent_tool"],
            **evidence,
        },
    )


def test_validator_off_is_noop() -> None:
    finding = _chain_finding()
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="off")
    out = validate_findings([finding], ctx)
    assert out[0].display_severity is None
    assert out[0].title == finding.title


def test_single_tool_overlap_capped_in_enforce() -> None:
    finding = _chain_finding()
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM
    assert out.severity == Severity.CRITICAL
    assert out.evidence_strength == "weak"
    assert out.evidence.get("single_tool_overlap") is True
    assert out.evidence.get("path_status") == "unproven"
    assert "hop_count" not in out.evidence
    assert "Potential capability overlap" in out.title


def test_warn_mode_caps_without_title_rewrite() -> None:
    finding = _chain_finding()
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="warn")
    out = validate_findings([finding], ctx)[0]
    assert out.display_severity == Severity.MEDIUM
    assert out.title == "Credential theft chain possible"


def test_proven_path_keeps_display_severity() -> None:
    finding = _chain_finding(hop_count=2, path=["a", "b", "c"])
    graph = {
        "paths": [
            {
                "id": "path-1",
                "finding_ids": ["chain-credential-theft"],
                "hop_count": 2,
                "nodes": ["a", "b", "c"],
            }
        ]
    }
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph=graph, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "graph_path"
    assert out.display_severity == Severity.CRITICAL


def test_multi_tool_overlap_capped_without_proven_path() -> None:
    finding = Finding(
        id="chain-read-exec",
        analyzer="attack_chains",
        title="Read → command execution chain possible",
        description="overlap",
        severity=Severity.CRITICAL,
        recommendation="fix",
        evidence={
            "read_tools": ["read_file"],
            "exec_tools": ["run_shell"],
        },
    )
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM
    assert out.severity == Severity.CRITICAL
    assert "Potential capability overlap" in out.title


def test_empty_finding_ids_does_not_prove_path() -> None:
    finding = _chain_finding()
    graph = {
        "paths": [
            {
                "hop_count": 3,
                "tools_on_path": ["a", "b", "c"],
                "finding_ids": [],
            }
        ]
    }
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph=graph, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM


def test_missing_finding_ids_key_does_not_prove_path() -> None:
    finding = _chain_finding()
    graph = {
        "paths": [
            {
                "hop_count": 3,
                "tools_on_path": ["a", "b", "c"],
            }
        ]
    }
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph=graph, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM


def test_evidence_hop_count_without_graph_does_not_prove_path() -> None:
    finding = _chain_finding(hop_count=3)
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM


def test_evidence_path_without_graph_association_does_not_prove_path() -> None:
    finding = _chain_finding(path=["a", "b", "c"])
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM


def test_stale_path_status_does_not_prove_without_graph() -> None:
    finding = _chain_finding(path_status="proven", path=["a", "b", "c"])
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.evidence_type == "capability_overlap"
    assert out.display_severity == Severity.MEDIUM


def test_security_finding_gets_priority_score() -> None:
    finding = Finding(
        id="exec-1",
        analyzer="command_execution",
        title="Shell invocation",
        description="d",
        severity=Severity.HIGH,
        recommendation="fix",
        tool="run_cmd",
    )
    ctx = ValidationContext(scan_scope="repository", tools=[], attack_graph={}, mode="enforce")
    out = validate_findings([finding], ctx)[0]
    assert out.priority_score is not None
    assert out.evidence_strength == "moderate"
    assert out.priority_score > 0
