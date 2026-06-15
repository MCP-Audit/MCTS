"""Attack graph path building and canonical graph helpers."""

from __future__ import annotations

from collections import deque
from typing import Any

from mcts.reporting.models import Finding

PathRecord = dict[str, Any]


def _has_edge(graph: dict[str, Any], src: str, dst: str) -> bool:
    return any(edge.get("from") == src and edge.get("to") == dst for edge in graph.get("edges", []))


def _path_validated(graph: dict[str, Any], nodes: list[str]) -> bool:
    if len(nodes) < 2:
        return False
    return all(_has_edge(graph, a, b) for a, b in zip(nodes, nodes[1:], strict=False))


def bfs_path(graph: dict[str, Any], start: str, end: str) -> list[str] | None:
    """Shortest BFS path; returns None when disconnected."""
    adjacency: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        adjacency.setdefault(edge["from"], []).append(edge["to"])

    queue: deque[list[str]] = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        node = path[-1]
        if node == end:
            return path
        for neighbor in adjacency.get(node, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append([*path, neighbor])
    return None


def _bfs_paths(graph: dict[str, Any], start: str, end: str, *, max_hops: int = 4) -> list[list[str]]:
    """All simple paths up to max_hops (for read-exec semantic pick)."""
    results: list[list[str]] = []
    direct = bfs_path(graph, start, end)
    if direct:
        results.append(direct)
    return results


def _semantic_cred_path(evidence: dict[str, Any], graph: dict[str, Any]) -> list[str] | None:
    read_tools = evidence.get("read_tools", [])
    cred_tools = evidence.get("credential_tools", [])
    exfil_tools = evidence.get("exfil_tools", [])
    for r in read_tools:
        for c in cred_tools:
            if c == r:
                continue
            for e in exfil_tools:
                path = [r, c, e]
                if _path_validated(graph, path):
                    return path
    return None


def _semantic_read_exec_path(evidence: dict[str, Any], graph: dict[str, Any]) -> list[str] | None:
    read_tools = evidence.get("read_tools", [])
    exec_tools = evidence.get("exec_tools", [])
    for r in read_tools:
        for e in exec_tools:
            if e == r:
                continue
            for path in ([r, e], *(_bfs_paths(graph, r, e) or [])):
                if _path_validated(graph, path):
                    return path
    return None


def _path_record(finding: Finding, nodes: list[str]) -> PathRecord:
    hop_count = len(nodes) - 1
    return {
        "id": f"path-{finding.id}-{hop_count}",
        "nodes": nodes,
        "tools_on_path": nodes,
        "hop_count": hop_count,
        "finding_ids": [finding.id],
    }


def build_paths(graph: dict[str, Any], chain_findings: list[Finding]) -> list[PathRecord]:
    """Emit semantic + validated paths from chain meta-findings."""
    paths: list[PathRecord] = []
    for finding in chain_findings:
        if finding.id == "chain-credential-theft":
            candidate = _semantic_cred_path(finding.evidence, graph)
            if candidate:
                paths.append(_path_record(finding, candidate))
        elif finding.id == "chain-read-exfil":
            raw = finding.evidence.get("path")
            if isinstance(raw, list) and len(raw) >= 2 and _path_validated(graph, raw):
                paths.append(_path_record(finding, raw))
        elif finding.id == "chain-read-exec":
            candidate = _semantic_read_exec_path(finding.evidence, graph)
            if candidate:
                paths.append(_path_record(finding, candidate))
    return paths


def _has_chain_findings(findings: list[Finding]) -> bool:
    return any(f.analyzer == "attack_chains" for f in findings)


def _build_graph_from_chain_findings(findings: list[Finding]) -> dict[str, Any]:
    """Rebuild nodes+edges from chain meta-finding evidence when raw_graph empty."""
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []
    for finding in findings:
        if finding.analyzer != "attack_chains":
            continue
        evidence = finding.evidence
        tool_names: list[str] = []
        for key in ("read_tools", "exfil_tools", "credential_tools", "exec_tools"):
            tool_names.extend(evidence.get(key, []))
        for name in tool_names:
            nodes[name] = {"id": name, "label": name, "type": "tool"}
        read_tools = evidence.get("read_tools", [])
        exfil_tools = evidence.get("exfil_tools", [])
        cred_tools = evidence.get("credential_tools", [])
        exec_tools = evidence.get("exec_tools", [])
        for src in read_tools:
            for dst in exfil_tools:
                if src != dst:
                    edges.append({"from": src, "to": dst, "label": "exfil"})
        for src in cred_tools:
            for dst in exfil_tools:
                if src != dst:
                    edges.append({"from": src, "to": dst, "label": "credential → exfil"})
        for src in read_tools:
            for dst in cred_tools:
                if src != dst:
                    edges.append({"from": src, "to": dst, "label": "read → cred"})
        for src in read_tools:
            for dst in exec_tools:
                if src != dst:
                    edges.append({"from": src, "to": dst, "label": "read → exec"})
    return {"nodes": list(nodes.values()), "edges": edges}


def canonical_attack_graph_from_scan(
    raw_graph: dict[str, Any],
    findings: list[Finding],
    tools: list[Any],
) -> dict[str, Any]:
    """Pre-report entry — canonicalize once inside build_scoring_context()."""
    if raw_graph.get("paths"):
        return raw_graph
    if raw_graph.get("edges") or raw_graph.get("nodes"):
        base = raw_graph
    elif _has_chain_findings(findings):
        base = _build_graph_from_chain_findings(findings)
    else:
        base = {}
    chain_findings = [f for f in findings if f.analyzer == "attack_chains"]
    paths = build_paths(base, chain_findings) if base else []
    return {**base, "paths": paths}


def canonical_attack_graph(report: Any) -> dict[str, Any]:
    """Post-report entry — dashboard, tests."""
    from mcts.reporting.models import ScanReport

    if not isinstance(report, ScanReport):
        raise TypeError("report must be ScanReport")
    return canonical_attack_graph_from_scan(
        report.attack_graph or {},
        report.findings,
        report.server.tools,
    )
