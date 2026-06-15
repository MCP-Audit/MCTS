"""Active protocol security probes for remote MCP HTTP endpoints (MCPS-001–009)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx

from mcts.reporting.models import Finding, Severity

_SIGNING_HEADERS = (
    "x-mcps-signature",
    "x-attp-signature",
    "x-agent-signature",
)


def probe_protocol_security(url: str, timeout: float = 10.0) -> list[Finding]:
    """Run MCPS-style checks against a remote MCP HTTP endpoint."""
    findings: list[Finding] = []
    parsed = urlparse(url)

    findings.extend(_check_transport(url, parsed))
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        init_resp = _post_jsonrpc(
            client,
            url,
            {"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {}},
        )
        tools_resp = _post_jsonrpc(
            client, url, {"jsonrpc": "2.0", "id": "tools", "method": "tools/list", "params": {}}
        )
        findings.extend(_check_auth(tools_resp))
        findings.extend(_check_signing(tools_resp, init_resp))
        findings.extend(_check_tool_integrity(tools_resp))
        findings.extend(_check_replay(client, url))
        findings.extend(_check_spoofed_identity(client, url))
        findings.extend(_check_fail_open(client, url))
        findings.extend(_check_rate_limiting(client, url))

    return findings


def _check_transport(url: str, parsed: Any) -> list[Finding]:
    if parsed.scheme != "http":
        return []
    return [_protocol_finding("mcps-001", "MCPS-001", "Unencrypted HTTP transport", Severity.HIGH, "CWE-319")]


def _check_auth(tools_resp: httpx.Response | None) -> list[Finding]:
    if tools_resp is None or tools_resp.status_code != 200:
        return []
    body = _parse_body(tools_resp)
    if body and isinstance(body, dict) and body.get("error"):
        return []
    return [
        _protocol_finding(
            "mcps-002",
            "MCPS-002",
            "Unauthenticated MCP endpoint accepted",
            Severity.HIGH,
            "CWE-306",
            {"status_code": tools_resp.status_code},
        )
    ]


def _check_signing(tools_resp: httpx.Response | None, init_resp: httpx.Response | None) -> list[Finding]:
    for resp in (tools_resp, init_resp):
        if resp is None:
            continue
        if any(h in resp.headers for h in _SIGNING_HEADERS):
            return []
    body = _parse_body(init_resp)
    if body and isinstance(body, dict):
        result = body.get("result", {})
        if isinstance(result, dict):
            caps = result.get("capabilities", {})
            if isinstance(caps, dict) and (caps.get("mcps") or caps.get("signing")):
                return []
    return [
        _protocol_finding(
            "mcps-003",
            "MCPS-003",
            "No message signing detected",
            Severity.HIGH,
            "CWE-345",
        )
    ]


def _check_tool_integrity(tools_resp: httpx.Response | None) -> list[Finding]:
    tools = _get_tools(tools_resp)
    if not tools:
        return []
    for tool in tools:
        if isinstance(tool, dict) and (tool.get("hash") or tool.get("integrity") or tool.get("signature")):
            return []
    return [
        _protocol_finding(
            "mcps-005",
            "MCPS-005",
            f"Tool definitions ({len(tools)} tools) lack integrity hashes",
            Severity.MEDIUM,
            "CWE-494",
            {"tool_count": len(tools)},
        )
    ]


def _check_replay(client: httpx.Client, url: str) -> list[Finding]:
    payload = {"jsonrpc": "2.0", "id": "replay-check", "method": "tools/list", "params": {}}
    body = json.dumps(payload)
    try:
        r1 = client.post(url, content=body, headers={"Content-Type": "application/json"})
        r2 = client.post(url, content=body, headers={"Content-Type": "application/json"})
        if r1.status_code == 200 and r2.status_code == 200:
            return [
                _protocol_finding(
                    "mcps-004",
                    "MCPS-004",
                    "Server accepts identical replayed requests",
                    Severity.MEDIUM,
                    "CWE-294",
                )
            ]
    except httpx.HTTPError:
        pass
    return []


def _check_spoofed_identity(client: httpx.Client, url: str) -> list[Finding]:
    headers = {
        "Content-Type": "application/json",
        "X-Agent-ID": "spoofed-admin-agent",
        "X-Agent-Role": "admin",
        "X-Agent-Trust-Level": "4",
    }
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    try:
        resp = client.post(url, json=payload, headers=headers)
        if resp.status_code == 200:
            body = _parse_body(resp)
            if body and not (isinstance(body, dict) and body.get("error")):
                return [
                    _protocol_finding(
                        "mcps-007",
                        "MCPS-007",
                        "Server accepts spoofed agent identity headers",
                        Severity.HIGH,
                        "CWE-290",
                    )
                ]
    except httpx.HTTPError:
        pass
    return []


def _check_fail_open(client: httpx.Client, url: str) -> list[Finding]:
    invalid_payloads: list[Any] = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "../../../../etc/passwd", "arguments": {}},
        },
        {"not_jsonrpc": True},
        "this is not json",
    ]
    for payload in invalid_payloads:
        try:
            if isinstance(payload, str):
                resp = client.post(url, content=payload, headers={"Content-Type": "application/json"})
            else:
                resp = client.post(url, json=payload)
            if resp.status_code == 200:
                body = _parse_body(resp)
                if body and isinstance(body, dict) and body.get("result"):
                    return [
                        _protocol_finding(
                            "mcps-008",
                            "MCPS-008",
                            "Server processes invalid requests (fail-open)",
                            Severity.MEDIUM,
                            "CWE-636",
                        )
                    ]
        except httpx.HTTPError:
            continue
    return []


def _check_rate_limiting(client: httpx.Client, url: str) -> list[Finding]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    accepted = 0
    for _ in range(10):
        try:
            resp = client.post(url, json=payload)
            if resp.status_code == 429:
                return []
            if resp.status_code == 200:
                accepted += 1
        except httpx.HTTPError:
            break
    if accepted >= 10:
        return [
            _protocol_finding(
                "mcps-009",
                "MCPS-009",
                f"No rate limiting detected ({accepted} rapid requests accepted)",
                Severity.MEDIUM,
                "CWE-770",
                {"requests_accepted": accepted},
            )
        ]
    return []


def _protocol_finding(
    finding_id: str,
    check_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    evidence: dict | None = None,
) -> Finding:
    ev = {
        "check_id": check_id,
        "facts": [
            {
                "rule_id": check_id,
                "match": title,
                "field": "protocol_probe",
            }
        ],
        "evidence_tier": "bronze",
        **(evidence or {}),
    }
    return Finding(
        id=finding_id,
        analyzer="protocol_probe",
        title=f"{title} ({check_id})",
        description=title,
        severity=severity,
        recommendation="Harden MCP HTTP endpoint per OWASP MCP Security Cheat Sheet.",
        technique_id="MCTS-T-1027",
        cwe_id=cwe,
        confidence=0.75,
        evidence=ev,
    )


def _post_jsonrpc(client: httpx.Client, url: str, payload: dict) -> httpx.Response | None:
    try:
        return client.post(url, json=payload)
    except httpx.HTTPError:
        return None


def _parse_body(resp: httpx.Response | None) -> Any:
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _get_tools(resp: httpx.Response | None) -> list[dict]:
    body = _parse_body(resp)
    if body and isinstance(body, dict):
        result = body.get("result", {})
        if isinstance(result, dict):
            tools = result.get("tools", [])
            if isinstance(tools, list):
                return [t for t in tools if isinstance(t, dict)]
    return []
