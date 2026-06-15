"""OAuth configuration analysis for MCP client configs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.oauth_implicit import detect_oauth_implicit_flow
from mcts.inventory.discoverers import discover_config_paths, parse_config_file
from mcts.inventory.models import InventoryEntry
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

OAUTH_URL_KEYS = (
    "authorization_endpoint",
    "authorizationEndpoint",
    "authorization_url",
    "authorizationUrl",
    "token_endpoint",
    "tokenEndpoint",
    "issuer",
    "oauth",
    "oauth2",
    "auth_url",
    "redirect_uri",
    "redirectUri",
)

SCOPE_KEYS = ("scope", "scopes", "requested_scopes", "oauth_scopes", "permissions")

TYPOSQUAT_MARKERS = (
    "accounts-google",
    "account.google",
    "acounts.google",
    "accountsgoogle",
    "gogle.com",
    "gooogle.com",
    "login-microsoft",
    "signin-microsoft",
    "microsft.com",
    "auth-github",
    "guthub.com",
    "githup.com",
    "oauth-aws",
    "amazn.com",
    "signin-apple",
    "aple.com",
)

LEGITIMATE_OAUTH_HOSTS = (
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "github.com",
    "signin.aws.amazon.com",
    "appleid.apple.com",
)

TRUSTED_ISSUER_HOSTS = LEGITIMATE_OAUTH_HOSTS + (
    "auth0.com",
    "okta.com",
    "login.salesforce.com",
)

ROGUE_ISSUER_MARKERS = (
    "attacker",
    "malicious",
    "rogue",
    "evil",
    "phish",
    "fake-oauth",
)

BROAD_SCOPE_MARKERS = (
    "*",
    "admin",
    "read:all",
    "write:all",
    "full_access",
    "mcp:admin",
    "mcp:delete",
    "superuser",
)

DEPUTY_KEYS = (
    "forward_token",
    "proxy_token",
    "shared_token",
    "reuse_token",
    "cross_user",
    "impersonate",
)

_OAUTH_KEY_NAMES = {key.lower() for key in OAUTH_URL_KEYS}

JSON_SCAN_SKIP_DIRS = frozenset(
    {
        "data",
        "fixtures",
        "test_data",
        "processed",
        "__fixtures__",
        "tests",
    }
)


class OAuthConfigAnalyzer(BaseAnalyzer):
    """Detect OAuth misconfigurations in MCP client configs and repo JSON files."""

    name = "oauth_config"

    def __init__(self, target: Path | None = None, inventory: list[InventoryEntry] | None = None) -> None:
        self.target = target
        self.inventory = inventory or []

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        del server
        findings: list[Finding] = []
        seen: set[str] = set()
        config_docs: list[tuple[str, dict]] = []

        for entry in self._config_entries():
            payload = _load_json(entry.config_path)
            if payload is not None:
                config_docs.append((entry.config_path, payload))
            for url, key_path in _extract_oauth_urls(entry.config_path):
                findings.extend(self._analyze_url(url, key_path, entry.config_path, seen))

        if self.target is not None:
            for path in _json_files_under(self.target):
                payload = _load_json(str(path))
                if payload is not None:
                    config_docs.append((str(path), payload))
                for url, key_path in _extract_oauth_urls(str(path)):
                    findings.extend(self._analyze_url(url, key_path, str(path), seen))

        findings.extend(self._analyze_escalation(config_docs, seen))
        return findings

    def _config_entries(self) -> list[InventoryEntry]:
        if self.inventory:
            return self.inventory
        entries: list[InventoryEntry] = []
        for client, path in discover_config_paths():
            entries.extend(parse_config_file(client, path))
        return entries

    def _analyze_url(self, url: str, key_path: str, source: str, seen: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        finding_key = f"{source}:{key_path}:{url}"
        if finding_key in seen:
            return findings
        seen.add(finding_key)

        if parsed.scheme == "http" and host and _is_oauth_endpoint_key_path(key_path):
            findings.append(
                _oauth_finding(
                    finding_id=f"oauth-http-{abs(hash(finding_key))}",
                    title="OAuth endpoint uses plaintext HTTP",
                    description=f"OAuth URL over HTTP at {key_path}: {url}",
                    severity=Severity.HIGH,
                    source=source,
                    mcts_technique="MCTS-T-1011",
                    technique_scenario="MCTS-T-1011",
                    evidence={"url": url, "key_path": key_path, "issue": "plaintext_http"},
                )
            )

        if "xn--" in host or re.search(r"[\u0400-\u04FF]", host):
            findings.append(
                _oauth_finding(
                    finding_id=f"oauth-idn-{abs(hash(finding_key))}",
                    title="Suspicious OAuth host (IDN/homograph)",
                    description=f"OAuth endpoint may use homograph domain: {host}",
                    severity=Severity.HIGH,
                    source=source,
                    mcts_technique="MCTS-T-1012",
                    technique_scenario="MCTS-T-1012",
                    evidence={"url": url, "host": host, "issue": "idn_homograph"},
                )
            )

        lowered = url.lower()
        if any(marker in lowered for marker in TYPOSQUAT_MARKERS) and not any(
            legit in lowered for legit in LEGITIMATE_OAUTH_HOSTS
        ):
            findings.append(
                _oauth_finding(
                    finding_id=f"oauth-typosquat-{abs(hash(finding_key))}",
                    title="Potential OAuth Authorization Server mix-up",
                    description=f"Typosquatting pattern in OAuth URL at {key_path}",
                    severity=Severity.CRITICAL,
                    source=source,
                    mcts_technique="MCTS-T-1012",
                    technique_scenario="MCTS-T-1012",
                    evidence={"url": url, "key_path": key_path, "issue": "typosquatting"},
                )
            )

        if host.endswith((".io", ".co", ".cloud")):
            brands = ("google", "microsoft", "github", "amazon", "apple")
            brand_hit = any(brand in host for brand in brands)
            legit = any(
                host.endswith(legit_host) or legit_host in host for legit_host in LEGITIMATE_OAUTH_HOSTS
            )
            if brand_hit and not legit:
                findings.append(
                    _oauth_finding(
                        finding_id=f"oauth-tld-{abs(hash(finding_key))}",
                        title="Suspicious OAuth provider TLD substitution",
                        description=f"Brand-like OAuth host with suspicious TLD: {host}",
                        severity=Severity.MEDIUM,
                        source=source,
                        mcts_technique="MCTS-T-1012",
                        technique_scenario="MCTS-T-1012",
                        evidence={"url": url, "host": host, "issue": "tld_substitution"},
                    )
                )

        return findings

    def _analyze_escalation(
        self,
        config_docs: list[tuple[str, dict]],
        seen: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        redirect_index: dict[str, list[tuple[str, str, str]]] = {}

        for source, payload in config_docs:
            for block_path, block in _iter_oauth_blocks(payload):
                findings.extend(self._check_rogue_as(source, block_path, block, seen))
                findings.extend(self._check_broad_scopes(source, block_path, block, seen))
                findings.extend(self._check_confused_deputy_keys(source, block_path, block, seen))
                findings.extend(self._check_implicit_flow(source, block_path, block, seen))

                redirect = _string_field(block, ("redirect_uri", "redirectUri"))
                client_id = _string_field(block, ("client_id", "clientId"))
                if redirect:
                    redirect_index.setdefault(redirect, []).append((source, block_path, client_id or ""))

        for redirect, entries in redirect_index.items():
            if len(entries) < 2:
                continue
            client_ids = {client_id for _, _, client_id in entries if client_id}
            sources = {source for source, _, _ in entries}
            if len(client_ids) > 1 or len(sources) > 1:
                key = f"deputy:{redirect}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _oauth_finding(
                        finding_id=f"oauth-deputy-redirect-{abs(hash(key))}",
                        title="Shared OAuth redirect URI across distinct clients",
                        description=(
                            f"Redirect URI {redirect!r} is reused across multiple OAuth "
                            "client configurations — confused deputy risk (MCTS-T-1018)."
                        ),
                        severity=Severity.HIGH,
                        source=entries[0][0],
                        mcts_technique="MCTS-T-1018",
                        technique_scenario="MCTS-T-1018",
                        evidence={
                            "redirect_uri": redirect,
                            "sources": ",".join(sorted(sources)),
                            "issue": "shared_redirect_uri",
                        },
                    )
                )

        return findings

    def _check_rogue_as(
        self,
        source: str,
        block_path: str,
        block: dict,
        seen: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        issuer = _string_field(block, ("issuer",))
        auth_endpoint = _string_field(
            block,
            ("authorization_endpoint", "authorizationEndpoint", "authorization_url"),
        )
        token_endpoint = _string_field(block, ("token_endpoint", "tokenEndpoint"))

        oauth_urls = (
            ("issuer", issuer),
            ("authorization_endpoint", auth_endpoint),
            ("token_endpoint", token_endpoint),
        )
        for label, url in oauth_urls:
            if not url or not url.startswith("http"):
                continue
            host = (urlparse(url).hostname or "").lower()
            key = f"rogue:{source}:{block_path}:{label}:{url}"
            if key in seen:
                continue

            rogue = any(marker in host for marker in ROGUE_ISSUER_MARKERS)
            untrusted = host and not any(trusted in host for trusted in TRUSTED_ISSUER_HOSTS)
            local_issuer = any(marker in host for marker in (".example", "localhost", "127.0.0.1"))
            if rogue or (label == "issuer" and untrusted and local_issuer):
                seen.add(key)
                findings.append(
                    _oauth_finding(
                        finding_id=f"oauth-rogue-as-{abs(hash(key))}",
                        title="Rogue or untrusted Authorization Server",
                        description=f"OAuth {label} points to untrusted host: {host}",
                        severity=Severity.CRITICAL,
                        source=source,
                        mcts_technique="MCTS-T-1017",
                        technique_scenario="MCTS-T-1017",
                        evidence={
                            "url": url,
                            "field": label,
                            "host": host,
                            "issue": "rogue_authorization_server",
                        },
                    )
                )

        if issuer and auth_endpoint:
            issuer_host = (urlparse(issuer).hostname or "").lower()
            auth_host = (urlparse(auth_endpoint).hostname or "").lower()
            if issuer_host and auth_host and issuer_host != auth_host:
                key = f"mismatch:{source}:{block_path}:{issuer_host}:{auth_host}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        _oauth_finding(
                            finding_id=f"oauth-issuer-mismatch-{abs(hash(key))}",
                            title="OAuth issuer/authorization endpoint host mismatch",
                            description=(
                                f"Issuer host ({issuer_host}) differs from authorization "
                                f"endpoint host ({auth_host})."
                            ),
                            severity=Severity.HIGH,
                            source=source,
                            mcts_technique="MCTS-T-1017",
                            technique_scenario="MCTS-T-1017",
                            evidence={
                                "issuer": issuer,
                                "authorization_endpoint": auth_endpoint,
                                "issue": "issuer_endpoint_mismatch",
                            },
                        )
                    )

        return findings

    def _check_broad_scopes(
        self,
        source: str,
        block_path: str,
        block: dict,
        seen: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key in SCOPE_KEYS:
            value = block.get(key)
            if value is None:
                continue
            scope_text = " ".join(value) if isinstance(value, list) else str(value)
            if not any(marker in scope_text.lower() for marker in BROAD_SCOPE_MARKERS):
                continue
            finding_key = f"scope:{source}:{block_path}:{key}:{scope_text}"
            if finding_key in seen:
                continue
            seen.add(finding_key)
            findings.append(
                _oauth_finding(
                    finding_id=f"oauth-broad-scope-{abs(hash(finding_key))}",
                    title="Overly broad OAuth scopes configured",
                    description=f"OAuth scope at {block_path}.{key} includes elevated permissions.",
                    severity=Severity.HIGH,
                    source=source,
                    mcts_technique="MCTS-T-1019",
                    technique_scenario="MCTS-T-1019",
                    evidence={"scope": scope_text, "field": key, "issue": "broad_scope"},
                )
            )
        return findings

    def _check_confused_deputy_keys(
        self,
        source: str,
        block_path: str,
        block: dict,
        seen: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, value in block.items():
            if key.lower() not in DEPUTY_KEYS and not any(marker in key.lower() for marker in DEPUTY_KEYS):
                continue
            finding_key = f"deputy-key:{source}:{block_path}:{key}"
            if finding_key in seen:
                continue
            seen.add(finding_key)
            findings.append(
                _oauth_finding(
                    finding_id=f"oauth-deputy-key-{abs(hash(finding_key))}",
                    title="OAuth token forwarding configuration detected",
                    description=f"Config key {key!r} may forward tokens across user contexts.",
                    severity=Severity.HIGH,
                    source=source,
                    mcts_technique="MCTS-T-1018",
                    technique_scenario="MCTS-T-1018",
                    evidence={"key": key, "value": str(value)[:120], "issue": "token_forwarding"},
                )
            )
        return findings

    def _check_implicit_flow(
        self,
        source: str,
        block_path: str,
        block: dict,
        seen: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not detect_oauth_implicit_flow(block):
            return findings
        finding_key = f"implicit:{source}:{block_path}"
        if finding_key in seen:
            return findings
        seen.add(finding_key)
        findings.append(
            _oauth_finding(
                finding_id=f"oauth-implicit-{abs(hash(finding_key))}",
                title="OAuth implicit flow downgrade",
                description=(
                    "OAuth configuration uses deprecated implicit flow (response_type token/id_token) "
                    "instead of authorization code with PKCE."
                ),
                severity=Severity.HIGH,
                source=source,
                mcts_technique="MCTS-T-1047",
                technique_scenario="MCTS-T-1047",
                evidence={"block_path": block_path, "issue": "implicit_flow_downgrade"},
            )
        )
        return findings


def _oauth_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    severity: Severity,
    source: str,
    mcts_technique: str,
    technique_scenario: str,
    evidence: dict[str, str],
) -> Finding:
    return build_analyzer_finding(
        finding_id=finding_id,
        analyzer="oauth_config",
        title=title,
        description=description,
        severity=severity,
        recommendation=_recommendation_for(technique_scenario),
        rule_id=finding_id,
        match=title,
        field="oauth_config",
        location=SourceLocation(file=source, line=None),
        technique_id=mcts_technique,
        confidence=0.85,
        extra_evidence=evidence,
    )


def _recommendation_for(technique_scenario: str) -> str:
    mapping = {
        "MCTS-T-1011": "Use HTTPS-only OAuth endpoints from trusted providers.",
        "MCTS-T-1012": "Pin Authorization Server URLs; validate issuer per RFC 9207.",
        "MCTS-T-1017": "Allowlist Authorization Servers; reject unknown issuers and mismatched endpoints.",
        "MCTS-T-1018": "Never forward tokens across users; isolate redirect URIs per client.",
        "MCTS-T-1019": "Request least-privilege scopes; reject wildcard or admin scopes in client configs.",
    }
    return mapping.get(
        technique_scenario,
        "Review OAuth configuration against MCTS OAuth hardening guidance.",
    )


def _load_json(source: str) -> dict | None:
    try:
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _json_files_under(root: Path) -> list[Path]:
    if root.is_file() and root.suffix == ".json":
        return [root]
    if not root.is_dir():
        return []
    files: list[Path] = []
    for path in root.rglob("*.json"):
        if any(part.startswith(".") for part in path.parts):
            continue
        if any(part in JSON_SCAN_SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
    return files[:50]


def _is_oauth_endpoint_key_path(key_path: str) -> bool:
    if not key_path or key_path == "$text":
        return False
    leaf = key_path.rsplit(".", 1)[-1].lower()
    if leaf in _OAUTH_KEY_NAMES:
        return True
    return "oauth" in leaf


def _extract_oauth_urls(source: str) -> list[tuple[str, str]]:
    payload = _load_json(source)
    if payload is None:
        return []

    urls: list[tuple[str, str]] = []
    _walk_json(payload, "$", urls)
    return urls


def _walk_json(node: object, prefix: str, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            key_path = f"{prefix}.{key}"
            if (
                isinstance(value, str)
                and (key.lower() in _OAUTH_KEY_NAMES or "oauth" in key.lower())
                and value.startswith("http")
            ):
                out.append((value, key_path))
            elif not isinstance(value, str):
                _walk_json(value, key_path, out)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk_json(item, f"{prefix}[{index}]", out)


def _iter_oauth_blocks(node: object, prefix: str = "$") -> list[tuple[str, dict]]:
    blocks: list[tuple[str, dict]] = []
    if isinstance(node, dict):
        if any(key in node for key in OAUTH_URL_KEYS) or any(k in node for k in SCOPE_KEYS):
            blocks.append((prefix, node))
        if "mcpServers" in node and isinstance(node["mcpServers"], dict):
            for name, cfg in node["mcpServers"].items():
                if isinstance(cfg, dict):
                    blocks.extend(_iter_oauth_blocks(cfg, f"{prefix}.mcpServers.{name}"))
        for key, value in node.items():
            if key == "mcpServers":
                continue
            blocks.extend(_iter_oauth_blocks(value, f"{prefix}.{key}"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            blocks.extend(_iter_oauth_blocks(item, f"{prefix}[{index}]"))
    return blocks


def _string_field(block: dict, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = block.get(key)
        if isinstance(value, str) and value:
            return value
    return None
