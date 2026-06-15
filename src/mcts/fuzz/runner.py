"""Fuzz runner orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from mcts.core.config import ScanConfig
from mcts.discovery.live_config import resolve_live_config
from mcts.fuzz.classifier import classify_response, finding_from_classification
from mcts.fuzz.payloads import FuzzLevel, probes_for_level
from mcts.fuzz.transport import run_probe_messages
from mcts.fuzz.transport_http import run_probe_messages_http
from mcts.probe.auth import RemoteAuth
from mcts.probe.consent import require_live_consent
from mcts.probe.http_session import probe_remote, remote_config_from_scan
from mcts.probe.models import RemoteServerConfig
from mcts.probe.session import MCPProbeError, probe_stdio
from mcts.probe.startup_errors import MCPStartupError
from mcts.reporting.models import Finding


@dataclass
class FuzzResult:
    findings: list[Finding] = field(default_factory=list)
    probes_run: int = 0
    level: FuzzLevel = FuzzLevel.SAFE


class FuzzRunner:
    """Run safe read-only MCP protocol fuzz probes against a stdio or remote server."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._remote_cfg: RemoteServerConfig | None = None

    @property
    def _is_remote(self) -> bool:
        return bool(self.config.remote_url)

    def run(self) -> FuzzResult:
        return asyncio.run(self.run_async())

    async def run_async(self) -> FuzzResult:
        require_live_consent(flag=self.config.live_consent)
        level = FuzzLevel(self.config.fuzz_level)

        if level == FuzzLevel.AGGRESSIVE and not self.config.fuzz_consent:
            raise ValueError(
                "Aggressive fuzz may invoke tools/call. Pass --i-understand-fuzz-risk to proceed."
            )

        tool_names = await self._discover_tools()
        probes = probes_for_level(level, tool_names)
        findings: list[Finding] = []
        seen: set[str] = set()

        for probe in probes:
            response_text, errored = await self._send_probe(probe.messages, probe.followups)
            classified = classify_response(probe, response_text, process_exited=errored)
            if classified is None:
                continue
            finding = finding_from_classification(
                probe,
                classified,
                response_excerpt=response_text[:500],
                transport="http" if self._is_remote else None,
                remote_url=self.config.remote_url if self._is_remote else None,
            )
            if finding.id in seen:
                continue
            seen.add(finding.id)
            findings.append(finding)

        return FuzzResult(findings=findings, probes_run=len(probes), level=level)

    async def _discover_tools(self) -> tuple[str, ...]:
        """Discover tool names via the appropriate transport."""
        if self._is_remote:
            server = await probe_remote(
                self._get_remote_config(),
                timeout_seconds=min(self.config.timeout_seconds, 30),
            )
            return tuple(tool.name for tool in server.tools)

        live_config = resolve_live_config(self.config)
        try:
            server = await probe_stdio(
                live_config,
                timeout_seconds=min(self.config.timeout_seconds, 30),
            )
            return tuple(tool.name for tool in server.tools)
        except MCPStartupError:
            raise
        except MCPProbeError:
            raise

    async def _send_probe(
        self,
        messages: tuple,
        followups: tuple,
    ) -> tuple[str, bool]:
        """Send a single fuzz probe via the appropriate transport."""
        timeout = min(self.config.timeout_seconds, 15)
        if self._is_remote:
            return await run_probe_messages_http(
                self._get_remote_config(),
                messages,
                timeout_seconds=timeout,
                followups=followups,
            )
        live_config = resolve_live_config(self.config)
        return await run_probe_messages(
            live_config,
            messages,
            timeout_seconds=timeout,
            followups=followups,
        )

    def _get_remote_config(self) -> RemoteServerConfig:
        if self._remote_cfg is None:
            self._remote_cfg = self._build_remote_config()
        return self._remote_cfg

    def _build_remote_config(self) -> RemoteServerConfig:
        auth = RemoteAuth(
            bearer_token=self.config.bearer_token,
            headers=self.config.remote_headers,
            oauth_token_url=self.config.oauth_token_url,
            oauth_client_id=self.config.oauth_client_id,
            oauth_client_secret=self.config.oauth_client_secret,
            oauth_scopes=self.config.oauth_scopes,
        )
        return remote_config_from_scan(
            url=self.config.remote_url or "",
            transport=self.config.remote_transport,
            auth=auth,
            server_name=self.config.config_server or "remote-server",
        )
