"""Tests for remote MCP HTTP session construction."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import httpx
import pytest

from mcts.probe.auth import RemoteAuth
from mcts.probe.http_session import probe_remote
from mcts.probe.models import RemoteServerConfig


class _FakeTransportContext:
    async def __aenter__(self) -> tuple[object, object, None]:
        return object(), object(), None

    async def __aexit__(self, *args: object) -> None:
        return None


class _FakeClientSession:
    def __init__(self, read: object, write: object) -> None:
        pass

    async def __aenter__(self) -> _FakeClientSession:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def initialize(self) -> SimpleNamespace:
        return SimpleNamespace(server_version="1.0.0", instructions=None)

    async def list_tools(self) -> SimpleNamespace:
        return SimpleNamespace(tools=[])

    async def list_prompts(self) -> SimpleNamespace:
        return SimpleNamespace(prompts=[])

    async def list_resources(self) -> SimpleNamespace:
        return SimpleNamespace(resources=[])


def _install_fake_mcp_modules(
    monkeypatch: pytest.MonkeyPatch,
    *,
    streamable_http_client: Any,
    create_mcp_http_client: Any | None = None,
    sse_client: Any | None = None,
) -> None:
    mcp_module = ModuleType("mcp")
    mcp_module.ClientSession = _FakeClientSession  # type: ignore[attr-defined]

    client_module = ModuleType("mcp.client")
    streamable_module = ModuleType("mcp.client.streamable_http")
    streamable_module.streamable_http_client = streamable_http_client  # type: ignore[attr-defined]
    streamable_module.create_mcp_http_client = (  # type: ignore[attr-defined]
        create_mcp_http_client or (lambda **kwargs: httpx.AsyncClient(**kwargs))
    )

    sse_module = ModuleType("mcp.client.sse")
    sse_module.sse_client = sse_client or (lambda *_args, **_kwargs: _FakeTransportContext())  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.client", client_module)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", streamable_module)
    monkeypatch.setitem(sys.modules, "mcp.client.sse", sse_module)


def _clear_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("all_proxy", "http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.asyncio
async def test_streamable_http_probe_passes_auth_headers_via_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_proxy_env(monkeypatch)
    calls: list[dict[str, Any]] = []
    factory_calls: list[dict[str, Any]] = []

    def fake_streamable_http_client(url: str, **kwargs: Any) -> _FakeTransportContext:
        calls.append({"url": url, "kwargs": kwargs})
        return _FakeTransportContext()

    def fake_create_mcp_http_client(**kwargs: Any) -> httpx.AsyncClient:
        factory_calls.append(kwargs)
        return httpx.AsyncClient(**kwargs)

    _install_fake_mcp_modules(
        monkeypatch,
        streamable_http_client=fake_streamable_http_client,
        create_mcp_http_client=fake_create_mcp_http_client,
    )

    info = await probe_remote(
        RemoteServerConfig(
            url="https://mcp.test/mcp",
            transport="streamable-http",
            auth=RemoteAuth(bearer_token="test-token"),
        )
    )

    assert info.transport == "streamable-http-live"
    assert len(calls) == 1
    assert calls[0]["url"] == "https://mcp.test/mcp"
    assert set(calls[0]["kwargs"]) == {"http_client"}
    assert factory_calls == [{"headers": {"Authorization": "Bearer test-token"}}]
    http_client = calls[0]["kwargs"]["http_client"]
    assert isinstance(http_client, httpx.AsyncClient)
    assert http_client.headers["Authorization"] == "Bearer test-token"
    assert http_client.is_closed


@pytest.mark.asyncio
async def test_sse_probe_still_passes_headers_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_streamable_http_client(*_args: Any, **_kwargs: Any) -> _FakeTransportContext:
        raise AssertionError("streamable HTTP transport should not be used for SSE")

    def fake_sse_client(url: str, **kwargs: Any) -> _FakeTransportContext:
        calls.append({"url": url, "kwargs": kwargs})
        return _FakeTransportContext()

    _install_fake_mcp_modules(
        monkeypatch,
        streamable_http_client=fake_streamable_http_client,
        sse_client=fake_sse_client,
    )

    info = await probe_remote(
        RemoteServerConfig(
            url="https://mcp.test/sse",
            transport="sse",
            auth=RemoteAuth(headers={"X-Api-Key": "secret"}),
        )
    )

    assert info.transport == "sse-live"
    assert calls == [{"url": "https://mcp.test/sse", "kwargs": {"headers": {"X-Api-Key": "secret"}}}]
