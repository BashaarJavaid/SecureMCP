"""A session that goes silent without disconnecting is reaped once its Redis
last-seen key expires (ARCHITECTURE.md §4.8, session idle timeout)."""

import asyncio
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from services.gateway.config import settings
from services.gateway.main import app
from tests.integration.conftest import Gateway


async def test_idle_session_is_torn_down(gateway: Gateway) -> None:
    manager = app.state.session_manager
    old_ttl = settings.session_idle_ttl
    settings.session_idle_ttl = 1
    observed: dict[str, Any] = {}
    try:
        # The client-side contexts may error on exit — the server side is gone by then —
        # so observations are captured inside and asserted outside.
        try:
            async with httpx.AsyncClient(
                headers={"X-PortunusMCP-Key": gateway.keys["agent-full"]}, follow_redirects=True
            ) as http_client:
                async with streamable_http_client(
                    f"{gateway.url}/mcp/default", http_client=http_client
                ) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        observed["sessions_before"] = len(manager._sessions)
                        process = next(iter(manager._sessions.values())).process
                        await asyncio.sleep(1.5)  # let the last_seen key expire
                        await manager.sweep_once()
                        observed["sessions_after"] = len(manager._sessions)
                        await process.wait()
                        observed["returncode"] = process.returncode
        except Exception:
            pass
    finally:
        settings.session_idle_ttl = old_ttl

    assert observed["sessions_before"] == 1
    assert observed["sessions_after"] == 0
    assert observed["returncode"] is not None  # subprocess actually exited
