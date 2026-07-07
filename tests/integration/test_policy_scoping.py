"""Identity-scoped tools/list (pruning) plus §4.1 point-of-action enforcement:
a tool absent from the pruned menu is also denied when called directly."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from mcp import ClientSession, McpError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent


@asynccontextmanager
async def connect(gateway: str, identity: str | None) -> AsyncIterator[ClientSession]:
    headers = {"X-SecurMCP-Identity": identity} if identity else {}
    # follow_redirects matches the SDK's default client (Mount("/mcp") redirects to /mcp/).
    async with httpx.AsyncClient(headers=headers, follow_redirects=True) as http_client:
        async with streamable_http_client(f"{gateway}/mcp", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def test_readonly_identity_sees_and_calls_only_allowed_tools(gateway: str) -> None:
    async with connect(gateway, "agent-readonly") as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo"]  # add pruned away

        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "hi"

        # Not in the menu is not the boundary — calling it directly is denied too (§4.1).
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("add", {"a": 2, "b": 3})
        assert excinfo.value.error.data["event_type"] == "DENY_RBAC"
        assert excinfo.value.error.data["decision"] == "deny"


async def test_full_identity_sees_and_calls_everything(gateway: str) -> None:
    async with connect(gateway, "agent-full") as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo", "add"]

        result = await session.call_tool("add", {"a": 2, "b": 3})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "5"


async def test_missing_identity_gets_empty_tool_list(gateway: str) -> None:
    async with connect(gateway, None) as session:
        tools = await session.list_tools()
        assert tools.tools == []
