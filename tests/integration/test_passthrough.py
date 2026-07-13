"""ARCHITECTURE.md §11 integration criterion: full initialize → tools/list → tools/call
sequence via the actual MCP client SDK, proxied through the gateway."""

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from tests.integration.conftest import Gateway


async def test_full_sequence_passes_through(gateway: Gateway) -> None:
    async with httpx.AsyncClient(
        headers={"X-SecurMCP-Key": gateway.keys["agent-full"]}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(
            f"{gateway.url}/mcp/default", http_client=http_client
        ) as (
            read,
            write,
            _get_session_id,
        ):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert init.serverInfo.name == "echo-upstream"  # upstream's identity, untouched

                tools = await session.list_tools()
                assert [tool.name for tool in tools.tools] == ["echo", "add"]

                result = await session.call_tool("echo", {"text": "hello through the gateway"})
                assert isinstance(result.content[0], TextContent)
                assert result.content[0].text == "hello through the gateway"
