"""Item 34 e2e: a signing client completes the full initialize → tools/list →
tools/call sequence with no API key header anywhere — identity rides the non-secret
key id, proof rides the per-message HMAC."""

import httpx
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from tests.integration.conftest import SignedGateway, SignedSession


async def test_signed_client_full_sequence(signed_gateway: SignedGateway) -> None:
    async with httpx.AsyncClient(follow_redirects=True) as http_client:  # no key header
        async with streamable_http_client(
            f"{signed_gateway.url}/mcp/default", http_client=http_client
        ) as (
            read,
            write,
            _,
        ):
            async with SignedSession(
                read, write, key_id=signed_gateway.key_id, secret=signed_gateway.secret
            ) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert [tool.name for tool in tools.tools] == ["echo", "add"]
                result = await session.call_tool("echo", {"text": "signed hello"})
                assert isinstance(result.content[0], TextContent)
                assert result.content[0].text == "signed hello"
