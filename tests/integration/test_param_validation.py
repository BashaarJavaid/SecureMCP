"""Parameter Validator end-to-end (§4.8): strict-mode rejection, DENY_VALIDATION
auditing, and sanitization observable through the echo tool."""

import pytest
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import Gateway
from tests.integration.test_policy_scoping import connect


async def fetch_rows() -> list[AuditLog]:
    async with async_session() as db:
        return list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


async def test_extra_field_is_denied_and_audited(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "hi", "bogus": 1})

    data = excinfo.value.error.data
    assert data["event_type"] == "DENY_VALIDATION"
    assert data["decision"] == "deny"
    rows = await fetch_rows()
    assert rows[-1].event_type == "DENY_VALIDATION"
    assert rows[-1].tool_name == "echo"
    assert data["audit_id"] == str(rows[-1].seq)


async def test_wrong_type_is_denied(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": 42})
        assert excinfo.value.error.data["event_type"] == "DENY_VALIDATION"


async def test_sanitization_is_observable_end_to_end(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()
        result = await session.call_tool("echo", {"text": "../../etc/passwd\x00"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "etc/passwd"  # upstream received cleaned args

    rows = await fetch_rows()
    allow = [r for r in rows if r.event_type == "ALLOW"][-1]
    assert allow.payload["arguments"] == {"text": "etc/passwd"}
    assert allow.payload["sanitized_fields"] == ["text"]
