"""Parameter Validator end-to-end (§4.8): strict-mode rejection and DENY_VALIDATION
auditing, including injection-pattern rejection (item 31), through the echo tool."""

import pytest
from mcp import McpError
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


@pytest.mark.parametrize("text", ["....//etc/passwd", "..././etc/passwd", "a\x00b"])
async def test_injection_patterns_are_denied_not_rewritten(gateway: Gateway, text: str) -> None:
    # Item 31: the old sanitizer would have rewritten the first two into '../…'
    # and forwarded them upstream. Rejection is the only fail-closed posture.
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": text})

    data = excinfo.value.error.data
    assert data["event_type"] == "DENY_VALIDATION"
    assert data["decision"] == "deny"
    rows = await fetch_rows()
    assert rows[-1].event_type == "DENY_VALIDATION"
    assert "sanitized_fields" not in rows[-1].payload
    assert data["audit_id"] == str(rows[-1].seq)
