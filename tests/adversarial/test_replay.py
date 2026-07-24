"""ARCHITECTURE.md §11: simulate a replay attack — identical nonce+timestamp
resubmitted must be DENY_REPLAY, and a timestamp outside the window must be denied.
These identities are `bearer` (item 34): a volunteered nonce is fully enforced, and
a stock client sending none at all still completes its call."""

import time
import uuid

import pytest
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY
from tests.integration.conftest import Gateway
from tests.integration.test_policy_scoping import connect


async def test_identical_nonce_and_timestamp_is_deny_replay(gateway: Gateway) -> None:
    meta = {NONCE_META_KEY: str(uuid.uuid4()), TIMESTAMP_META_KEY: time.time()}
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        result = await session.call_tool("echo", {"text": "original"}, meta=dict(meta))
        assert isinstance(result.content[0], TextContent)

        # The captured request, resubmitted verbatim.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "original"}, meta=dict(meta))
        data = excinfo.value.error.data
        assert data["event_type"] == "DENY_REPLAY"
        assert data["decision"] == "deny"
        assert data["matched_rules"] == ["replay_guard"]
        assert data["audit_id"] is not None

    async with async_session() as db:
        events = (await db.execute(select(AuditLog.event_type).order_by(AuditLog.seq))).scalars()
        assert "DENY_REPLAY" in list(events)


async def test_timestamp_outside_window_is_denied(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "stale"},
                meta={
                    NONCE_META_KEY: str(uuid.uuid4()),
                    TIMESTAMP_META_KEY: time.time() - 31,
                },
            )
        assert excinfo.value.error.data["event_type"] == "DENY_REPLAY"


async def test_malformed_nonce_fails_closed(gateway: Gateway) -> None:
    # A bearer client that volunteers the pair gets it fully enforced (item 34):
    # present-but-garbage is a deny, never a silent skip.
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "bare"},
                meta={NONCE_META_KEY: "not-a-uuid", TIMESTAMP_META_KEY: "yesterday"},
            )
        assert excinfo.value.error.data["event_type"] == "DENY_REPLAY"


async def test_stock_client_without_meta_completes_tools_call(gateway: Gateway) -> None:
    # Item 34 verify: a stock SDK client sending no portunusmcp _meta at all makes a
    # successful tools/call under bearer — the client-compatibility half of the item.
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        result = await session.call_tool("echo", {"text": "no meta"})
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "no meta"
