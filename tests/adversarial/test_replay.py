"""ARCHITECTURE.md §11: simulate a replay attack — identical nonce+timestamp
resubmitted must be DENY_REPLAY, and a timestamp outside the window must be denied."""

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
        events = (
            await db.execute(select(AuditLog.event_type).order_by(AuditLog.seq))
        ).scalars()
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


async def test_missing_nonce_fails_closed(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo", {"text": "bare"}, meta={NONCE_META_KEY: None, TIMESTAMP_META_KEY: None}
            )
        assert excinfo.value.error.data["event_type"] == "DENY_REPLAY"
