"""Audit chain integration (§4.8/§11): every decision point writes a chained row,
the basic verifier validates the chain, tampering is caught, concurrent writes don't
collide, and an unrecordable action is denied (§5)."""

import asyncio
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest
import redis.asyncio as aioredis
from mcp import McpError
from sqlalchemy import select, text

from services.gateway.audit_log import GENESIS_HASH, AuditWriter
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from services.gateway.decision import EventType
from services.gateway.main import app
from tests.integration.conftest import Gateway
from tests.integration.test_policy_scoping import connect


async def drive_session(gateway: Gateway) -> None:
    """initialize → tools/list → allowed call → denied call, as agent-readonly."""
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        await session.list_tools()
        await session.call_tool("echo", {"text": "hi"})
        with pytest.raises(McpError):
            await session.call_tool("add", {"a": 1, "b": 2})


async def fetch_rows() -> list[AuditLog]:
    async with async_session() as db:
        return list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


def run_verifier() -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [sys.executable, "scripts/verify_audit_chain.py"], capture_output=True, text=True
    )


async def test_decision_points_write_chained_rows(gateway: Gateway) -> None:
    await drive_session(gateway)
    rows = await fetch_rows()

    assert [r.event_type for r in rows] == ["SESSION_START", "TOOLS_LIST", "ALLOW", "DENY_RBAC"]
    assert all(r.identity_id == "agent-readonly" for r in rows)
    assert all(r.policy_version == 1 for r in rows)
    assert rows[2].tool_name == "echo"
    assert rows[3].tool_name == "add"
    assert rows[1].payload["served_tools"] == ["echo"]
    assert rows[1].payload["pruned_tools"] == ["add"]

    assert rows[0].prev_hash == GENESIS_HASH
    for prev, row in zip(rows, rows[1:], strict=False):
        assert row.prev_hash == prev.curr_hash


async def test_deny_error_carries_audit_id(gateway: Gateway) -> None:
    async with connect(gateway.url, gateway.keys["agent-readonly"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("add", {"a": 1, "b": 2})
    rows = await fetch_rows()
    deny_row = rows[-1]
    assert deny_row.event_type == "DENY_RBAC"
    assert excinfo.value.error.data["audit_id"] == str(deny_row.seq)


async def test_verifier_passes_then_catches_tampering(gateway: Gateway) -> None:
    await drive_session(gateway)

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 0, result.stdout + result.stderr

    async with async_session() as db:
        await db.execute(
            text(
                "UPDATE audit_log SET payload = jsonb_set(payload, '{tool_name}', '\"evil\"')"
                " WHERE event_type = 'ALLOW'"
            )
        )
        await db.commit()

    result = await asyncio.to_thread(run_verifier)
    assert result.returncode == 1
    assert "TAMPERED" in result.stdout


async def test_concurrent_writes_do_not_collide(clean_audit: None) -> None:
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    writer = AuditWriter(
        redis_client, async_session, cast(Any, SimpleNamespace(engine=SimpleNamespace(version=1)))
    )
    try:
        seqs = await asyncio.gather(
            *(writer.write(EventType.ALLOW, f"id-{i}", tool_name="echo") for i in range(50))
        )
    finally:
        await redis_client.aclose()

    assert len(set(seqs)) == 50
    rows = await fetch_rows()
    assert len(rows) == 50
    assert rows[0].prev_hash == GENESIS_HASH
    for prev, row in zip(rows, rows[1:], strict=False):
        assert row.prev_hash == prev.curr_hash


async def test_unrecordable_call_is_denied(
    gateway: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with connect(gateway.url, gateway.keys["agent-full"]) as session:
        await session.list_tools()  # prime the schema cache before breaking the writer
        writer = app.state.session_manager._writer

        async def broken_write(*args: Any, **kwargs: Any) -> int:
            raise ConnectionError("postgres down")

        monkeypatch.setattr(writer, "write", broken_write)
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "x"})
        assert "audit log unavailable" in excinfo.value.error.message
