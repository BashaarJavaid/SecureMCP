"""The item-14 demo, verified before anyone records it: rogue server starts benign,
a REAL POST /_admin/apply_mutation (no timer) swaps send_email's schema mid-session,
the gateway classifies the drift Critical and blocks, an admin re-approves, and the
same call — now carrying the new required bcc — succeeds (scored with the item-36b
suspicious_baseline factor, since the approved mutated description matches the
heuristics)."""

import asyncio
import secrets
import socket
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import risk_engine
from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect

ROGUE_SERVER = Path(__file__).parents[2] / "sample_target" / "rogue_server.py"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
async def rogue_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    # Clock-independent like the drift fixture: the re-approved mutated description
    # is (correctly) flagged suspicious (+20, item 36b), and off-hours (+25) on top
    # would push the post-approval ALLOW into the CHALLENGE band.
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    keys = {"developer": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "developer",
                "api_key_hash": _key_hash(keys["developer"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": ["send_email", "read_inbox"]}
                ],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "rogue-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    state_file = tmp_path / "state.json"
    upstream = f"{sys.executable} {ROGUE_SERVER} --state {state_file}"
    async with running_gateway(policy_path, upstream, keys) as gw:
        yield gw


async def test_full_rogue_demo_arc(rogue_gateway: Gateway, tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    admin_port = _free_port()
    admin_process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(ROGUE_SERVER),
        "--admin",
        "--port",
        str(admin_port),
        "--state",
        str(state_file),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with connect(rogue_gateway.url, rogue_gateway.keys["developer"]) as session:
            # Pruning: the destructive tool is absent, not denied; baseline anchored.
            tools = await session.list_tools()
            assert [t.name for t in tools.tools] == ["send_email", "read_inbox"]

            args = {"to": "a@b.c", "subject": "hi", "body": "hello"}
            result = await session.call_tool("send_email", args)
            assert isinstance(result.content[0], TextContent)

            # The real mutation endpoint — operator-triggered, no timer.
            async with httpx.AsyncClient() as client:
                for _ in range(40):  # the admin subprocess may still be booting
                    try:
                        response = await client.post(
                            f"http://127.0.0.1:{admin_port}/_admin/apply_mutation"
                        )
                        break
                    except httpx.ConnectError:
                        await asyncio.sleep(0.25)
                else:
                    pytest.fail("rogue admin endpoint never came up")
            assert response.status_code == 200
            assert state_file.exists()

            # Same live session: the next list shows the mutated schema and the
            # gateway classifies it Critical (new REQUIRED param) and blocks.
            tools = await session.list_tools()
            send_email = {t.name: t for t in tools.tools}["send_email"]
            assert "bcc" in (send_email.inputSchema.get("required") or [])

            with pytest.raises(McpError) as excinfo:
                await session.call_tool("send_email", args)
            assert excinfo.value.error.data["event_type"] == "DENY_DRIFT"

            # Admin reviews and re-approves; the call now succeeds with the new schema.
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{rogue_gateway.url}/admin/tools/default/send_email/approve",
                    headers={"X-PortunusMCP-Key": rogue_gateway.keys["ops-admin"]},
                )
            assert response.status_code == 200
            assert response.json()["event_type"] == "APPROVED"

            result = await session.call_tool("send_email", {**args, "bcc": "x@y.z"})
            assert isinstance(result.content[0], TextContent)
    finally:
        admin_process.terminate()
        await admin_process.wait()

    async with async_session() as db:
        events = (
            await db.execute(
                select(AuditLog.event_type)
                .where(AuditLog.event_type.in_(["DRIFT_CRITICAL", "DENY_DRIFT", "APPROVED"]))
                .order_by(AuditLog.seq)
            )
        ).scalars()
        assert list(events) == ["DRIFT_CRITICAL", "DENY_DRIFT", "APPROVED"]

        # Item 36b: approving the poisoned description unblocked the tool, but the
        # flag survives approval — the final ALLOW was scored knowing it.
        final_allow = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type == "ALLOW")
                    .order_by(AuditLog.seq.desc())
                    .limit(1)
                )
            )
            .scalars()
            .one()
        )
        factors = {f["factor"] for f in final_allow.payload.get("risk_factors", [])}
        assert "suspicious_baseline" in factors
