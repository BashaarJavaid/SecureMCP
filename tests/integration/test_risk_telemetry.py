"""Item 18 telemetry factors end to end: repeated denials raise the next scored
call's risk, a spike of failed key lookups does the same gateway-wide, and a tool's
drift history keeps counting after re-approval (audit log, not tool_baselines, is
the source of truth). Business hours are dropped as in test_risk_approval so scores
are time-of-day independent."""

import secrets
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
from tests.adversarial.conftest import set_mutation, upstream_command
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect


def _policy(keys: dict[str, str], allowed_tool: str) -> dict:
    return {
        "version": 1,
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": [allowed_tool]}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


@pytest.fixture
def no_business_hours(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )


@pytest.fixture
async def telemetry_gateway(
    clean_audit: None, no_business_hours: None, tmp_path: Path
) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, "echo")))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def allow_factors(tool_name: str) -> set[str]:
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type == "ALLOW", AuditLog.tool_name == tool_name)
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    assert rows, f"no ALLOW row for {tool_name!r}"
    return {f["factor"] for f in rows[-1].payload.get("risk_factors", [])}


async def test_repeated_denials_raise_the_next_scored_call(telemetry_gateway: Gateway) -> None:
    async with connect(telemetry_gateway.url, telemetry_gateway.keys["agent"]) as session:
        # Walk the identity past the denial threshold (default >3 in 10 min).
        for _ in range(4):
            with pytest.raises(McpError) as excinfo:
                await session.call_tool("add", {"a": 1, "b": 2})
            assert excinfo.value.error.data["event_type"] == "DENY_RBAC"

        # The next allowed call is scored with the denial history behind it.
        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
    assert await allow_factors("echo") == {"prior_denial_rate"}


async def test_auth_failure_spike_raises_every_identitys_calls(
    telemetry_gateway: Gateway,
) -> None:
    # Credential stuffing: wrong keys past the threshold (default >5 in 5 min)...
    async with httpx.AsyncClient() as client:
        for _ in range(6):
            response = await client.post(
                f"{telemetry_gateway.url}/mcp/",
                headers={"X-SecurMCP-Key": "not-a-real-key"},
                json={},
            )
            assert response.status_code == 401

    # ...then a perfectly valid call carries the gateway-wide spike as a factor.
    async with connect(telemetry_gateway.url, telemetry_gateway.keys["agent"]) as session:
        result = await session.call_tool("echo", {"text": "hi"})
        assert isinstance(result.content[0], TextContent)
    assert await allow_factors("echo") == {"auth_failures"}


@pytest.fixture
async def drift_history_gateway(
    clean_audit: None, no_business_hours: None, tmp_path: Path
) -> AsyncIterator[Gateway]:
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_policy(keys, "send_email")))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw


async def test_drift_history_survives_reapproval(drift_history_gateway: Gateway) -> None:
    gw = drift_history_gateway
    # Baseline the pristine shape, then drift it twice at non-blocking severities
    # (Low: description change; Medium: optional param) — two DRIFT_* audit events.
    async with connect(gw.url, gw.keys["agent"]) as session:
        await session.list_tools()
    for mutation in ("description", "optional_param"):
        set_mutation(mutation)
        async with connect(gw.url, gw.keys["agent"]) as session:
            await session.list_tools()

    # Re-approval promotes the observed schema and clears drift-in-review...
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{gw.url}/admin/tools/default/send_email/approve",
            headers={"X-SecurMCP-Key": gw.keys["ops-admin"]},
        )
        assert response.status_code == 200

    # ...but the tool's drift history keeps scoring: the audit rows don't reset.
    async with connect(gw.url, gw.keys["agent"]) as session:
        result = await session.call_tool("send_email", {"to": "a@b.c", "subject": "hi"})
        assert isinstance(result.content[0], TextContent)
    factors = await allow_factors("send_email")
    assert "drift_history" in factors
    assert "drift_in_review" not in factors  # cleared by the approval, §4.8
