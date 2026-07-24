"""Decision Explanation accuracy across the terminal families the existing
integration tests don't reconstruct (item 20, §11): ALLOW, DENY_ABAC,
DENY_VALIDATION, HUMAN_APPROVAL_REQUIRED, and DENY_DRIFT. For each, a live call
produces the canonical Decision; GET /admin/decisions/{seq} must reconstruct it
field-for-field, and — for the families whose outcome doesn't depend on Redis
counter state — POST /admin/decisions/explain on the same inputs must reach the
same outcome (using an identity with no live traffic, so the dry-run frequency
read can't skew the score).

Business-hours factor dropped like the other explanation suites (unit-tested,
clock-dependent); frequency threshold lowered to 3 so the approval band (70-90)
is reachable: send_email is tiered high (30), "prod-*" arguments add 30, and the
spike adds 20 → 30 ALLOW, 60 CHALLENGE, 80 HUMAN_APPROVAL_REQUIRED."""

import secrets
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import risk_engine
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from tests.adversarial.conftest import set_mutation, upstream_command
from tests.integration.conftest import Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect

BENIGN_ARGS = {"to": "a@b.c", "subject": "hello"}
INVALID_ARGS = {"to": "a@b.c", "subject": "hello", "evil": "x"}  # unknown field, strict
PROD_ARGS = {"to": "a@b.c", "subject": "prod-db"}


@pytest.fixture
async def explain_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    monkeypatch.setattr(settings, "risk_freq_threshold", 3)
    keys = {
        "agent": secrets.token_urlsafe(32),
        "conditioned": secrets.token_urlsafe(32),
        "fresh": secrets.token_urlsafe(32),
        "ops-admin": secrets.token_urlsafe(32),
    }

    def grant(**extra: Any) -> dict[str, Any]:
        return {"server_id": "default", "allowed_tools": ["send_email"], **extra}

    policy = {
        "version": 1,
        "risk": {
            "tool_sensitivity": {"send_email": "high"},
            "protected_repos": ["prod-*"],
        },
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [grant()],
            },
            {
                "id": "conditioned",
                "api_key_hash": _key_hash(keys["conditioned"]),
                "attributes": {"team": "sales"},
                "allowed_servers": [grant(conditions=["identity.team == 'engineering'"])],
            },
            {
                "id": "fresh",
                "api_key_hash": _key_hash(keys["fresh"]),
                "allowed_servers": [grant()],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [],
            },
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw


async def _get_decision(gw: Gateway, seq: Any) -> dict[str, Any]:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{gw.url}/admin/decisions/{seq}",
            headers={"X-PortunusMCP-Key": gw.keys["ops-admin"]},
        )
    assert response.status_code == 200
    return response.json()


async def _explain(gw: Gateway, identity: str, arguments: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{gw.url}/admin/decisions/explain",
            headers={"X-PortunusMCP-Key": gw.keys["ops-admin"]},
            json={"identity": identity, "tool": "send_email", "arguments": arguments},
        )
    assert response.status_code == 200
    return response.json()


def _assert_reconstructs(body: dict[str, Any], live: dict[str, Any]) -> None:
    """GET must reproduce the Decision the client saw, not a paraphrase of it."""
    for field in ("decision", "event_type", "reason", "matched_rules", "risk_score", "audit_id"):
        assert body[field] == live[field], field
    if live.get("risk_factors"):
        assert body["risk_factors"] == live["risk_factors"]


async def test_reconstruction_and_dry_run_match_live_terminals(
    explain_gateway: Gateway,
) -> None:
    gw = explain_gateway
    live: dict[str, dict[str, Any]] = {}

    async with connect(gw.url, gw.keys["agent"]) as session:
        # ALLOW (count 1, tier 30 < 40): the one family whose Decision never
        # reaches the client — reconstructed from its audit seq below.
        result = await session.call_tool("send_email", BENIGN_ARGS)
        assert isinstance(result.content[0], TextContent)

        # DENY_VALIDATION (count 2, still 30 → stage 7 rejects the unknown field).
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", INVALID_ARGS)
        live["DENY_VALIDATION"] = excinfo.value.error.data

        # CHALLENGE at 60 (count 3), then the spike lands 80 in the approval band.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", PROD_ARGS)
        assert excinfo.value.error.data["event_type"] == "CHALLENGE"
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", PROD_ARGS)
        live["HUMAN_APPROVAL_REQUIRED"] = excinfo.value.error.data
        assert live["HUMAN_APPROVAL_REQUIRED"]["risk_score"] == 80

    async with connect(gw.url, gw.keys["conditioned"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", BENIGN_ARGS)
        live["DENY_ABAC"] = excinfo.value.error.data

    for data in live.values():
        _assert_reconstructs(await _get_decision(gw, data["audit_id"]), data)

    async with async_session() as db:
        allow_row = (
            await db.execute(select(AuditLog).where(AuditLog.event_type == "ALLOW"))
        ).scalar_one()
    body = await _get_decision(gw, allow_row.seq)
    assert body["decision"] == "allow"
    assert body["event_type"] == "ALLOW"
    assert body["audit_id"] == str(allow_row.seq)

    # Dry-run parity for the counter-independent families, via the untouched
    # identity: same stage, same event_type as the live calls above.
    explained = await _explain(gw, "conditioned", BENIGN_ARGS)
    assert explained["event_type"] == "DENY_ABAC"
    assert explained["reason"] == live["DENY_ABAC"]["reason"]
    explained = await _explain(gw, "fresh", INVALID_ARGS)
    assert explained["event_type"] == "DENY_VALIDATION"

    # DENY_DRIFT: mutate the upstream, let a new session observe the critical
    # drift, and the blocked baseline must show identically in all three views.
    set_mutation("required_change")
    async with connect(gw.url, gw.keys["agent"]) as session:
        await session.list_tools()
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("send_email", BENIGN_ARGS)
    drift_live = excinfo.value.error.data
    assert drift_live["event_type"] == "DENY_DRIFT"
    _assert_reconstructs(await _get_decision(gw, drift_live["audit_id"]), drift_live)
    explained = await _explain(gw, "fresh", BENIGN_ARGS)
    assert explained["event_type"] == "DENY_DRIFT"
