"""Decision Explanation end to end (item 20): GET /admin/decisions/{seq} reconstructs
what a live terminal decision recorded, POST /admin/decisions/explain dry-runs the
pipeline with the same outcome a live call would get — without writing audit rows or
bumping Redis telemetry — and both endpoints enforce the admin flag.

Same score setup as test_risk_approval: business-hours factor dropped (unit-tested,
keeps scores time-of-day independent), echo tiered medium (20), "prod-*" adds 30."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import redis.asyncio as aioredis
import yaml
from mcp import McpError
from sqlalchemy import func, select

from services.gateway import risk_engine
from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect


@pytest.fixture
async def explain_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    keys = {"agent": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "risk": {
            "tool_sensitivity": {"echo": "medium"},
            "protected_repos": ["prod-*"],
        },
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "admin": True,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "explain-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def _audit_row_count() -> int:
    async with async_session() as db:
        return (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()


async def test_get_decision_reconstructs_live_terminals(explain_gateway: Gateway) -> None:
    async with connect(explain_gateway.url, explain_gateway.keys["agent"]) as session:
        # An RBAC deny and a risk CHALLENGE (20+30=50), each carrying its audit_id.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("not_granted", {})
        rbac_deny = excinfo.value.error.data
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        challenge = excinfo.value.error.data

    async with httpx.AsyncClient() as client:
        admin = {"X-SecurMCP-Key": explain_gateway.keys["ops-admin"]}
        response = await client.get(
            f"{explain_gateway.url}/admin/decisions/{rbac_deny['audit_id']}", headers=admin
        )
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "deny"
        assert body["event_type"] == "DENY_RBAC"
        assert body["matched_rules"] == rbac_deny["matched_rules"]
        assert body["reason"] == rbac_deny["reason"]
        assert body["audit_id"] == rbac_deny["audit_id"]

        response = await client.get(
            f"{explain_gateway.url}/admin/decisions/{challenge['audit_id']}", headers=admin
        )
        assert response.status_code == 200
        body = response.json()
        assert body["decision"] == "challenge"
        assert body["risk_score"] == challenge["risk_score"] == 50
        assert body["matched_rules"] == ["risk_engine"]
        factors = {f["factor"]: f for f in body["risk_factors"]}
        assert set(factors) == {"tool_sensitivity", "protected_repository"}
        assert all(f["reason"] for f in factors.values())  # reason strings survive


async def test_explain_matches_live_outcome_without_side_effects(
    explain_gateway: Gateway,
) -> None:
    # Warm the shared schema cache (explain never re-fetches from the upstream).
    async with connect(explain_gateway.url, explain_gateway.keys["agent"]) as session:
        await session.list_tools()

        rows_before = await _audit_row_count()
        redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
        try:
            freq_key = "risk:freq:agent:echo"
            assert await redis_client.get(freq_key) is None

            async with httpx.AsyncClient() as client:
                admin = {"X-SecurMCP-Key": explain_gateway.keys["ops-admin"]}
                url = f"{explain_gateway.url}/admin/decisions/explain"
                response = await client.post(
                    url,
                    headers=admin,
                    json={"identity": "agent", "tool": "echo", "arguments": {"text": "prod-db"}},
                )
                assert response.status_code == 200
                explained = response.json()
                assert explained["decision"] == "challenge"
                assert explained["event_type"] == "CHALLENGE"
                assert explained["risk_score"] == 50
                assert explained["audit_id"] is None

                # A hypothetical allow and a hypothetical RBAC deny, same dry-run path.
                response = await client.post(
                    url,
                    headers=admin,
                    json={"identity": "agent", "tool": "echo", "arguments": {"text": "hello"}},
                )
                assert response.json()["decision"] == "allow"
                response = await client.post(
                    url, headers=admin, json={"identity": "agent", "tool": "not_granted"}
                )
                assert response.json()["event_type"] == "DENY_RBAC"

            # Dry run: no audit rows written, no frequency counter bumped.
            assert await _audit_row_count() == rows_before
            assert await redis_client.get(freq_key) is None
        finally:
            await redis_client.aclose()

        # The live call explain predicted: same outcome, same score.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        live = excinfo.value.error.data
        assert live["event_type"] == explained["event_type"]
        assert live["risk_score"] == explained["risk_score"]


async def test_admin_auth_and_missing_rows(explain_gateway: Gateway) -> None:
    async with httpx.AsyncClient() as client:
        url = f"{explain_gateway.url}/admin/decisions"
        agent = {"X-SecurMCP-Key": explain_gateway.keys["agent"]}
        admin = {"X-SecurMCP-Key": explain_gateway.keys["ops-admin"]}

        assert (await client.get(f"{url}/1", headers=agent)).status_code == 403
        assert (await client.get(f"{url}/1")).status_code == 401
        body = {"identity": "agent", "tool": "echo"}
        assert (await client.post(f"{url}/explain", headers=agent, json=body)).status_code == 403

        response = await client.get(f"{url}/999999", headers=admin)
        assert response.status_code == 404
        assert "no audit row" in response.json()["detail"]

        # seq 1 is the boot-time POLICY_ACTIVATED row — real, but not a decision.
        response = await client.get(f"{url}/1", headers=admin)
        assert response.status_code == 404
        assert "not a decision" in response.json()["detail"]
