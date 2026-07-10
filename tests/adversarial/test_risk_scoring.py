"""ARCHITECTURE.md §11: simulate a high-risk call and assert it lands in
HUMAN_APPROVAL_REQUIRED, not ALLOW — the canary the risk weights were anchored to
(high tier 30 + protected repo 30 + off-hours 25 = 85), plus the >90 band as a
terminal DENY_RISK. Unlike the integration suites, the business-hours factor stays
IN; off-hours is deterministic by shrinking the configured window to empty
(start == end makes `start <= hour < end` false at every hour), no clock mocking."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import yaml
from mcp import McpError
from sqlalchemy import select

from services.gateway.config import settings
from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect

CANARY_ARGS = {"text": "acme/prod-api"}


@pytest.fixture
async def canary_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Gateway]:
    monkeypatch.setattr(settings, "business_hours_start_utc", 9)
    monkeypatch.setattr(settings, "business_hours_end_utc", 9)
    monkeypatch.setattr(settings, "risk_freq_threshold", 2)
    keys = {"agent": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "risk": {
            "tool_sensitivity": {"echo": "high"},
            "protected_repos": ["acme/prod-*"],
        },
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def test_canary_lands_in_human_approval_not_allow(canary_gateway: Gateway) -> None:
    async with connect(canary_gateway.url, canary_gateway.keys["agent"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", CANARY_ARGS)
    data = excinfo.value.error.data
    assert data["event_type"] == "HUMAN_APPROVAL_REQUIRED"
    assert data["decision"] == "human_approval_required"
    assert data["risk_score"] == 85
    assert {f["factor"] for f in data["risk_factors"]} == {
        "tool_sensitivity",
        "protected_repository",
        "business_hours",
    }

    async with async_session() as db:
        rows = list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())
    held = [r for r in rows if r.event_type == "HUMAN_APPROVAL_REQUIRED"]
    assert len(held) == 1
    assert held[0].risk_score == 85
    assert not [r for r in rows if r.event_type == "ALLOW"]  # never forwarded


async def test_frequency_spike_over_90_is_deny_risk(canary_gateway: Gateway) -> None:
    async with connect(canary_gateway.url, canary_gateway.keys["agent"]) as session:
        # Two canary calls hold at 85; the third trips the spike (count 3 > 2):
        # 30 + 30 + 25 + 20 = 105, clamped to 100 — past the deny threshold.
        for _ in range(2):
            with pytest.raises(McpError) as excinfo:
                await session.call_tool("echo", CANARY_ARGS)
            assert excinfo.value.error.data["event_type"] == "HUMAN_APPROVAL_REQUIRED"

        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", CANARY_ARGS)
    data = excinfo.value.error.data
    assert data["event_type"] == "DENY_RISK"
    assert data["decision"] == "deny"
    assert data["risk_score"] == 100
    assert {f["factor"] for f in data["risk_factors"]} == {
        "tool_sensitivity",
        "protected_repository",
        "business_hours",
        "call_frequency",
    }
