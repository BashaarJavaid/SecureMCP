"""Step-up auth end to end (item 37): a CHALLENGE-band call completes after the
human satisfies the TOTP factor, and stays denied without it — the roadmap's two
verify checks. Adversarial replay/TOCTOU/dedup cases live in
tests/adversarial/test_step_up.py.

Same deterministic scoring setup as test_risk_approval.py: business hours dropped,
echo tiered medium (20), "prod-*" arguments add 30 — 50 lands in the 40-69 band."""

import base64
import secrets
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from mcp import McpError
from mcp.types import TextContent
from sqlalchemy import select

from services.gateway import risk_engine
from services.gateway.db import AuditLog, async_session
from services.gateway.step_up import (
    CHALLENGE_ID_META_KEY,
    CHALLENGE_PROOF_META_KEY,
    totp_code,
)
from tests.integration.conftest import ECHO_SERVER, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect

TOTP_SECRET_ENV = "SECURMCP_TEST_TOTP_SECRET"


@dataclass
class StepUpGateway:
    url: str
    keys: dict[str, str]  # identity id -> raw API key
    totp_secret: str  # base32, as the human's authenticator app holds it


@pytest.fixture
async def step_up_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[StepUpGateway]:
    monkeypatch.setattr(
        risk_engine,
        "FACTORS",
        [fn for fn in risk_engine.FACTORS if fn is not risk_engine._business_hours],
    )
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
    monkeypatch.setenv(TOTP_SECRET_ENV, totp_secret)
    keys = {"agent": secrets.token_urlsafe(32), "agent-no-factor": secrets.token_urlsafe(32)}
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
                "totp_secret_env": TOTP_SECRET_ENV,
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "agent-no-factor",
                "api_key_hash": _key_hash(keys["agent-no-factor"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
        ],
    }
    policy_path = tmp_path / "step-up-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield StepUpGateway(url=gw.url, keys=keys, totp_secret=totp_secret)


async def test_challenge_completes_after_totp_and_stays_denied_without_it(
    step_up_gateway: StepUpGateway,
) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent"]) as session:
        # Protected argument (20+30=50): an answerable CHALLENGE, not a bare deny.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "CHALLENGE"
        assert data["risk_score"] == 50
        challenge_id = data["challenge_id"]
        assert challenge_id
        assert "TOTP" in data["reason"]

        # The human reads a code off their authenticator; the retry completes.
        result = await session.call_tool(
            "echo",
            {"text": "prod-db"},
            meta={
                CHALLENGE_ID_META_KEY: challenge_id,
                CHALLENGE_PROOF_META_KEY: totp_code(step_up_gateway.totp_secret),
            },
        )
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "prod-db"

        # Without a valid proof the band stays closed: a wrong code on a fresh
        # challenge is a terminal DENY_STEP_UP, and nothing reaches the upstream.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        second_challenge = excinfo.value.error.data["challenge_id"]
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-db"},
                meta={
                    CHALLENGE_ID_META_KEY: second_challenge,
                    CHALLENGE_PROOF_META_KEY: "000000",
                },
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"

    async with async_session() as db:
        allows = (
            (await db.execute(select(AuditLog).where(AuditLog.event_type == "ALLOW")))
            .scalars()
            .all()
        )
        # The redeemed retry's ALLOW row records which challenge it satisfied.
        assert [row.payload.get("challenge_id") for row in allows] == [challenge_id]
        events = (
            (
                await db.execute(
                    select(AuditLog.event_type)
                    .where(AuditLog.event_type.in_(["CHALLENGE", "DENY_STEP_UP"]))
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
        assert events == ["CHALLENGE", "CHALLENGE", "DENY_STEP_UP"]


async def test_identity_without_factor_keeps_terminal_challenge(
    step_up_gateway: StepUpGateway,
) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent-no-factor"]) as session:
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"})
        data = excinfo.value.error.data
        assert data["event_type"] == "CHALLENGE"
        assert data["challenge_id"] is None  # nothing to redeem — today's terminal error

        # A fabricated id (with a code that would otherwise verify) buys nothing.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-db"},
                meta={
                    CHALLENGE_ID_META_KEY: "f" * 32,
                    CHALLENGE_PROOF_META_KEY: totp_code(step_up_gateway.totp_secret),
                },
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"
