"""Adversarial step-up auth (item 37): the challenge is one-time, the proof is
one-time, the arguments are pinned (TOCTOU), and a verified proof clears nothing
but the CHALLENGE band — it can never bypass human approval or DENY_RISK."""

import pytest
from mcp import McpError

from services.gateway.config import settings
from services.gateway.step_up import (
    CHALLENGE_ID_META_KEY,
    CHALLENGE_PROOF_META_KEY,
    totp_code,
)
from tests.integration.test_policy_scoping import connect
from tests.integration.test_step_up import StepUpGateway


def _proof_meta(challenge_id: str, code: str) -> dict[str, str]:
    return {CHALLENGE_ID_META_KEY: challenge_id, CHALLENGE_PROOF_META_KEY: code}


async def _challenge_id(session: object, arguments: dict[str, str]) -> str:
    with pytest.raises(McpError) as excinfo:
        await session.call_tool("echo", arguments)  # type: ignore[attr-defined]
    data = excinfo.value.error.data
    assert data["event_type"] == "CHALLENGE"
    return str(data["challenge_id"])


async def test_redeemed_challenge_cannot_be_replayed(step_up_gateway: StepUpGateway) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent"]) as session:
        challenge_id = await _challenge_id(session, {"text": "prod-db"})
        code = totp_code(step_up_gateway.totp_secret)
        await session.call_tool("echo", {"text": "prod-db"}, meta=_proof_meta(challenge_id, code))

        # A captured (id, code) pair replayed verbatim: the challenge was consumed
        # atomically at first redemption.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo", {"text": "prod-db"}, meta=_proof_meta(challenge_id, code)
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"


async def test_captured_code_cannot_answer_a_second_challenge(
    step_up_gateway: StepUpGateway,
) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent"]) as session:
        first = await _challenge_id(session, {"text": "prod-db"})
        code = totp_code(step_up_gateway.totp_secret)
        await session.call_tool("echo", {"text": "prod-db"}, meta=_proof_meta(first, code))

        # Same still-in-window code against a *fresh* challenge: one code, one
        # redemption (the per-identity dedup key).
        second = await _challenge_id(session, {"text": "prod-db"})
        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "prod-db"}, meta=_proof_meta(second, code))
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"


async def test_mutated_arguments_are_toctou_denied_and_consume_the_challenge(
    step_up_gateway: StepUpGateway,
) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent"]) as session:
        challenge_id = await _challenge_id(session, {"text": "prod-db"})

        # The retry answers the challenge but swaps the arguments — the pinned
        # hash catches it, and neither version forwards.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-exfiltrate"},
                meta=_proof_meta(challenge_id, totp_code(step_up_gateway.totp_secret)),
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"

        # One-time use held even though redemption failed: the original call
        # can't ride the consumed challenge either.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-db"},
                meta=_proof_meta(challenge_id, totp_code(step_up_gateway.totp_secret)),
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"


async def test_proof_cannot_clear_the_approval_band(
    step_up_gateway: StepUpGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    async with connect(step_up_gateway.url, step_up_gateway.keys["agent"]) as session:
        challenge_id = await _challenge_id(session, {"text": "prod-db"})  # 50: CHALLENGE

        # The retry is re-scored, and by then the frequency factor spikes it to 70
        # (20+30+20): a valid proof answers a challenge, never an approval hold.
        monkeypatch.setattr(settings, "risk_freq_threshold", 1)
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-db"},
                meta=_proof_meta(challenge_id, totp_code(step_up_gateway.totp_secret)),
            )
        data = excinfo.value.error.data
        assert data["event_type"] == "HUMAN_APPROVAL_REQUIRED"
        assert data["risk_score"] == 70

        # The proof was still consumed on the way through — no second use.
        with pytest.raises(McpError) as excinfo:
            await session.call_tool(
                "echo",
                {"text": "prod-db"},
                meta=_proof_meta(challenge_id, totp_code(step_up_gateway.totp_secret)),
            )
        assert excinfo.value.error.data["event_type"] == "DENY_STEP_UP"
