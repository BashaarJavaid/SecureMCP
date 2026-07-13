import hashlib
import os
from typing import Any, cast

from services.gateway.auth import (
    AUTH_FAILURE_KEY,
    KEY_ID_META_KEY,
    SIGNATURE_META_KEY,
    resolve_identity,
    resolve_identity_tracked,
    sign_request,
    verify_signed_request,
    verify_signed_request_tracked,
)
from services.gateway.policy_engine import PolicyEngine, PolicyFile
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

KEY_A = "test-key-alpha"
KEY_B = "test-key-beta"


def hash_of(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


ENGINE = PolicyEngine(
    PolicyFile.model_validate(
        {
            "version": 1,
            "identities": [
                {"id": "agent-a", "api_key_hash": hash_of(KEY_A), "allowed_servers": []},
                {"id": "agent-b", "api_key_hash": hash_of(KEY_B), "allowed_servers": []},
            ],
        }
    )
)


def test_correct_key_resolves_to_its_identity() -> None:
    assert resolve_identity(KEY_A, ENGINE) == "agent-a"
    assert resolve_identity(KEY_B, ENGINE) == "agent-b"


def test_wrong_key_resolves_to_none() -> None:
    assert resolve_identity("not-a-key", ENGINE) is None


def test_missing_key_resolves_to_none() -> None:
    assert resolve_identity(None, ENGINE) is None
    assert resolve_identity("", ENGINE) is None


class FakeRedis:
    """INCR/EXPIRE recorder for the auth-failure counter (item 18)."""

    def __init__(self, error: Exception | None = None) -> None:
        self.counts: dict[str, int] = {}
        self.expires: dict[str, int] = {}
        self.error = error

    async def incr(self, key: str) -> int:
        if self.error is not None:
            raise self.error
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.expires[key] = seconds


async def test_wrong_key_increments_the_failure_counter() -> None:
    redis = FakeRedis()
    assert await resolve_identity_tracked("not-a-key", ENGINE, cast(Any, redis)) is None
    assert await resolve_identity_tracked("not-a-key", ENGINE, cast(Any, redis)) is None
    assert redis.counts == {AUTH_FAILURE_KEY: 2}
    assert AUTH_FAILURE_KEY in redis.expires  # rolling window set on first failure


async def test_missing_key_is_not_a_stuffing_signal() -> None:
    redis = FakeRedis()
    assert await resolve_identity_tracked(None, ENGINE, cast(Any, redis)) is None
    assert await resolve_identity_tracked("", ENGINE, cast(Any, redis)) is None
    assert redis.counts == {}


async def test_valid_key_does_not_increment() -> None:
    redis = FakeRedis()
    assert await resolve_identity_tracked(KEY_A, ENGINE, cast(Any, redis)) == "agent-a"
    assert redis.counts == {}


async def test_redis_failure_still_produces_the_401_path() -> None:
    # Counting is telemetry: Redis down must yield None (→ 401), never a 500.
    redis = FakeRedis(error=ConnectionError("redis down"))
    assert await resolve_identity_tracked("not-a-key", ENGINE, cast(Any, redis)) is None
    # And a valid key still resolves.
    assert await resolve_identity_tracked(KEY_A, ENGINE, cast(Any, redis)) == "agent-a"


# --- signed mode (item 34) ---

SECRET = "unit-test-signing-secret"
KEY_ID = "kid_unittest"


def signed_engine() -> PolicyEngine:
    os.environ["TEST_SIGNING_SECRET"] = SECRET
    return PolicyEngine(
        PolicyFile.model_validate(
            {
                "version": 1,
                "identities": [
                    {
                        "id": "ci-agent",
                        "auth_mode": "signed",
                        "key_id": KEY_ID,
                        "signing_secret_env": "TEST_SIGNING_SECRET",
                        "allowed_servers": [],
                    }
                ],
            }
        )
    )


def signed_call(
    nonce: str = "n-1",
    timestamp: float = 1000.0,
    method: str = "tools/call",
    tool: str | None = "echo",
    arguments: dict | None = None,
    key_id: str = KEY_ID,
    secret: str = SECRET,
) -> dict[str, Any]:
    if method == "tools/call":
        arguments = arguments if arguments is not None else {"text": "hi"}
    else:
        tool, arguments = None, None
    signature = sign_request(secret.encode(), nonce, timestamp, method, tool, arguments)
    params: dict[str, Any] = {
        "_meta": {
            NONCE_META_KEY: nonce,
            TIMESTAMP_META_KEY: timestamp,
            KEY_ID_META_KEY: key_id,
            SIGNATURE_META_KEY: signature,
        }
    }
    if method == "tools/call":
        params["name"] = tool
        params["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


def test_valid_signature_resolves_to_its_identity() -> None:
    assert verify_signed_request(signed_call(), signed_engine()) == "ci-agent"


def test_non_tools_call_methods_verify_with_null_tool() -> None:
    message = signed_call(method="tools/list")
    assert verify_signed_request(message, signed_engine()) == "ci-agent"


def test_tampered_arguments_fail_verification() -> None:
    message = signed_call()
    message["params"]["arguments"] = {"text": "rm -rf /"}
    assert verify_signed_request(message, signed_engine()) is None


def test_fresh_nonce_cannot_be_re_signed_without_the_secret() -> None:
    # The attacker swaps in a fresh nonce/timestamp but can only reuse the captured
    # signature — verification must fail (the item-34 core property).
    message = signed_call()
    message["params"]["_meta"][NONCE_META_KEY] = "n-2"
    message["params"]["_meta"][TIMESTAMP_META_KEY] = 2000.0
    assert verify_signed_request(message, signed_engine()) is None


def test_unknown_key_id_fails() -> None:
    assert verify_signed_request(signed_call(key_id="kid_nope"), signed_engine()) is None


def test_wrong_secret_fails() -> None:
    assert verify_signed_request(signed_call(secret="guessed"), signed_engine()) is None


def test_missing_nonce_or_signature_fails() -> None:
    engine = signed_engine()
    for key in (NONCE_META_KEY, TIMESTAMP_META_KEY, KEY_ID_META_KEY, SIGNATURE_META_KEY):
        message = signed_call()
        del message["params"]["_meta"][key]
        assert verify_signed_request(message, engine) is None, key


async def test_bad_signature_increments_the_failure_counter() -> None:
    redis = FakeRedis()
    message = signed_call(secret="guessed")
    assert await verify_signed_request_tracked(message, signed_engine(), cast(Any, redis)) is None
    assert redis.counts == {AUTH_FAILURE_KEY: 1}


async def test_no_key_material_is_not_a_stuffing_signal() -> None:
    redis = FakeRedis()
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}}
    assert await verify_signed_request_tracked(message, signed_engine(), cast(Any, redis)) is None
    assert redis.counts == {}
