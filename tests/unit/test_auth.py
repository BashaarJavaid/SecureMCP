import hashlib
from typing import Any, cast

from services.gateway.auth import AUTH_FAILURE_KEY, resolve_identity, resolve_identity_tracked
from services.gateway.policy_engine import PolicyEngine, PolicyFile

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
