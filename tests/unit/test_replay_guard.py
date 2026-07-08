import time
import uuid
from typing import Any, cast

import pytest

from services.gateway.replay_guard import ReplayGuard


class FakeRedis:
    """Just enough of redis.asyncio for SET NX EX (expiry not simulated)."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {}
        self.ttls: dict[str, int] = {}

    async def set(
        self, key: str, value: Any, nx: bool = False, ex: int | None = None
    ) -> bool | None:
        if nx and key in self.data:
            return None
        self.data[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True


def make_guard(window: int = 30) -> tuple[ReplayGuard, FakeRedis]:
    fake = FakeRedis()
    return ReplayGuard(cast(Any, fake), window), fake


async def test_fresh_nonce_passes() -> None:
    guard, fake = make_guard()
    nonce = str(uuid.uuid4())
    assert await guard.check(nonce, time.time()) is None
    assert fake.ttls[f"replay:{nonce}"] == 60  # 2 x window covers the ± span


async def test_duplicate_nonce_is_denied() -> None:
    guard, _ = make_guard()
    nonce = str(uuid.uuid4())
    timestamp = time.time()
    assert await guard.check(nonce, timestamp) is None
    reason = await guard.check(nonce, timestamp)
    assert reason == "nonce already seen within the timestamp window"


async def test_stale_timestamp_is_denied() -> None:
    guard, fake = make_guard()
    reason = await guard.check(str(uuid.uuid4()), time.time() - 31)
    assert reason is not None and "window" in reason
    assert not fake.data  # a rejected timestamp must not burn the nonce


async def test_future_timestamp_is_denied() -> None:
    guard, _ = make_guard()
    reason = await guard.check(str(uuid.uuid4()), time.time() + 31)
    assert reason is not None and "window" in reason


@pytest.mark.parametrize("nonce", [None, "", "not-a-uuid", 42, str(uuid.uuid4()).encode()])
async def test_missing_or_invalid_nonce_is_denied(nonce: Any) -> None:
    guard, _ = make_guard()
    assert await guard.check(nonce, time.time()) == "missing or invalid nonce"


@pytest.mark.parametrize("timestamp", [None, "", "1234", True, {}])
async def test_missing_or_invalid_timestamp_is_denied(timestamp: Any) -> None:
    guard, _ = make_guard()
    reason = await guard.check(str(uuid.uuid4()), timestamp)
    assert reason == "missing or invalid timestamp"


async def test_redis_error_propagates() -> None:
    guard, fake = make_guard()

    async def broken(*args: Any, **kwargs: Any) -> bool:
        raise ConnectionError("redis down")

    fake.set = broken  # type: ignore[method-assign]
    with pytest.raises(ConnectionError):  # caller denies (fail closed, §5)
        await guard.check(str(uuid.uuid4()), time.time())
