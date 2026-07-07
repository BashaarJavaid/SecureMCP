"""Replay Guard (ARCHITECTURE.md §4.8): nonce + timestamp window dedup via Redis.

Every tools/call from a compliant client carries a client-generated UUID nonce and a
Unix-epoch-seconds timestamp in `params._meta` under the keys `securmcp/nonce` and
`securmcp/timestamp` (MCP reserves `_meta` for exactly this kind of out-of-band
metadata; top-level params would collide with the typed CallToolRequestParams shape).
A timestamp outside the configurable ±window is rejected; a nonce seen before within
the window is a replay (DENY_REPLAY). Missing or malformed fields fail closed, as does
Redis being unreachable (§5). Deliberately no request signing beyond this pair in v1 —
the bar is "defend against naive replay", not a fully compromised client.
"""

import time
import uuid

import redis.asyncio as aioredis

NONCE_META_KEY = "securmcp/nonce"
TIMESTAMP_META_KEY = "securmcp/timestamp"


def _nonce_key(nonce: str) -> str:
    return f"replay:{nonce}"


class ReplayGuard:
    def __init__(self, redis_client: aioredis.Redis, window_seconds: int) -> None:
        self._redis = redis_client
        self._window = window_seconds

    async def check(self, nonce: object, timestamp: object) -> str | None:
        """Return a denial reason string, or None if the call is fresh.
        Raises on Redis failure — callers deny (fail closed, §5)."""
        if not isinstance(nonce, str):
            return "missing or invalid nonce"
        try:
            uuid.UUID(nonce)
        except ValueError:
            return "missing or invalid nonce"
        if isinstance(timestamp, bool) or not isinstance(timestamp, int | float):
            return "missing or invalid timestamp"
        if abs(time.time() - timestamp) > self._window:
            return f"timestamp outside the ±{self._window}s window"
        # The setting is the half-width: a nonce with timestamp t stays acceptable
        # until t + window, so first-seen + 2×window strictly outlives its validity.
        fresh = await self._redis.set(
            _nonce_key(nonce), 1, nx=True, ex=2 * self._window
        )
        if not fresh:
            return "nonce already seen within the timestamp window"
        return None
