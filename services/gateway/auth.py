"""API key verification, identity resolution (ARCHITECTURE.md §4.8 Auth Layer).

Hash-and-lookup, not HMAC or signing: the policy store holds only SHA256(key) as
"sha256:<hex>"; the presented key is hashed and looked up directly. Keys are 256-bit
random values (see scripts/generate_api_key.py), so no salting is needed — and
deterministic hashing is what makes direct lookup possible. Never log the key (§6).

Item 18 adds the auth-failure counter: one gateway-wide Redis rolling counter bumped
on every failed key lookup — a spike just before a successful call is a classic
credential-stuffing pattern, so the Risk Engine reads it as a factor for every
identity while the spike is live. Counting is best-effort telemetry: Redis being
down must keep producing 401s, never 500s.
"""

import hashlib

import redis.asyncio as aioredis
import structlog

from services.gateway.config import settings
from services.gateway.policy_engine import PolicyEngine

logger = structlog.get_logger(__name__)

AUTH_FAILURE_KEY = "risk:auth_failures"


def resolve_identity(api_key: str | None, engine: PolicyEngine) -> str | None:
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    return engine.identity_for_key_hash(f"sha256:{digest}")


async def resolve_identity_tracked(
    api_key: str | None, engine: PolicyEngine, redis_client: aioredis.Redis
) -> str | None:
    """resolve_identity plus the failure counter: a *wrong* key counts (that's the
    stuffing signal); a missing header does not. Same INCR + EXPIRE-on-first rolling
    window as the risk:freq counters."""
    identity_id = resolve_identity(api_key, engine)
    if identity_id is None and api_key:
        try:
            count = await redis_client.incr(AUTH_FAILURE_KEY)
            if count == 1:
                await redis_client.expire(
                    AUTH_FAILURE_KEY, settings.risk_auth_failure_window_seconds
                )
        except Exception:
            logger.exception("auth_failure_count_unavailable")
    return identity_id
