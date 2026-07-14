"""API key verification, identity resolution (ARCHITECTURE.md §4.8 Auth Layer).

Two per-identity auth modes (item 34). `bearer` is hash-and-lookup: the policy store
holds only SHA256(key) as "sha256:<hex>"; the presented key is hashed and looked up
directly. Keys are 256-bit random values (see scripts/generate_api_key.py), so no
salting is needed — and deterministic hashing is what makes direct lookup possible.
Never log the key (§6). `signed` puts no secret on the wire at all: the request
carries a non-secret key id plus an HMAC-SHA256 over the canonical
(nonce, timestamp, method, tool, arguments) tuple in params._meta, verified against
a secret the gateway resolves from the environment at policy load. A captured signed
request contains no credential, so a fresh nonce cannot be re-signed.

Item 18 adds the auth-failure counter: one gateway-wide Redis rolling counter bumped
on every failed key lookup (and, item 34, every unknown key id or bad signature) — a
spike just before a successful call is a classic credential-stuffing pattern, so the
Risk Engine reads it as a factor for every identity while the spike is live. Counting
is best-effort telemetry: Redis being down must keep producing 401s, never 500s.
"""

import hashlib
import hmac
from typing import Any

import canonicaljson
import redis.asyncio as aioredis
import structlog

from services.gateway.config import settings
from services.gateway.policy_engine import PolicyEngine
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

logger = structlog.get_logger(__name__)

AUTH_FAILURE_KEY = "risk:auth_failures"

KEY_ID_META_KEY = "securmcp/key-id"
SIGNATURE_META_KEY = "securmcp/signature"


def resolve_identity(api_key: str | None, engine: PolicyEngine) -> str | None:
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode()).hexdigest()
    return engine.identity_for_key_hash(f"sha256:{digest}")


async def _count_failure(redis_client: aioredis.Redis) -> None:
    """Best-effort bump of the gateway-wide failure counter (item 18): same
    INCR + EXPIRE-on-first rolling window as the risk:freq counters."""
    try:
        count = await redis_client.incr(AUTH_FAILURE_KEY)
        if count == 1:
            await redis_client.expire(AUTH_FAILURE_KEY, settings.risk_auth_failure_window_seconds)
    except Exception:
        logger.exception("auth_failure_count_unavailable")


async def resolve_identity_tracked(
    api_key: str | None, engine: PolicyEngine, redis_client: aioredis.Redis
) -> str | None:
    """resolve_identity plus the failure counter: a *wrong* key counts (that's the
    stuffing signal); a missing header does not."""
    identity_id = resolve_identity(api_key, engine)
    if identity_id is None and api_key:
        await _count_failure(redis_client)
    return identity_id


def signature_payload(
    nonce: object, timestamp: object, method: str, tool: object, arguments: object
) -> bytes:
    """The canonical bytes a signed request's HMAC covers (item 34). canonicaljson —
    the same canonicalization the audit chain and drift hashes pin — kills every
    separator/encoding ambiguity a hand-rolled concatenation would reintroduce."""
    return canonicaljson.encode_canonical_json(
        {
            "nonce": nonce,
            "timestamp": timestamp,
            "method": method,
            "tool": tool,
            "arguments": arguments,
        }
    )


def sign_request(
    secret: bytes, nonce: object, timestamp: object, method: str, tool: object, arguments: object
) -> str:
    return hmac.new(
        secret, signature_payload(nonce, timestamp, method, tool, arguments), hashlib.sha256
    ).hexdigest()


def verify_signed_request(message: dict[str, Any], engine: PolicyEngine) -> str | None:
    """Resolve + verify a signed-mode JSON-RPC request: identity id on success, None
    on any failure — unknown key id, missing fields, bad signature (fail closed, §5).
    The nonce/timestamp are required members of the signed tuple here; their format
    and freshness are the Replay Guard's job (dedup → DENY_REPLAY, not 401)."""
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta") or {}
    if not isinstance(meta, dict):
        return None
    method = message.get("method")
    key_id = meta.get(KEY_ID_META_KEY)
    signature = meta.get(SIGNATURE_META_KEY)
    nonce = meta.get(NONCE_META_KEY)
    timestamp = meta.get(TIMESTAMP_META_KEY)
    if (
        not isinstance(method, str)
        or not isinstance(key_id, str)
        or not isinstance(signature, str)
        or nonce is None
        or timestamp is None
    ):
        return None
    identity_id = engine.identity_for_key_id(key_id)
    if identity_id is None:
        return None
    identity = engine.identity(identity_id)
    if identity is None or identity.auth_mode != "signed":
        return None
    if method == "tools/call":
        tool, arguments = params.get("name"), params.get("arguments")
    else:
        tool, arguments = None, None
    expected = sign_request(identity.signing_secret, nonce, timestamp, method, tool, arguments)
    if not hmac.compare_digest(expected, signature):
        return None
    return identity_id


async def verify_signed_request_tracked(
    message: dict[str, Any], engine: PolicyEngine, redis_client: aioredis.Redis
) -> str | None:
    """verify_signed_request plus the failure counter: a presented-but-wrong key id
    or signature counts (forgery/stuffing signal); a request with no key material
    at all does not — mirroring the bearer path."""
    identity_id = verify_signed_request(message, engine)
    if identity_id is None:
        params = message.get("params") if isinstance(message, dict) else None
        meta = params.get("_meta") if isinstance(params, dict) else None
        if isinstance(meta, dict) and (
            meta.get(KEY_ID_META_KEY) is not None or meta.get(SIGNATURE_META_KEY) is not None
        ):
            await _count_failure(redis_client)
    return identity_id
