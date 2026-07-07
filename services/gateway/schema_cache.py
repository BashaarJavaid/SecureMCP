"""Shared per-server tool-schema cache (ARCHITECTURE.md §8).

Redis-backed with a TTL (default 10 min): a long-lived session must not trust a stale
schema indefinitely between handshakes. Invalidated on every initialize (a fresh
handshake is the natural trust boundary); expiry surfaces as a cache miss, which makes
the interceptor transparently re-fetch tools/list from the upstream.
"""

import hashlib
import json
from typing import Any

import canonicaljson
import redis.asyncio as aioredis

from services.gateway.config import settings


def _key(server_id: str) -> str:
    return f"schema:{server_id}"


def schema_hash(tools: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonicaljson.encode_canonical_json(tools)).hexdigest()


class SchemaCache:
    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client

    async def get(self, server_id: str) -> list[dict[str, Any]] | None:
        raw = await self._redis.get(_key(server_id))
        if raw is None:
            return None
        tools: list[dict[str, Any]] = json.loads(raw)
        return tools

    async def put(self, server_id: str, tools: list[dict[str, Any]]) -> str:
        """Cache the full tool list; returns its canonical hash (ETag ingredient)."""
        encoded = canonicaljson.encode_canonical_json(tools)
        await self._redis.set(_key(server_id), encoded, ex=settings.schema_cache_ttl)
        return hashlib.sha256(encoded).hexdigest()

    async def invalidate(self, server_id: str) -> None:
        await self._redis.delete(_key(server_id))
