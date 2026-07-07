"""Hash-chain audit writer (ARCHITECTURE.md §4.8). ECDSA signing comes in Phase 2.

Chain: H_t = SHA256(H_(t-1) || canonical_json(payload_t)). The payload is
self-contained — identity, server, tool, event type and policy version live *inside*
it — because the hash covers only the payload; the bare columns on audit_log are
queryable projections, and tampering them is caught via their hash-protected copies.

The latest chain hash is cached in Redis (`latest_audit_hash`) so the hot path never
does a Postgres read; the Postgres insert itself stays synchronous and awaited —
"no record, no action" (§5): if the insert fails, the exception propagates and the
caller must deny.
"""

import asyncio
import hashlib
import logging
from typing import Any

import canonicaljson
import redis.asyncio as aioredis
from redis.exceptions import WatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.config import settings
from services.gateway.db import AuditLog
from services.gateway.decision import EventType
from services.gateway.policy_engine import PolicyStore

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
POINTER_KEY = "latest_audit_hash"


def compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        prev_hash.encode() + canonicaljson.encode_canonical_json(payload)
    ).hexdigest()


class AuditWriter:
    def __init__(
        self,
        redis_client: aioredis.Redis,
        sessionmaker: async_sessionmaker[AsyncSession],
        policy_store: PolicyStore,
    ) -> None:
        self._redis = redis_client
        self._sessions = sessionmaker
        self._policy_store = policy_store
        # Serializes chain writes so seq order matches chain order. Sufficient for the
        # single-instance Phase 1 deployment; multi-replica write ordering is the
        # documented §10 concern, deferred with the rest of the scaling story.
        self._lock = asyncio.Lock()

    async def write(
        self,
        event_type: EventType,
        identity_id: str,
        tool_name: str | None = None,
        payload_extra: dict[str, Any] | None = None,
        risk_score: int | None = None,
    ) -> int:
        """Append one chained row and return its seq. Raises on any failure — callers
        must treat that as a terminal deny (§5 fail-closed)."""
        async with self._lock:
            while True:
                async with self._redis.pipeline(transaction=True) as pipe:
                    try:
                        await pipe.watch(POINTER_KEY)
                        prev_hash = await self._prev_hash(pipe)
                        payload: dict[str, Any] = {
                            "event_type": event_type.value,
                            "identity_id": identity_id,
                            "server_id": settings.upstream_server_id,
                            "tool_name": tool_name,
                            "policy_version": self._policy_store.engine.version,
                            **(payload_extra or {}),
                        }
                        curr_hash = compute_hash(prev_hash, payload)
                        seq = await self._insert(
                            prev_hash,
                            curr_hash,
                            payload,
                            event_type,
                            identity_id,
                            tool_name,
                            risk_score,
                        )
                        pipe.multi()  # type: ignore[no-untyped-call]  # redis-py lacks a stub here
                        await pipe.set(POINTER_KEY, curr_hash)
                        await pipe.execute()
                        return seq
                    except WatchError:
                        # Another writer moved the pointer between watch and exec
                        # (cross-process); recompute from the fresh pointer (§4.8).
                        continue

    async def _prev_hash(self, pipe: "aioredis.client.Pipeline") -> str:
        cached: bytes | None = await pipe.get(POINTER_KEY)
        if cached is not None:
            return cached.decode()
        # Cold start / evicted pointer: the one-off slow path §4.8 keeps off the hot path.
        async with self._sessions() as session:
            result = await session.execute(
                select(AuditLog.curr_hash).order_by(AuditLog.seq.desc()).limit(1)
            )
            row = result.scalar_one_or_none()
        return row if row is not None else GENESIS_HASH

    async def _insert(
        self,
        prev_hash: str,
        curr_hash: str,
        payload: dict[str, Any],
        event_type: EventType,
        identity_id: str,
        tool_name: str | None,
        risk_score: int | None,
    ) -> int:
        async with self._sessions() as session:
            row = AuditLog(
                prev_hash=prev_hash,
                curr_hash=curr_hash,
                identity_id=identity_id,
                server_id=settings.upstream_server_id,
                tool_name=tool_name,
                policy_version=self._policy_store.engine.version,
                event_type=event_type.value,
                risk_score=risk_score,
                payload=payload,
            )
            session.add(row)
            await session.commit()
            return row.seq
