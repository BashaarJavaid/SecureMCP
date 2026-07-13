"""Human approval lifecycle (ARCHITECTURE.md §4.8, item 16).

A HUMAN_APPROVAL_REQUIRED decision creates a Postgres `approvals` row tied to that
decision's audit seq (restart-durable: pending state survives the gateway). An admin
approves via POST /admin/approvals/{approval_id}/approve; the client then *re-invokes*
the tool with the approval id in `params._meta` under `securmcp/approval_id` (the held
call is not auto-retried), alongside a fresh replay nonce/timestamp.

Redemption re-checks everything the approval asserted: identity and tool must match,
the row must be approved, unexpired, and unconsumed (reuse is a replay class,
DENY_REPLAY), and the arguments hash recomputed at redemption must equal the hash
stored at request time — a mismatch is the TOCTOU case, DENY_APPROVAL_MISMATCH.
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import canonicaljson
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.db import Approval
from services.gateway.decision import EventType

APPROVAL_META_KEY = "securmcp/approval_id"


def arguments_hash(arguments: dict[str, Any]) -> str:
    """Canonical hash of a call's arguments, computed the same way at request time
    and at redemption so the TOCTOU comparison is apples-to-apples."""
    return hashlib.sha256(canonicaljson.encode_canonical_json(arguments)).hexdigest()


class ApprovalStore:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], writer: AuditWriter) -> None:
        self._sessions = sessionmaker
        self._writer = writer

    async def create(self, identity_id: str, tool_name: str, args_hash: str, audit_id: int) -> str:
        approval_id = uuid.uuid4().hex
        async with self._sessions() as session:
            session.add(
                Approval(
                    approval_id=approval_id,
                    audit_id=audit_id,
                    identity_id=identity_id,
                    tool_name=tool_name,
                    arguments_hash=args_hash,
                    expires_at=datetime.now(UTC) + timedelta(seconds=settings.approval_ttl_seconds),
                )
            )
            await session.commit()
        return approval_id

    async def approve(self, approval_id: str, approved_by: str) -> tuple[int, str, str]:
        """Admin action: pending + unexpired -> approved. Returns the APPROVED audit
        row's seq plus the approval's (identity_id, tool_name) — the risk-decay
        counter is keyed on that pair. Raises LookupError for anything that can't
        be approved."""
        async with self._sessions() as session:
            row = await self._locked(session, approval_id)
            if row is None:
                raise LookupError("unknown approval id")
            if row.status == "pending" and _expired(row):
                row.status = "expired"
                await self._writer.write(
                    EventType.EXPIRED,
                    row.identity_id,
                    tool_name=row.tool_name,
                    payload_extra={"approval_id": approval_id},
                )
                await session.commit()
                raise LookupError("approval has expired")
            if row.status != "pending":
                raise LookupError(f"approval is {row.status}, not pending")
            row.status = "approved"
            row.approved_by = approved_by
            row.approved_at = datetime.now(UTC)
            seq = await self._writer.write(
                EventType.APPROVED,
                approved_by,
                tool_name=row.tool_name,
                payload_extra={"approval_id": approval_id, "identity_id": row.identity_id},
            )
            await session.commit()
            return seq, row.identity_id, row.tool_name

    async def redeem(
        self, approval_id: str, identity_id: str, tool_name: str, args_hash: str
    ) -> tuple[EventType, str] | None:
        """Validate an approved retry and mark it consumed in the same transaction
        (one-time use holds even if the forward later fails). Returns None on success,
        or the (event_type, reason) classifying the denial."""
        async with self._sessions() as session:
            row = await self._locked(session, approval_id)
            if row is None:
                return (EventType.DENY_APPROVAL_MISMATCH, "unknown approval id")
            if row.consumed:
                # Approval reuse is itself a replay class (§4.8).
                return (EventType.DENY_REPLAY, "approval has already been used")
            if _expired(row):
                if row.status == "pending":
                    row.status = "expired"
                    await session.commit()
                return (EventType.EXPIRED, "approval has expired")
            if row.status != "approved":
                return (EventType.DENY_APPROVAL_MISMATCH, "approval has not been granted")
            if row.identity_id != identity_id or row.tool_name != tool_name:
                return (
                    EventType.DENY_APPROVAL_MISMATCH,
                    "approval was granted to a different identity or tool",
                )
            if row.arguments_hash != args_hash:
                # TOCTOU (§4.8): arguments changed between approval and dispatch.
                return (
                    EventType.DENY_APPROVAL_MISMATCH,
                    "arguments differ from the ones that were approved",
                )
            row.consumed = True
            await session.commit()
            return None

    async def expire_stale(self) -> None:
        """Startup re-check (§4.8 restart-durable): transition pending rows whose TTL
        lapsed while the gateway was down (or while nobody acted) and audit each."""
        async with self._sessions() as session:
            result = await session.execute(
                select(Approval).where(
                    Approval.status == "pending", Approval.expires_at < datetime.now(UTC)
                )
            )
            for row in result.scalars():
                row.status = "expired"
                await self._writer.write(
                    EventType.EXPIRED,
                    row.identity_id,
                    tool_name=row.tool_name,
                    payload_extra={"approval_id": row.approval_id},
                )
            await session.commit()

    async def _locked(self, session: AsyncSession, approval_id: str) -> Approval | None:
        # FOR UPDATE so two concurrent redeems of one id can't both pass the
        # consumed check — one-time use is a security guarantee, not best-effort.
        result = await session.execute(
            select(Approval).where(Approval.approval_id == approval_id).with_for_update()
        )
        return result.scalar_one_or_none()


def _expired(row: Approval) -> bool:
    return row.expires_at < datetime.now(UTC)
