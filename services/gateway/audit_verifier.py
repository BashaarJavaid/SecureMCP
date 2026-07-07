"""Incremental audit-chain verifier (ARCHITECTURE.md §4.8, ROADMAP item 11).

Verifies forward from the last_verified_seq checkpoint instead of rescanning from
seq=1 — O(recent writes), which is what makes "run this every minute" credible. Each
row is checked three ways: chain linkage (prev_hash continues), chain math (recomputed
curr_hash matches), and the ECDSA signature over curr_hash (a regenerated chain is
self-consistent but unsignable without the gateway's private key).

On a break the checkpoint stops advancing at the last good row and never moves past
it — everything downstream of a confirmed break is untrusted regardless of whether it
individually re-verifies. Alerting is logger.error for now (structlog is item 13,
Prometheus counters are item 25). The daemon being down never blocks live traffic
(§5): it is a detective control, not a preventive one.
"""

import structlog
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from services.gateway import signing
from services.gateway.audit_log import GENESIS_HASH, compute_hash
from services.gateway.db import AuditLog, VerifierCheckpoint

logger = structlog.get_logger(__name__)

CHECKPOINT_ID = 1


async def verify_increment(
    sessionmaker: async_sessionmaker[AsyncSession],
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[int, str | None]:
    """One verification pass from the checkpoint forward. Returns (rows verified this
    pass, failure description or None). The checkpoint advances only through the last
    good row; a failing row is re-hit on every subsequent pass until resolved."""
    async with sessionmaker() as session:
        checkpoint = await session.get(VerifierCheckpoint, CHECKPOINT_ID)
        last_verified = checkpoint.last_verified_seq if checkpoint is not None else 0

        if last_verified == 0:
            prev_hash = GENESIS_HASH
        else:
            anchor = await session.get(AuditLog, last_verified)
            if anchor is None:
                return 0, f"checkpoint row seq={last_verified} is missing from audit_log"
            prev_hash = anchor.curr_hash

        verified = 0
        failure: str | None = None
        rows = await session.stream_scalars(
            select(AuditLog).where(AuditLog.seq > last_verified).order_by(AuditLog.seq)
        )
        async for row in rows:
            if row.prev_hash != prev_hash:
                failure = f"BROKEN LINK at seq={row.seq}: prev_hash does not continue the chain"
            elif compute_hash(prev_hash, row.payload) != row.curr_hash:
                failure = f"TAMPERED ROW at seq={row.seq}: payload does not match curr_hash"
            elif not signing.verify(public_key, row.signature, row.curr_hash):
                failure = f"BAD SIGNATURE at seq={row.seq}: curr_hash was not signed by the gateway"
            if failure is not None:
                logger.error("audit_chain_verification_failed", failure=failure, seq=row.seq)
                break
            prev_hash = row.curr_hash
            last_verified = row.seq
            verified += 1

        if verified:
            if checkpoint is None:
                session.add(
                    VerifierCheckpoint(id=CHECKPOINT_ID, last_verified_seq=last_verified)
                )
            else:
                checkpoint.last_verified_seq = last_verified
            await session.commit()
        return verified, failure
