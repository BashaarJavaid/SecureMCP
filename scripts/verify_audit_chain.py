"""Walk and verify the audit hash chain (basic verifier, ROADMAP Phase 1 item 5).

Recomputes H_t = SHA256(H_(t-1) || canonical_json(payload_t)) for every row in seq
order, checking both linkage (prev_hash) and content (curr_hash). Exits 1 at the first
break. ECDSA signature checks and the incremental last_verified_seq checkpoint daemon
are Phase 2 (item 11).

Usage: [DATABASE_URL=...] python scripts/verify_audit_chain.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select  # noqa: E402

from services.gateway.audit_log import GENESIS_HASH, compute_hash  # noqa: E402
from services.gateway.db import AuditLog, async_session, engine  # noqa: E402


async def verify() -> int:
    prev_hash = GENESIS_HASH
    count = 0
    async with async_session() as session:
        rows = await session.stream_scalars(select(AuditLog).order_by(AuditLog.seq))
        async for row in rows:
            if row.prev_hash != prev_hash:
                print(f"BROKEN LINK at seq={row.seq}: prev_hash does not continue the chain")
                return 1
            if compute_hash(prev_hash, row.payload) != row.curr_hash:
                print(f"TAMPERED ROW at seq={row.seq}: payload does not match curr_hash")
                return 1
            prev_hash = row.curr_hash
            count += 1
    print(f"chain OK ({count} rows)")
    return 0


async def main() -> int:
    try:
        return await verify()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
