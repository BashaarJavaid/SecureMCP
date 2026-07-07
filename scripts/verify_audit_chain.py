"""Walk and verify the audit hash chain (full-scan operator tool).

Recomputes H_t = SHA256(H_(t-1) || canonical_json(payload_t)) for every row in seq
order, checking both linkage (prev_hash) and content (curr_hash), plus each row's
ECDSA signature when the public key file exists (item 11). Exits 1 at the first
break. The scheduled incremental verifier is scripts/audit_verifier_daemon.py.

Usage: [DATABASE_URL=...] python scripts/verify_audit_chain.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select  # noqa: E402

from services.gateway import signing  # noqa: E402
from services.gateway.audit_log import GENESIS_HASH, compute_hash  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import AuditLog, async_session, engine  # noqa: E402


async def verify() -> int:
    public_key = None
    if Path(settings.signing_public_key_file).exists():
        public_key = signing.load_public_key(settings.signing_public_key_file)
    else:
        print(f"no public key at {settings.signing_public_key_file}; skipping signature checks")
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
            if public_key is not None and not signing.verify(
                public_key, row.signature, row.curr_hash
            ):
                print(f"BAD SIGNATURE at seq={row.seq}: curr_hash was not signed by the gateway")
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
