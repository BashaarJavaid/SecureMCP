"""Audit verifier daemon (ARCHITECTURE.md §4.8, ROADMAP item 11): incremental
chain + signature verification on a schedule, resuming from last_verified_seq.

Runs as a sidecar container (see docker-compose.yml) or under cron with a single
pass via --once. Needs only the PUBLIC key — the private key stays with the gateway.

Usage:
    [DATABASE_URL=...] [VERIFY_INTERVAL_SECONDS=60] python scripts/audit_verifier_daemon.py [--once]
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.gateway import signing  # noqa: E402
from services.gateway.audit_verifier import verify_increment  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import async_session, engine  # noqa: E402

logger = logging.getLogger("audit_verifier_daemon")


async def main() -> int:
    public_key = signing.load_public_key(settings.signing_public_key_file)
    interval = int(os.environ.get("VERIFY_INTERVAL_SECONDS", "60"))
    once = "--once" in sys.argv
    try:
        while True:
            verified, failure = await verify_increment(async_session, public_key)
            # Heartbeat: a silent daemon is indistinguishable from a dead one (§5 table).
            logger.info("pass complete: %d row(s) verified, failure=%s", verified, failure)
            if once:
                return 1 if failure is not None else 0
            await asyncio.sleep(interval)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    sys.exit(asyncio.run(main()))
