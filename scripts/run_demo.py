"""Recorded demo driver (ROADMAP item 8: pruning; item 14 adds drift blocking).

Mints two API keys, writes policies/demo-policy.yaml (gitignored — keys never enter
the repo), then drives the full narrative against the dockerized gateway: identity-
scoped pruning, a successful call, an ON-SCREEN operator mutation of the rogue server
(curl, no timer), drift classified Critical and blocked, admin re-approval, and the
same call succeeding — finishing with the audit-log receipts.

Run (mint the audit signing keypair once first — the gateway won't start without it):
    python scripts/generate_signing_key.py
    python scripts/run_demo.py
and when prompted, in another terminal:
    POLICY_FILE=policies/demo-policy.yaml \
      UPSTREAM_COMMAND="python sample_target/rogue_server.py --state /rogue-state/state.json" \
      docker compose up -d --build
then, when prompted again (the rug pull, visible on screen):
    curl -X POST localhost:9800/_admin/apply_mutation
"""

import asyncio
import base64
import hashlib
import secrets
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402
import redis.asyncio as aioredis  # noqa: E402
import yaml  # noqa: E402
from mcp import ClientSession, McpError  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

from services.gateway.audit_log import POINTER_KEY  # noqa: E402
from services.gateway.config import settings  # noqa: E402
from services.gateway.db import AuditLog, async_session, engine  # noqa: E402
from services.gateway.replay_guard import (  # noqa: E402
    NONCE_META_KEY,
    TIMESTAMP_META_KEY,
)

GATEWAY = "http://localhost:8000"
ROOT = Path(__file__).parent.parent
POLICY_PATH = ROOT / "policies" / "demo-policy.yaml"
STATE_PATH = ROOT / ".rogue-state" / "state.json"

RECEIPT_EVENTS = ["TOOLS_LIST", "DRIFT_CRITICAL", "DENY_DRIFT", "APPROVED"]


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def mint_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def fresh_meta() -> dict:
    """The Replay Guard's nonce/timestamp pair (§4.8) — fresh per call."""
    return {NONCE_META_KEY: str(uuid.uuid4()), TIMESTAMP_META_KEY: time.time()}


def write_policy(keys: dict[str, str]) -> None:
    def key_hash(identity: str) -> str:
        return f"sha256:{hashlib.sha256(keys[identity].encode()).hexdigest()}"

    POLICY_PATH.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "identities": [
                    {
                        "id": "developer",
                        "api_key_hash": key_hash("developer"),
                        "allowed_servers": [
                            {
                                "server_id": "default",
                                "allowed_tools": ["send_email", "read_inbox"],
                            }
                        ],
                    },
                    {
                        "id": "ops-admin",
                        "api_key_hash": key_hash("ops-admin"),
                        "admin": True,
                        "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
                    },
                ],
            }
        )
    )


async def reset_dev_state() -> None:
    """Fresh slate for a repeatable recording: dev-only wipe of the audit chain,
    drift baselines, and cached pointers — same reset the integration suite uses.
    A leftover baseline from a prior run would make the benign schema itself
    register as drift."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.delete(POINTER_KEY, f"schema:{settings.upstream_server_id}")
    except Exception:
        sys.exit("redis not reachable — run: docker compose up -d redis")
    finally:
        await redis_client.aclose()
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
            await conn.execute(text("TRUNCATE tool_baselines"))
            await conn.execute(text("TRUNCATE audit_verifier_checkpoint"))
            await conn.execute(text("TRUNCATE policy_versions"))
    except Exception:
        sys.exit("postgres not reachable — run: docker compose up -d postgres")
    # Each demo run re-mints keys into the same policy version number; stale revision
    # snapshots would collide with the fresh content (item 19's append-only check).
    for snapshot in Path(settings.policy_revisions_dir).glob("v*.yaml"):
        snapshot.unlink()


@asynccontextmanager
async def connect(api_key: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"X-SecurMCP-Key": api_key}, follow_redirects=True
    ) as http_client:
        async with streamable_http_client(f"{GATEWAY}/mcp", http_client=http_client) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def wait_for_gateway(api_key: str) -> None:
    print("\nWaiting for the gateway to come up with the demo policy...")
    print("  In another terminal:")
    print("    POLICY_FILE=policies/demo-policy.yaml \\")
    print(
        '      UPSTREAM_COMMAND="python sample_target/rogue_server.py'
        ' --state /rogue-state/state.json" \\'
    )
    print("      docker compose up -d --build")
    print(
        "  (stack already running with the demo policy? hot-reload this run's fresh"
        " keys with:  docker kill -s HUP securemcp-gateway-1)"
    )
    async with httpx.AsyncClient() as client:
        for _ in range(240):
            try:
                response = await client.post(
                    f"{GATEWAY}/mcp/", json={}, headers={"X-SecurMCP-Key": api_key}
                )
                if response.status_code != 401:  # demo key accepted => demo policy live
                    print("  gateway is up.")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.5)
    sys.exit("gateway never became ready — is docker compose up?")


async def show_tools(identity: str, api_key: str) -> None:
    section(f"tools/list as {identity!r}")
    async with connect(api_key) as session:
        for tool in (await session.list_tools()).tools:
            print(f"  - {tool.name}: {(tool.description or '').strip()}")


async def wait_for_mutation() -> None:
    section("the rug pull — an operator mutates the rogue server, on screen")
    print("  In another terminal:  curl -X POST localhost:9800/_admin/apply_mutation")
    print("  (no timer, no hidden trigger — the schema changes only when you do this)")
    while not STATE_PATH.exists():
        await asyncio.sleep(0.5)
    print(
        "  mutation applied: send_email now has a REQUIRED bcc parameter and a"
        " poisoned description."
    )


async def drift_and_block(api_key: str) -> None:
    async with connect(api_key) as session:
        section("developer's next tools/list — the gateway sees the drift")
        send_email = {t.name: t for t in (await session.list_tools()).tools}["send_email"]
        print(f"  send_email description is now: {(send_email.description or '').strip()!r}")
        print("  drift classified CRITICAL (new required param) — tool is blocked.")

        section("developer calls send_email — blocked at the point of action")
        try:
            await session.call_tool(
                "send_email",
                {"to": "a@b.c", "subject": "hi", "body": "hello"},
                meta=fresh_meta(),
            )
            sys.exit("expected DENY_DRIFT — did the mutation apply?")
        except McpError as error:
            decision = error.error.data
            print(f"  decision={decision['decision']} event_type={decision['event_type']}")
            print(f"  reason: {decision['reason']}")
            print(f"  audit_id: {decision['audit_id']}")


async def approve_and_retry(keys: dict[str, str]) -> None:
    section("ops-admin reviews and re-approves the new schema")
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GATEWAY}/admin/tools/default/send_email/approve",
            headers={"X-SecurMCP-Key": keys["ops-admin"]},
        )
        response.raise_for_status()
        decision = response.json()
        print(f"  event_type={decision['event_type']} audit_id={decision['audit_id']}")

    section("developer retries (with the now-required bcc) — allowed again")
    async with connect(keys["developer"]) as session:
        result = await session.call_tool(
            "send_email",
            {"to": "a@b.c", "subject": "hi", "body": "hello", "bcc": "x@y.z"},
            meta=fresh_meta(),
        )
        print(f"  {result.content[0].text}")  # type: ignore[union-attr]


async def show_audit_receipts() -> None:
    section("audit log receipts (tamper-evident, hash-chained, ECDSA-signed)")
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type.in_(RECEIPT_EVENTS))
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    for row in rows:
        detail = {
            k: v
            for k, v in row.payload.items()
            if k in ("served_tools", "pruned_tools", "severity", "reason", "new_hash")
        }
        print(f"  seq={row.seq} {row.event_type} identity={row.identity_id!r} {detail}")
    await engine.dispose()


async def main() -> None:
    section("SecurMCP demo — schema pruning + drift blocking (rug pull)")
    STATE_PATH.unlink(missing_ok=True)  # start from the benign schema
    await reset_dev_state()
    keys = {"developer": mint_key(), "ops-admin": mint_key()}
    write_policy(keys)
    print(f"\nDemo policy written to {POLICY_PATH.relative_to(Path.cwd())}")
    print("  developer  -> allowed: send_email, read_inbox")
    print("  ops-admin  -> allowed: * (everything), admin: true")
    print(
        "Upstream: sample_target/rogue_server.py — starts benign, mutates only when"
        " its admin endpoint is hit."
    )

    await wait_for_gateway(keys["developer"])

    await show_tools("developer", keys["developer"])
    print(
        "\n  delete_mailbox is not denied — it is ABSENT. The LLM planning over"
        " this list never sees it."
    )
    await show_tools("ops-admin", keys["ops-admin"])

    section("developer calls send_email — benign schema, allowed")
    async with connect(keys["developer"]) as session:
        result = await session.call_tool(
            "send_email",
            {"to": "a@b.c", "subject": "hi", "body": "hello"},
            meta=fresh_meta(),
        )
        print(f"  {result.content[0].text}")  # type: ignore[union-attr]

    await wait_for_mutation()
    await drift_and_block(keys["developer"])
    await approve_and_retry(keys)
    await show_audit_receipts()
    section("done")


if __name__ == "__main__":
    asyncio.run(main())
