"""First recorded demo (ROADMAP Phase 1, item 8): schema pruning only.

Mints two API keys, writes policies/demo-policy.yaml (gitignored — keys never enter
the repo), then connects to the dockerized gateway as each identity and shows what
each one sees, finishing with the audit-log receipts.

Run:
    python scripts/run_demo.py
and when prompted, in another terminal:
    POLICY_FILE=policies/demo-policy.yaml docker compose up -d --build
"""

import asyncio
import base64
import hashlib
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx  # noqa: E402
import yaml  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402
from sqlalchemy import select  # noqa: E402

from services.gateway.db import AuditLog, async_session, engine  # noqa: E402

GATEWAY = "http://localhost:8000"
POLICY_PATH = Path(__file__).parent.parent / "policies" / "demo-policy.yaml"


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def mint_key() -> tuple[str, str]:
    key = base64.b64encode(secrets.token_bytes(32)).decode()
    return key, f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def write_policy(keys: dict[str, str]) -> None:
    dev_key_hash = f"sha256:{hashlib.sha256(keys['developer'].encode()).hexdigest()}"
    admin_key_hash = f"sha256:{hashlib.sha256(keys['ops-admin'].encode()).hexdigest()}"
    POLICY_PATH.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "identities": [
                    {
                        "id": "developer",
                        "api_key_hash": dev_key_hash,
                        "allowed_servers": [
                            {
                                "server_id": "default",
                                "allowed_tools": ["read_file", "list_issues"],
                            }
                        ],
                    },
                    {
                        "id": "ops-admin",
                        "api_key_hash": admin_key_hash,
                        "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
                    },
                ],
            }
        )
    )


async def wait_for_gateway(api_key: str) -> None:
    print("\nWaiting for the gateway to come up with the demo policy...")
    print("  In another terminal:  POLICY_FILE=policies/demo-policy.yaml"
          " docker compose up -d --build")
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
                result = await session.list_tools()
                for tool in result.tools:
                    print(f"  - {tool.name}: {(tool.description or '').strip()}")


async def show_audit_receipts() -> None:
    section("audit log receipts (tamper-evident, hash-chained)")
    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type == "TOOLS_LIST")
                    .order_by(AuditLog.seq.desc())
                    .limit(2)
                )
            )
            .scalars()
            .all()
        )
    for row in reversed(rows):
        print(
            f"  seq={row.seq} identity={row.identity_id!r}"
            f" served={row.payload['served_tools']} pruned={row.payload['pruned_tools']}"
        )
    await engine.dispose()


async def main() -> None:
    section("SecurMCP demo — identity-scoped tools/list (schema pruning)")
    keys = {"developer": mint_key()[0], "ops-admin": mint_key()[0]}
    write_policy(keys)
    print(f"\nDemo policy written to {POLICY_PATH.relative_to(Path.cwd())}")
    print("  developer  -> allowed: read_file, list_issues")
    print("  ops-admin  -> allowed: * (everything)")
    print("Upstream: sample_target/overscoped_server.py — exposes read_file,"
          " list_issues, delete_repo, merge_pr to ANYONE. No authz of its own.")

    await wait_for_gateway(keys["developer"])
    await show_tools("developer", keys["developer"])
    print("\n  delete_repo and merge_pr are not denied — they are ABSENT.")
    print("  The LLM planning over this list never sees them as an option.")
    await show_tools("ops-admin", keys["ops-admin"])
    await show_audit_receipts()
    section("done")


if __name__ == "__main__":
    asyncio.run(main())
