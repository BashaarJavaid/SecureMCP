import asyncio
import hashlib
import secrets
import socket
import sys
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import redis.asyncio as aioredis
import uvicorn
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import ClientSession
from mcp.shared.session import ProgressFnT
from mcp.types import CallToolResult
from sqlalchemy import text

from services.gateway.audit_log import POINTER_KEY
from services.gateway.config import settings
from services.gateway.db import Base, engine
from services.gateway.main import app
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"


class ReplayCompliantSession(ClientSession):
    """ClientSession whose call_tool carries the Replay Guard's nonce/timestamp pair
    (fresh per call) unless the test supplies its own via `meta=`."""

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
        progress_callback: ProgressFnT | None = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        meta = {
            NONCE_META_KEY: str(uuid.uuid4()),
            TIMESTAMP_META_KEY: time.time(),
            **(meta or {}),
        }
        return await super().call_tool(
            name, arguments, read_timeout_seconds, progress_callback, meta=meta
        )


@pytest.fixture
async def clean_audit() -> None:
    """Skip unless postgres + redis are reachable; start each test from an empty,
    consistent chain (empty audit_log AND no stale latest_audit_hash pointer)."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.ping()
        await redis_client.delete(POINTER_KEY, f"schema:{settings.upstream_server_id}")
    except Exception:
        pytest.skip("redis not reachable — run: docker compose up -d redis")
    finally:
        await redis_client.aclose()
    # Each test runs in a fresh event loop; drop connections pooled under the old one.
    await engine.dispose()
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("TRUNCATE audit_log RESTART IDENTITY"))
            await conn.execute(text("TRUNCATE tool_baselines"))
            await conn.execute(text("TRUNCATE audit_verifier_checkpoint"))
    except Exception:
        pytest.skip("postgres not reachable — run: docker compose up -d postgres")


@dataclass
class Gateway:
    url: str
    keys: dict[str, str]  # identity id -> raw API key
    policy_path: Path


def _key_hash(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


def policy_dict(
    keys: dict[str, str], readonly_tools: list[str] | None = None, version: int = 1
) -> dict:
    return {
        "version": version,
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": _key_hash(keys["agent-readonly"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": readonly_tools or ["echo"]}
                ],
            },
            {
                "id": "agent-full",
                "api_key_hash": _key_hash(keys["agent-full"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }


def write_signing_keypair(directory: Path) -> tuple[Path, Path]:
    """Per-run audit signing keypair — never a checked-in key (§4.8)."""
    key = ec.generate_private_key(ec.SECP256R1())
    private_path = directory / "audit_signing_key.pem"
    public_path = directory / "audit_signing_key.pub.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private_path, public_path


@asynccontextmanager
async def running_gateway(
    policy_path: Path, upstream_command: str, keys: dict[str, str]
) -> AsyncIterator[Gateway]:
    """The gateway app on an ephemeral port with the given policy file and upstream."""
    old_policy_file = settings.policy_file
    old_command = settings.upstream_command
    old_signing_key = settings.signing_key_file
    old_signing_pub = settings.signing_public_key_file
    settings.policy_file = str(policy_path)
    settings.upstream_command = upstream_command
    private_path, public_path = write_signing_keypair(policy_path.parent)
    settings.signing_key_file = str(private_path)
    settings.signing_public_key_file = str(public_path)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)

    try:
        yield Gateway(url=f"http://127.0.0.1:{port}", keys=keys, policy_path=policy_path)
    finally:
        settings.policy_file = old_policy_file
        settings.upstream_command = old_command
        settings.signing_key_file = old_signing_key
        settings.signing_public_key_file = old_signing_pub
        server.should_exit = True
        await task


@pytest.fixture
async def gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    """Echo fixture upstream, with a policy file generated at runtime so no
    real-looking API keys ever land in the repo."""
    keys = {
        "agent-readonly": secrets.token_urlsafe(32),
        "agent-full": secrets.token_urlsafe(32),
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy_dict(keys)))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw
