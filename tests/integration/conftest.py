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
from pathlib import Path
from typing import Any

import pytest
import redis.asyncio as aioredis
import uvicorn
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from mcp import ClientSession
from mcp.types import NotificationParams, PaginatedRequestParams, RequestParams
from sqlalchemy import text

from services.gateway import auth
from services.gateway.audit_log import POINTER_KEY
from services.gateway.config import settings
from services.gateway.db import Base, engine
from services.gateway.main import app
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY

ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"

SIGNED_SECRET_ENV = "SECURMCP_TEST_SIGNING_SECRET"


class SignedSession(ClientSession):
    """ClientSession for a `signed` identity (item 34): every outgoing request AND
    notification carries key id, nonce/timestamp, and an HMAC over the canonical
    tuple in params._meta — the wire format a custom signing client implements.
    (Client→server *responses* — server-initiated sampling — are not signed; the
    echo/rogue upstreams never send them.)"""

    def __init__(self, *args: Any, key_id: str, secret: bytes, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._key_id = key_id
        self._secret = secret

    def _sign(self, root: Any) -> None:
        nonce, timestamp = str(uuid.uuid4()), int(time.time())
        params = root.params
        if root.method == "tools/call":
            tool, arguments = params.name, params.arguments
        else:
            tool, arguments = None, None
        signature = auth.sign_request(self._secret, nonce, timestamp, root.method, tool, arguments)
        meta = {
            NONCE_META_KEY: nonce,
            TIMESTAMP_META_KEY: timestamp,
            auth.KEY_ID_META_KEY: self._key_id,
            auth.SIGNATURE_META_KEY: signature,
        }
        if params is None:
            cls = (
                NotificationParams
                if root.method.startswith("notifications/")
                else PaginatedRequestParams
            )
            root.params = cls.model_validate({"_meta": meta})
        else:
            params.meta = RequestParams.Meta.model_validate(meta)

    async def send_request(self, request: Any, result_type: Any, **kwargs: Any) -> Any:
        self._sign(request.root)
        return await super().send_request(request, result_type, **kwargs)

    async def send_notification(self, notification: Any, **kwargs: Any) -> None:
        self._sign(notification.root)
        await super().send_notification(notification, **kwargs)


@pytest.fixture
async def clean_audit() -> None:
    """Skip unless postgres + redis are reachable; start each test from an empty,
    consistent chain (empty audit_log AND no stale latest_audit_hash pointer)."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.ping()
        await redis_client.delete(POINTER_KEY)
        # Any server's cached schema (item 35: the multi-server test registers
        # non-default ids), plus the risk counters and step-up challenge state.
        for pattern in ("schema:*", "risk:*", "challenge:*"):
            keys = await redis_client.keys(pattern)
            if keys:
                await redis_client.delete(*keys)
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
            await conn.execute(text("TRUNCATE approvals"))
            await conn.execute(text("TRUNCATE policy_versions"))
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
        "servers": {"default": f"{sys.executable} {ECHO_SERVER}"},
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
    """The gateway app on an ephemeral port with the given policy file and upstream.
    A policy without a `servers:` block (the single-server fixtures) gets the given
    command registered as "default" — item 35's registry, transparently."""
    policy = yaml.safe_load(policy_path.read_text())
    if "servers" not in policy:
        policy["servers"] = {"default": upstream_command}
        policy_path.write_text(yaml.safe_dump(policy))
    old_policy_file = settings.policy_file
    old_signing_key = settings.signing_key_file
    old_signing_pub = settings.signing_public_key_file
    old_revisions_dir = settings.policy_revisions_dir
    settings.policy_file = str(policy_path)
    settings.policy_revisions_dir = str(policy_path.parent / "revisions")
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
        settings.signing_key_file = old_signing_key
        settings.signing_public_key_file = old_signing_pub
        settings.policy_revisions_dir = old_revisions_dir
        server.should_exit = True
        await task


@pytest.fixture
async def gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    """Echo fixture upstream, with a policy file generated at runtime so no
    real-looking API keys ever land in the repo. Identities are plain `bearer` —
    every test on this fixture doubles as proof that a stock MCP client works."""
    keys = {
        "agent-readonly": secrets.token_urlsafe(32),
        "agent-full": secrets.token_urlsafe(32),
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy_dict(keys)))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


@dataclass
class SignedGateway:
    url: str
    key_id: str
    secret: bytes
    policy_path: Path


@pytest.fixture
async def signed_gateway(
    clean_audit: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[SignedGateway]:
    """Echo fixture upstream behind a single `signed` identity (item 34): the secret
    lives only in an env var; the policy YAML carries the key id + the var's name."""
    key_id = f"kid_{secrets.token_hex(8)}"
    secret = secrets.token_urlsafe(32)
    monkeypatch.setenv(SIGNED_SECRET_ENV, secret)
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "ci-agent",
                "auth_mode": "signed",
                "key_id": key_id,
                "signing_secret_env": SIGNED_SECRET_ENV,
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", {}) as gw:
        yield SignedGateway(
            url=gw.url, key_id=key_id, secret=secret.encode(), policy_path=policy_path
        )
