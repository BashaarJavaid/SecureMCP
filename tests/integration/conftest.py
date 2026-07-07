import asyncio
import hashlib
import secrets
import socket
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import redis.asyncio as aioredis
import uvicorn
import yaml

from services.gateway.config import settings
from services.gateway.main import app

ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"


@dataclass
class Gateway:
    url: str
    keys: dict[str, str]  # identity id -> raw API key


def _key_hash(key: str) -> str:
    return f"sha256:{hashlib.sha256(key.encode()).hexdigest()}"


@pytest.fixture
async def gateway(tmp_path: Path) -> AsyncIterator[Gateway]:
    """The gateway app on an ephemeral port: echo fixture upstream, and a policy file
    generated at runtime so no real-looking API keys ever land in the repo."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.ping()
    except Exception:
        pytest.skip("redis not reachable — run: docker compose up -d redis")
    finally:
        await redis_client.aclose()

    keys = {
        "agent-readonly": secrets.token_urlsafe(32),
        "agent-full": secrets.token_urlsafe(32),
    }
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": _key_hash(keys["agent-readonly"]),
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            },
            {
                "id": "agent-full",
                "api_key_hash": _key_hash(keys["agent-full"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))

    old_policy_file = settings.policy_file
    old_command = settings.upstream_command
    settings.policy_file = str(policy_path)
    settings.upstream_command = f"{sys.executable} {ECHO_SERVER}"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)

    yield Gateway(url=f"http://127.0.0.1:{port}", keys=keys)

    settings.policy_file = old_policy_file
    settings.upstream_command = old_command
    server.should_exit = True
    await task
