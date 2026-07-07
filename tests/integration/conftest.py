import asyncio
import socket
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import redis.asyncio as aioredis
import uvicorn

from services.gateway.config import settings
from services.gateway.main import app

ECHO_SERVER = Path(__file__).parent / "fixtures" / "echo_server.py"


@pytest.fixture
async def gateway() -> AsyncIterator[str]:
    """The gateway app on an ephemeral port, upstream wired to the echo fixture server."""
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    try:
        await redis_client.ping()
    except Exception:
        pytest.skip("redis not reachable — run: docker compose up -d redis")
    finally:
        await redis_client.aclose()

    old_command = settings.upstream_command
    settings.upstream_command = f"{sys.executable} {ECHO_SERVER}"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.05)

    yield f"http://127.0.0.1:{port}"

    settings.upstream_command = old_command
    server.should_exit = True
    await task
