"""FastAPI app entrypoint."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from services.gateway import policy_engine
from services.gateway.config import settings
from services.gateway.session_manager import SessionManager

# Temporary, unverified identity header — replaced by X-SecurMCP-Key auth in item 4.
IDENTITY_HEADER = "x-securmcp-identity"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # An invalid or missing policy file must fail startup (ARCHITECTURE.md §5).
    policy = policy_engine.load(settings.policy_file)
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    manager = SessionManager(redis_client, policy)
    app.state.session_manager = manager
    sweep = asyncio.create_task(manager.sweep_loop())
    try:
        yield
    finally:
        # SIGTERM lands here via uvicorn's graceful shutdown (ARCHITECTURE.md §4.8).
        sweep.cancel()
        await manager.shutdown_all()
        await redis_client.aclose()


app = FastAPI(title="SecurMCP Gateway", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    """Raw ASGI endpoint: routes each request to its session's Streamable HTTP transport."""
    manager: SessionManager = scope["app"].state.session_manager
    headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
    session_id = headers.get(MCP_SESSION_ID_HEADER)

    if session_id is not None:
        session = manager.get(session_id)
        if session is None:
            await Response("session not found", status_code=404)(scope, receive, send)
            return
    elif scope["method"] == "POST":
        # A POST without a session header is a new session (the initialize request).
        try:
            session = await manager.create(headers.get(IDENTITY_HEADER))
        except RuntimeError as exc:
            await Response(str(exc), status_code=503)(scope, receive, send)
            return
    else:
        await Response("missing mcp-session-id header", status_code=400)(scope, receive, send)
        return

    await session.transport.handle_request(scope, receive, send)
    if scope["method"] == "DELETE":
        await manager.teardown(session.id)


app.mount("/mcp", mcp_endpoint)
