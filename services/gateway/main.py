"""FastAPI app entrypoint."""

import asyncio
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from services.gateway import auth
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.db import async_session
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyStore
from services.gateway.schema_cache import SchemaCache
from services.gateway.session_manager import SessionManager

logger = logging.getLogger(__name__)

KEY_HEADER = "x-securmcp-key"


async def _reload_policy(store: PolicyStore, writer: AuditWriter) -> None:
    old_version = store.engine.version
    if not store.reload():
        return  # last-known-good stays active; failure already logged
    try:
        await writer.write(
            EventType.POLICY_ACTIVATED,
            "operator",
            payload_extra={
                "old_version": old_version,
                "new_version": store.engine.version,
                "content_hash": store.engine.content_hash,
            },
        )
    except Exception:
        logger.exception("audit write failed for POLICY_ACTIVATED")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # An invalid or missing policy file must fail startup (ARCHITECTURE.md §5).
    store = PolicyStore(settings.policy_file)
    app.state.policy_store = store
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    writer = AuditWriter(redis_client, async_session, store)
    detector = DriftDetector(async_session, writer)
    app.state.drift_detector = detector
    manager = SessionManager(
        redis_client, store, writer, SchemaCache(redis_client), detector
    )
    app.state.session_manager = manager
    sweep = asyncio.create_task(manager.sweep_loop())
    # Policy hot-reload on SIGHUP (§8): docker kill -s HUP <gateway>.
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(
        signal.SIGHUP, lambda: loop.create_task(_reload_policy(store, writer))
    )
    try:
        yield
    finally:
        # SIGTERM lands here via uvicorn's graceful shutdown (ARCHITECTURE.md §4.8).
        with suppress(ValueError):
            loop.remove_signal_handler(signal.SIGHUP)
        sweep.cancel()
        await manager.shutdown_all()
        await redis_client.aclose()


app = FastAPI(title="SecurMCP Gateway", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/admin/tools/{server_id}/{tool_name}/approve")
async def approve_tool(server_id: str, tool_name: str, request: Request) -> dict[str, object]:
    """Drift re-approval (§4.8): snapshot the observed schema as the accepted baseline.
    Audited, authenticated admin action — requires a key resolving to an admin identity."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = auth.resolve_identity(request.headers.get(KEY_HEADER), store.engine)
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    detector: DriftDetector = request.app.state.drift_detector
    try:
        seq = await detector.approve(server_id, tool_name, approved_by=identity_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.APPROVED,
        reason=f"schema for {tool_name!r} on {server_id!r} re-approved by {identity_id!r}",
        matched_rules=["admin_approval"],
        policy_version=store.engine.version,
        audit_id=str(seq),
    )
    return decision.model_dump(mode="json")


async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    """Raw ASGI endpoint: routes each request to its session's Streamable HTTP transport."""
    manager: SessionManager = scope["app"].state.session_manager
    headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
    session_id = headers.get(MCP_SESSION_ID_HEADER)

    # Auth on every request, not just session creation (ARCHITECTURE.md §4.8).
    identity_id = auth.resolve_identity(
        headers.get(KEY_HEADER), scope["app"].state.policy_store.engine
    )
    if identity_id is None:
        await Response("invalid or missing API key", status_code=401)(scope, receive, send)
        return

    if session_id is not None:
        session = manager.get(session_id)
        if session is None:
            await Response("session not found", status_code=404)(scope, receive, send)
            return
        if session.interceptor.identity_id != identity_id:
            # A valid key for a different identity must not ride an existing session.
            await Response("key does not match session identity", status_code=401)(
                scope, receive, send
            )
            return
    elif scope["method"] == "POST":
        # A POST without a session header is a new session (the initialize request).
        # Any failure here — including the SESSION_START audit write — means no
        # session (§5: no record, no action).
        try:
            session = await manager.create(identity_id)
        except Exception:
            logger.exception("session creation failed")
            await Response("session could not be created", status_code=503)(
                scope, receive, send
            )
            return
    else:
        await Response("missing mcp-session-id header", status_code=400)(scope, receive, send)
        return

    await session.transport.handle_request(scope, receive, send)
    if scope["method"] == "DELETE":
        await manager.teardown(session.id)


app.mount("/mcp", mcp_endpoint)
