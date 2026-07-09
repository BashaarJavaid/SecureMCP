"""FastAPI app entrypoint."""

import asyncio
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, HTTPException, Request
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from services.gateway import auth, logging_config, policy_engine, policy_versions, signing
from services.gateway.approvals import ApprovalStore
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.db import async_session
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyStore
from services.gateway.replay_guard import ReplayGuard
from services.gateway.risk_engine import RiskEngine
from services.gateway.schema_cache import SchemaCache
from services.gateway.session_manager import SessionManager

logging_config.configure()
logger = structlog.get_logger(__name__)

KEY_HEADER = "x-securmcp-key"


async def _reload_policy(store: PolicyStore, writer: AuditWriter) -> None:
    old_version = store.engine.version
    candidate = store.load_candidate()
    if candidate is None:
        return  # last-known-good stays active; failure already logged
    try:
        # Record before swap (item 19): a rejected or unrecordable activation keeps
        # last-known-good (§5 fail-closed).
        await policy_versions.record_activation(candidate, "operator", async_session)
    except Exception:
        logger.exception("policy_activation_rejected_keeping_last_known_good")
        return
    store.swap(candidate)
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
        logger.exception("audit_write_failed", event_type="POLICY_ACTIVATED")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # An invalid or missing policy file must fail startup (ARCHITECTURE.md §5);
    # so must a missing/unreadable audit signing key (§4.8, item 11).
    store = PolicyStore(settings.policy_file)
    app.state.policy_store = store
    signing_key = signing.load_private_key(settings.signing_key_file)
    redis_client: aioredis.Redis = aioredis.Redis.from_url(settings.redis_url)
    app.state.redis = redis_client  # auth-failure counter (§4.8, item 18)
    writer = AuditWriter(redis_client, async_session, store, signing_key)
    app.state.audit_writer = writer  # rollback endpoint (item 19)
    # Record + audit the boot-time activation (item 19). A monotonicity conflict
    # (e.g. same version, different content) fails startup; the snapshot/row are
    # idempotent on a re-seen version but the audit row is unconditional, so every
    # boot's active policy — including one reverting a rollback — is in the chain.
    await policy_versions.record_activation(store.engine, "startup", async_session)
    await writer.write(
        EventType.POLICY_ACTIVATED,
        "startup",
        payload_extra={
            "old_version": None,
            "new_version": store.engine.version,
            "content_hash": store.engine.content_hash,
        },
    )
    detector = DriftDetector(async_session, writer)
    app.state.drift_detector = detector
    risk_engine = RiskEngine(redis_client, detector)
    app.state.risk_engine = risk_engine
    approval_store = ApprovalStore(async_session, writer)
    app.state.approval_store = approval_store
    # Restart-durable approvals (§4.8): expire pending rows whose TTL lapsed while
    # the gateway was down before serving traffic.
    await approval_store.expire_stale()
    manager = SessionManager(
        redis_client,
        store,
        writer,
        SchemaCache(redis_client),
        detector,
        ReplayGuard(redis_client, settings.replay_window_seconds),
        risk_engine,
        approval_store,
    )
    app.state.session_manager = manager
    sweep = asyncio.create_task(manager.sweep_loop())
    # Policy hot-reload on SIGHUP (§8): docker kill -s HUP <gateway>.
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGHUP, lambda: loop.create_task(_reload_policy(store, writer)))
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
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
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


@app.post("/admin/approvals/{approval_id}/approve")
async def approve_call(approval_id: str, request: Request) -> dict[str, object]:
    """Human approval grant (§4.8, item 16): flips a pending approval to approved so
    the client's retry (params._meta["securmcp/approval_id"]) can redeem it once.
    Also applies one risk-decay step for the (identity, tool) pair — a human judged
    this high-risk call fine, and that calibrates future behavioral scoring."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    approval_store: ApprovalStore = request.app.state.approval_store
    try:
        seq, requester_id, tool_name = await approval_store.approve(
            approval_id, approved_by=identity_id
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    risk_engine: RiskEngine = request.app.state.risk_engine
    await risk_engine.apply_decay(requester_id, tool_name)
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.APPROVED,
        reason=f"call to {tool_name!r} approved by {identity_id!r}",
        matched_rules=["admin_approval"],
        policy_version=store.engine.version,
        audit_id=str(seq),
        approval_id=approval_id,
    )
    return decision.model_dump(mode="json")


@app.post("/admin/policy/rollback/{version}")
async def rollback_policy(version: int, request: Request) -> dict[str, object]:
    """Re-activate a prior policy revision (§4.8, item 19): loads the append-only
    snapshot, verifies it against the recorded content_hash, swaps the in-memory
    PolicyStore, and refreshes the policy_versions row. In-memory only — POLICY_FILE
    on disk is mounted read-only and keeps the newer version until the operator
    updates it; a restart re-activates whatever is on disk (audited)."""
    store: PolicyStore = request.app.state.policy_store
    identity_id = await auth.resolve_identity_tracked(
        request.headers.get(KEY_HEADER), store.engine, request.app.state.redis
    )
    if identity_id is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    if not store.engine.is_admin(identity_id):
        raise HTTPException(status_code=403, detail="admin identity required")
    snapshot = policy_versions.snapshot_path(version)
    if not snapshot.exists():
        raise HTTPException(status_code=404, detail=f"no revision snapshot for v{version}")
    try:
        engine = policy_engine.load_bytes(snapshot.read_bytes())
    except Exception as exc:
        raise HTTPException(status_code=409, detail=f"revision v{version} is invalid") from exc
    try:
        await policy_versions.record_rollback(engine, identity_id, async_session)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except policy_versions.ActivationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    old_version = store.engine.version
    writer: AuditWriter = request.app.state.audit_writer
    seq = await writer.write(
        EventType.POLICY_ACTIVATED,
        identity_id,
        payload_extra={
            "old_version": old_version,
            "new_version": engine.version,
            "content_hash": engine.content_hash,
            "rollback": True,
        },
    )
    store.swap(engine)
    logger.warning(
        "policy_rolled_back_in_memory_only",
        old_version=old_version,
        new_version=engine.version,
        hint="POLICY_FILE on disk still holds the newer version; update it or a restart reverts",
    )
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        event_type=EventType.POLICY_ACTIVATED,
        reason=f"policy rolled back from v{old_version} to v{engine.version} by {identity_id!r}",
        matched_rules=["admin_rollback"],
        policy_version=engine.version,
        audit_id=str(seq),
    )
    return decision.model_dump(mode="json")


async def mcp_endpoint(scope: Scope, receive: Receive, send: Send) -> None:
    """Raw ASGI endpoint: routes each request to its session's Streamable HTTP transport."""
    manager: SessionManager = scope["app"].state.session_manager
    headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
    session_id = headers.get(MCP_SESSION_ID_HEADER)

    # Auth on every request, not just session creation (ARCHITECTURE.md §4.8).
    identity_id = await auth.resolve_identity_tracked(
        headers.get(KEY_HEADER),
        scope["app"].state.policy_store.engine,
        scope["app"].state.redis,
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
            logger.exception("session_creation_failed", identity=identity_id)
            await Response("session could not be created", status_code=503)(scope, receive, send)
            return
    else:
        await Response("missing mcp-session-id header", status_code=400)(scope, receive, send)
        return

    await session.transport.handle_request(scope, receive, send)
    if scope["method"] == "DELETE":
        await manager.teardown(session.id)


app.mount("/mcp", mcp_endpoint)
