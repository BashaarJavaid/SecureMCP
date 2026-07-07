"""JSON-RPC method dispatch (ARCHITECTURE.md §4.8).

Per-session interceptor. Client→upstream messages are routed by method; upstream→client
responses are matched back to their request id (pruning happens on the tools/list
*response*). A method without an explicit handler is passed through unmodified but still
logged — deny-by-default is deliberately not enforced here; visibility in the log is the
day-one guarantee.

tools/call is authorized here regardless of what the pruned tools/list showed: pruning
shapes the LLM's planning surface, authorization happens fresh at the point of action
(§4.1 design principle). Every decision point is audit-logged before it takes effect —
an ALLOW that can't be recorded is a deny (§5, "no record, no action").

Schemas come from the shared per-server cache (§8): populated whenever a tools/list
response flows through, invalidated on initialize, and transparently re-fetched from
the upstream on a miss (TTL expiry or a client that calls without listing).
"""

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import structlog
from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    RequestId,
)

from services.gateway import param_validator, schema_pruner
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.drift_detector import DriftDetector
from services.gateway.policy_engine import PolicyEngine, PolicyStore
from services.gateway.replay_guard import NONCE_META_KEY, TIMESTAMP_META_KEY, ReplayGuard
from services.gateway.schema_cache import SchemaCache

# Implementation-defined JSON-RPC error codes; the canonical Decision object (§4.3)
# travels in error.data for policy denials.
POLICY_DENIED_CODE = -32003
AUDIT_UNAVAILABLE_CODE = -32004

_HANDLED_METHODS = frozenset({"initialize", "tools/list", "tools/call"})
_REFETCH_TIMEOUT_S = 10


@dataclass
class Forward:
    """Send this message on to the upstream server."""

    message: SessionMessage


@dataclass
class Respond:
    """Answer the client directly; nothing reaches the upstream server."""

    message: SessionMessage


def _error(request_id: RequestId, code: int, message: str, data: object = None) -> Respond:
    return Respond(
        SessionMessage(
            JSONRPCMessage(
                JSONRPCError(
                    jsonrpc="2.0",
                    id=request_id,
                    error=ErrorData(code=code, message=message, data=data),
                )
            )
        )
    )


@dataclass
class Interceptor:
    identity_id: str
    session_id: str
    store: PolicyStore
    writer: AuditWriter
    cache: SchemaCache
    detector: DriftDetector
    replay: ReplayGuard
    send_upstream: Callable[[JSONRPCMessage], Awaitable[None]]
    _pending: dict[RequestId, str] = field(default_factory=dict)  # request id -> method
    # Gateway-initiated upstream requests (transparent tools/list re-fetch): responses
    # to these ids resolve a future and are never forwarded to the client.
    _internal: dict[str, "asyncio.Future[dict[str, Any]]"] = field(default_factory=dict)
    _log: structlog.stdlib.BoundLogger = field(init=False)

    def __post_init__(self) -> None:
        # §7: correlation id = session id. Bound here because interceptor calls run in
        # the per-session pump task, out of reach of request-scoped contextvars.
        self._log = structlog.get_logger(__name__).bind(
            session_id=self.session_id, identity=self.identity_id
        )

    @property
    def engine(self) -> PolicyEngine:
        # Read through the store on every use so a SIGHUP reload takes effect on the
        # very next request of an in-flight session (§8).
        return self.store.engine

    async def on_client_message(self, message: SessionMessage) -> Forward | Respond:
        root = message.message.root
        if not isinstance(root, JSONRPCRequest):
            method = getattr(root, "method", None)
            if method is not None and method not in _HANDLED_METHODS:
                self._log.info("passthrough_no_handler", method=method)
            return Forward(message)
        self._pending[root.id] = root.method
        if root.method == "initialize":
            # A fresh handshake is the trust boundary to re-verify against (§8).
            await self.cache.invalidate(settings.upstream_server_id)
        elif root.method == "tools/call":
            return await self._authorize_call(message, root)
        elif root.method not in _HANDLED_METHODS:
            self._log.info("passthrough_no_handler", method=root.method)
        return Forward(message)

    async def _authorize_call(
        self, message: SessionMessage, request: JSONRPCRequest
    ) -> Forward | Respond:
        params = request.params or {}
        tool_name = str(params.get("name", ""))

        # Replay Guard (§4.2 stage 1, cheapest check first): nonce + timestamp from
        # params._meta; missing/invalid fields and a Redis failure all deny (§5).
        meta = params.get("_meta") or {}
        try:
            replay_reason = await self.replay.check(
                meta.get(NONCE_META_KEY), meta.get(TIMESTAMP_META_KEY)
            )
        except Exception:
            self._log.exception("replay_check_failed_fail_closed", tool=tool_name)
            replay_reason = "replay guard unavailable"
        if replay_reason is not None:
            return await self._deny(
                request,
                tool_name,
                EventType.DENY_REPLAY,
                f"Replay detected: {replay_reason}",
                ["replay_guard"],
            )

        if not self.engine.is_allowed(self.identity_id, settings.upstream_server_id, tool_name):
            return await self._deny_rbac(request, tool_name)

        # Schema drift status (§4.2 stage 5): a tool blocked on High/Critical drift is
        # denied until re-approval; a status lookup failure also denies (§5).
        try:
            drift_blocked = await self.detector.is_blocked(
                settings.upstream_server_id, tool_name
            )
        except Exception:
            self._log.exception("drift_status_lookup_failed_fail_closed", tool=tool_name)
            drift_blocked = True
        if drift_blocked:
            return await self._deny(
                request,
                tool_name,
                EventType.DENY_DRIFT,
                f"{tool_name!r} is blocked: schema drifted from its approved baseline"
                " and is pending re-approval",
                ["drift_detector"],
            )

        # Parameter validation (§4.2 stage 7, §4.8): cache miss triggers a transparent
        # upstream re-fetch (§8); only an unfetchable schema fails closed.
        arguments = params.get("arguments", {}) or {}
        input_schema = await self._input_schema_for(tool_name)
        if input_schema is None:
            return await self._deny_validation(
                request, tool_name, "tool schema unavailable from upstream"
            )
        error = param_validator.validate(arguments, input_schema)
        if error is not None:
            return await self._deny_validation(request, tool_name, error)
        arguments, sanitized_fields = param_validator.sanitize(arguments)
        params["arguments"] = arguments

        # ALLOW is recorded before the call is forwarded — no record, no action (§5).
        payload_extra: dict[str, object] = {"arguments": arguments}
        if sanitized_fields:
            payload_extra["sanitized_fields"] = sanitized_fields
        try:
            seq = await self.writer.write(
                EventType.ALLOW,
                self.identity_id,
                tool_name=tool_name,
                payload_extra=payload_extra,
            )
        except Exception:
            self._log.exception("audit_write_failed_fail_closed", tool=tool_name)
            self._pending.pop(request.id, None)
            return _error(
                request.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; call denied"
            )
        self._log.info(
            "decision",
            decision="allow",
            event_type=EventType.ALLOW.value,
            tool=tool_name,
            audit_id=str(seq),
        )
        # The nonce/timestamp pair is gateway-facing only — it must not leak upstream.
        meta.pop(NONCE_META_KEY, None)
        meta.pop(TIMESTAMP_META_KEY, None)
        if not meta:
            params.pop("_meta", None)
        return Forward(message)

    async def _input_schema_for(self, tool_name: str) -> dict[str, Any] | None:
        tools = await self.cache.get(settings.upstream_server_id)
        if tools is None:
            tools = await self._refetch_tools()
            if tools is None:
                return None
        for tool in tools:
            if tool.get("name") == tool_name:
                schema: dict[str, Any] = tool.get("inputSchema", {})
                return schema
        return None  # RBAC-allowed but the upstream doesn't expose it — fail closed

    async def _refetch_tools(self) -> list[dict[str, Any]] | None:
        """Gateway-initiated tools/list (§8 TTL expiry / cache miss). The re-fetched
        schema goes through the same drift check as a client-initiated list."""
        request_id = f"securmcp:{uuid.uuid4().hex}"
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._internal[request_id] = future
        try:
            await self.send_upstream(
                JSONRPCMessage(
                    JSONRPCRequest(jsonrpc="2.0", id=request_id, method="tools/list")
                )
            )
            result = await asyncio.wait_for(future, timeout=_REFETCH_TIMEOUT_S)
            tools: list[dict[str, Any]] = result.get("tools", [])
            await self.detector.check(settings.upstream_server_id, tools, self.identity_id)
            await self.cache.put(settings.upstream_server_id, tools)
        except Exception:
            self._log.exception("tools_list_refetch_failed")
            return None
        finally:
            self._internal.pop(request_id, None)
        return tools

    async def _deny(
        self,
        request: JSONRPCRequest,
        tool_name: str,
        event_type: EventType,
        reason: str,
        matched_rules: list[str],
    ) -> Respond:
        """Terminal deny: canonical Decision (§4.3) in error.data, audited with the
        row seq as audit_id. The deny stands even if the audit write fails."""
        self._pending.pop(request.id, None)
        decision = Decision(
            decision=DecisionOutcome.DENY,
            event_type=event_type,
            reason=reason,
            matched_rules=matched_rules,
            policy_version=self.engine.version,
        )
        try:
            seq = await self.writer.write(
                event_type,
                self.identity_id,
                tool_name=tool_name,
                payload_extra={"reason": decision.reason},
            )
            decision.audit_id = str(seq)
        except Exception:
            self._log.exception("audit_write_failed", event_type=event_type.value, tool=tool_name)
        self._log.info(
            "decision",
            decision="deny",
            event_type=event_type.value,
            tool=tool_name,
            reason=decision.reason,
            audit_id=decision.audit_id,
        )
        return _error(
            request.id,
            POLICY_DENIED_CODE,
            decision.reason,
            data=decision.model_dump(mode="json"),
        )

    async def _deny_validation(
        self, request: JSONRPCRequest, tool_name: str, reason: str
    ) -> Respond:
        return await self._deny(
            request,
            tool_name,
            EventType.DENY_VALIDATION,
            f"invalid arguments for {tool_name!r}: {reason}",
            ["param_validator"],
        )

    async def _deny_rbac(self, request: JSONRPCRequest, tool_name: str) -> Respond:
        return await self._deny(
            request,
            tool_name,
            EventType.DENY_RBAC,
            f"identity {self.identity_id!r} is not authorized to call {tool_name!r}",
            [f"policy-v{self.engine.version}:rbac"],
        )

    async def on_upstream_message(self, message: SessionMessage) -> SessionMessage | None:
        """Returns the message to serve to the client, or None to swallow it
        (responses to gateway-initiated internal requests)."""
        root = message.message.root
        if isinstance(root, JSONRPCResponse):
            if isinstance(root.id, str) and root.id in self._internal:
                future = self._internal[root.id]
                if not future.done():
                    future.set_result(root.result)
                return None
            method = self._pending.pop(root.id, None)
            if method == "tools/list":
                return await self._prune_tools_list(message, root)
        elif isinstance(root, JSONRPCError):
            if isinstance(root.id, str) and root.id in self._internal:
                future = self._internal[root.id]
                if not future.done():
                    future.set_exception(RuntimeError(root.error.message))
                return None
            self._pending.pop(root.id, None)
        return message

    async def _prune_tools_list(
        self, message: SessionMessage, response: JSONRPCResponse
    ) -> SessionMessage:
        full = response.result.get("tools", [])
        try:
            await self.detector.check(settings.upstream_server_id, full, self.identity_id)
        except Exception:
            self._log.exception("drift_check_failed_fail_closed")
            return _error(
                response.id, AUDIT_UNAVAILABLE_CODE, "drift check unavailable; tools/list denied"
            ).message
        schema_hash = await self.cache.put(settings.upstream_server_id, full)
        served = schema_pruner.prune(
            full, self.identity_id, settings.upstream_server_id, self.engine
        )
        response.result["tools"] = served
        # §8 ETag, realized as result metadata (per-message conditional HTTP semantics
        # don't exist over the streamed transport).
        response.result["_meta"] = {"etag": f"{self.engine.version}-{schema_hash}"}
        served_names = [str(tool.get("name")) for tool in served]
        pruned_names = [str(t.get("name")) for t in full if t not in served]
        try:
            await self.writer.write(
                EventType.TOOLS_LIST,
                self.identity_id,
                payload_extra={"served_tools": served_names, "pruned_tools": pruned_names},
            )
        except Exception:
            self._log.exception(
                "audit_write_failed_fail_closed", event_type=EventType.TOOLS_LIST.value
            )
            return _error(
                response.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; tools/list denied"
            ).message
        return message
