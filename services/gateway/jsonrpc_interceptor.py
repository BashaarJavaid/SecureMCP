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
"""

import logging
from dataclasses import dataclass, field

from mcp.shared.message import SessionMessage
from mcp.types import (
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCRequest,
    JSONRPCResponse,
    RequestId,
)

from services.gateway import schema_pruner
from services.gateway.audit_log import AuditWriter
from services.gateway.config import settings
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)

# Implementation-defined JSON-RPC error codes; the canonical Decision object (§4.3)
# travels in error.data for policy denials.
POLICY_DENIED_CODE = -32003
AUDIT_UNAVAILABLE_CODE = -32004

_HANDLED_METHODS = frozenset({"initialize", "tools/list", "tools/call"})


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
    engine: PolicyEngine
    writer: AuditWriter
    _pending: dict[RequestId, str] = field(default_factory=dict)  # request id -> method

    async def on_client_message(self, message: SessionMessage) -> Forward | Respond:
        root = message.message.root
        if not isinstance(root, JSONRPCRequest):
            method = getattr(root, "method", None)
            if method is not None and method not in _HANDLED_METHODS:
                logger.info("passthrough (no handler): %s", method)
            return Forward(message)
        self._pending[root.id] = root.method
        if root.method == "tools/call":
            return await self._authorize_call(message, root)
        if root.method not in _HANDLED_METHODS:
            logger.info("passthrough (no handler): %s", root.method)
        return Forward(message)

    async def _authorize_call(
        self, message: SessionMessage, request: JSONRPCRequest
    ) -> Forward | Respond:
        params = request.params or {}
        tool_name = str(params.get("name", ""))
        if not self.engine.is_allowed(self.identity_id, settings.upstream_server_id, tool_name):
            return await self._deny_rbac(request, tool_name)
        # ALLOW is recorded before the call is forwarded — no record, no action (§5).
        try:
            await self.writer.write(
                EventType.ALLOW,
                self.identity_id,
                tool_name=tool_name,
                payload_extra={"arguments": params.get("arguments", {})},
            )
        except Exception:
            logger.exception("audit write failed; denying tools/call %r (fail closed)", tool_name)
            self._pending.pop(request.id, None)
            return _error(
                request.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; call denied"
            )
        return Forward(message)

    async def _deny_rbac(self, request: JSONRPCRequest, tool_name: str) -> Respond:
        self._pending.pop(request.id, None)
        decision = Decision(
            decision=DecisionOutcome.DENY,
            event_type=EventType.DENY_RBAC,
            reason=f"identity {self.identity_id!r} is not authorized to call {tool_name!r}",
            matched_rules=[f"policy-v{self.engine.version}:rbac"],
            policy_version=self.engine.version,
        )
        logger.info("DENY_RBAC: %s", decision.reason)
        try:
            seq = await self.writer.write(
                EventType.DENY_RBAC,
                self.identity_id,
                tool_name=tool_name,
                payload_extra={"reason": decision.reason},
            )
            decision.audit_id = str(seq)
        except Exception:
            # The deny still stands; only the record of it failed. Log loudly.
            logger.exception("audit write failed for DENY_RBAC on %r", tool_name)
        return _error(
            request.id,
            POLICY_DENIED_CODE,
            decision.reason,
            data=decision.model_dump(mode="json"),
        )

    async def on_upstream_message(self, message: SessionMessage) -> SessionMessage:
        root = message.message.root
        if isinstance(root, JSONRPCResponse):
            method = self._pending.pop(root.id, None)
            if method == "tools/list":
                return await self._prune_tools_list(message, root)
        elif isinstance(root, JSONRPCError):
            self._pending.pop(root.id, None)
        return message

    async def _prune_tools_list(
        self, message: SessionMessage, response: JSONRPCResponse
    ) -> SessionMessage:
        full = response.result.get("tools", [])
        served = schema_pruner.prune(
            full, self.identity_id, settings.upstream_server_id, self.engine
        )
        response.result["tools"] = served
        served_names = [str(tool.get("name")) for tool in served]
        pruned_names = [str(t.get("name")) for t in full if t not in served]
        try:
            await self.writer.write(
                EventType.TOOLS_LIST,
                self.identity_id,
                payload_extra={"served_tools": served_names, "pruned_tools": pruned_names},
            )
        except Exception:
            logger.exception("audit write failed; withholding tools/list (fail closed)")
            return _error(
                response.id, AUDIT_UNAVAILABLE_CODE, "audit log unavailable; tools/list denied"
            ).message
        return message
