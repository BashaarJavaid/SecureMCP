"""JSON-RPC method dispatch (ARCHITECTURE.md §4.8).

Per-session interceptor. Client→upstream messages are routed by method; upstream→client
responses are matched back to their request id (pruning happens on the tools/list
*response*). A method without an explicit handler is passed through unmodified but still
logged — deny-by-default is deliberately not enforced here; visibility in the log is the
day-one guarantee.

tools/call is authorized here regardless of what the pruned tools/list showed: pruning
shapes the LLM's planning surface, authorization happens fresh at the point of action
(§4.1 design principle).
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
from services.gateway.config import settings
from services.gateway.decision import Decision, DecisionOutcome, EventType
from services.gateway.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)

# Implementation-defined JSON-RPC error code for policy denials; the canonical Decision
# object (§4.3) travels in error.data.
POLICY_DENIED_CODE = -32003

_HANDLED_METHODS = frozenset({"initialize", "tools/list", "tools/call"})


@dataclass
class Forward:
    """Send this message on to the upstream server."""

    message: SessionMessage


@dataclass
class Respond:
    """Answer the client directly; nothing reaches the upstream server."""

    message: SessionMessage


@dataclass
class Interceptor:
    identity_id: str | None
    engine: PolicyEngine
    _pending: dict[RequestId, str] = field(default_factory=dict)  # request id -> method

    def on_client_message(self, message: SessionMessage) -> Forward | Respond:
        root = message.message.root
        if not isinstance(root, JSONRPCRequest):
            method = getattr(root, "method", None)
            if method is not None and method not in _HANDLED_METHODS:
                logger.info("passthrough (no handler): %s", method)
            return Forward(message)
        self._pending[root.id] = root.method
        if root.method == "tools/call":
            return self._authorize_call(message, root)
        if root.method not in _HANDLED_METHODS:
            logger.info("passthrough (no handler): %s", root.method)
        return Forward(message)

    def _authorize_call(
        self, message: SessionMessage, request: JSONRPCRequest
    ) -> Forward | Respond:
        tool_name = str((request.params or {}).get("name", ""))
        if self.engine.is_allowed(self.identity_id, settings.upstream_server_id, tool_name):
            return Forward(message)
        self._pending.pop(request.id, None)
        decision = Decision(
            decision=DecisionOutcome.DENY,
            event_type=EventType.DENY_RBAC,
            reason=f"identity {self.identity_id!r} is not authorized to call {tool_name!r}",
            matched_rules=[f"policy-v{self.engine.version}:rbac"],
            policy_version=self.engine.version,
        )
        logger.info("DENY_RBAC: %s", decision.reason)
        error = JSONRPCError(
            jsonrpc="2.0",
            id=request.id,
            error=ErrorData(
                code=POLICY_DENIED_CODE,
                message=decision.reason,
                data=decision.model_dump(mode="json"),
            ),
        )
        return Respond(SessionMessage(JSONRPCMessage(error)))

    def on_upstream_message(self, message: SessionMessage) -> SessionMessage:
        root = message.message.root
        if isinstance(root, JSONRPCResponse):
            method = self._pending.pop(root.id, None)
            if method == "tools/list":
                root.result["tools"] = schema_pruner.prune(
                    root.result.get("tools", []),
                    self.identity_id,
                    settings.upstream_server_id,
                    self.engine,
                )
        elif isinstance(root, JSONRPCError):
            self._pending.pop(root.id, None)
        return message
