"""JSON-RPC method dispatch (ARCHITECTURE.md §4.8).

Every inbound client message is routed by its `method`. A method without an explicit
handler is passed through unmodified but still logged — deny-by-default is deliberately
not enforced here; visibility in the log is the day-one guarantee. Phase 1 items 3+
register real handlers for initialize / tools/list / tools/call.
"""

import logging
from collections.abc import Awaitable, Callable

from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

Handler = Callable[[SessionMessage], Awaitable[SessionMessage]]

# Item 2 is full passthrough: no handlers registered yet.
HANDLERS: dict[str, Handler] = {}


async def dispatch(message: SessionMessage) -> SessionMessage:
    method = getattr(message.message.root, "method", None)
    if method is None:
        # Responses/errors from the client carry no method; relay as-is.
        return message
    handler = HANDLERS.get(method)
    if handler is None:
        logger.info("passthrough (no handler): %s", method)
        return message
    return await handler(message)
