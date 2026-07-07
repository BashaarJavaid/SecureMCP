import logging

import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

from services.gateway.jsonrpc_interceptor import dispatch


async def test_unhandled_method_passes_through_unmodified_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = JSONRPCRequest(jsonrpc="2.0", id=1, method="weird/unknown", params={"x": 1})
    message = SessionMessage(JSONRPCMessage(request))

    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        result = await dispatch(message)

    assert result is message  # passed through, not rebuilt
    assert "weird/unknown" in caplog.text
