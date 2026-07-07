import logging

import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from services.gateway.jsonrpc_interceptor import Forward, Interceptor, Respond
from services.gateway.policy_engine import PolicyEngine, PolicyFile

POLICY = PolicyFile.model_validate(
    {
        "version": 1,
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": "sha256:0",
                "allowed_servers": [{"server_id": "default", "allowed_tools": ["echo"]}],
            }
        ],
    }
)


def make_interceptor(identity: str | None = "agent-readonly") -> Interceptor:
    return Interceptor(identity_id=identity, engine=PolicyEngine(POLICY))


def request(method: str, params: dict | None = None, id: int = 1) -> SessionMessage:  # noqa: A002
    return SessionMessage(
        JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params))
    )


def test_unhandled_method_passes_through_unmodified_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    message = request("weird/unknown", {"x": 1})
    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        outcome = make_interceptor().on_client_message(message)

    assert isinstance(outcome, Forward)
    assert outcome.message is message  # passed through, not rebuilt
    assert "weird/unknown" in caplog.text


def test_unauthorized_tools_call_is_denied_with_canonical_decision() -> None:
    outcome = make_interceptor().on_client_message(
        request("tools/call", {"name": "delete_repo", "arguments": {}})
    )

    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.id == 1
    assert error.error.data["event_type"] == "DENY_RBAC"
    assert error.error.data["decision"] == "deny"
    assert error.error.data["policy_version"] == 1


def test_authorized_tools_call_is_forwarded() -> None:
    outcome = make_interceptor().on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)


def test_tools_list_response_is_pruned_by_identity() -> None:
    interceptor = make_interceptor()
    interceptor.on_client_message(request("tools/list", id=7))
    response = SessionMessage(
        JSONRPCMessage(
            JSONRPCResponse(
                jsonrpc="2.0",
                id=7,
                result={"tools": [{"name": "echo"}, {"name": "delete_repo"}]},
            )
        )
    )

    out = interceptor.on_upstream_message(response)

    assert out.message.root.result["tools"] == [{"name": "echo"}]
