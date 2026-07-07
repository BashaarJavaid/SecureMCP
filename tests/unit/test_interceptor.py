import logging
from typing import Any, cast

import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from services.gateway.decision import EventType
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


class FakeWriter:
    def __init__(self) -> None:
        self.events: list[EventType] = []

    async def write(
        self,
        event_type: EventType,
        identity_id: str,
        tool_name: str | None = None,
        payload_extra: dict[str, Any] | None = None,
        risk_score: int | None = None,
    ) -> int:
        self.events.append(event_type)
        return 42


ECHO_SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
}


def make_interceptor(
    identity: str = "agent-readonly", with_schema: bool = True
) -> tuple[Interceptor, FakeWriter]:
    writer = FakeWriter()
    interceptor = Interceptor(
        identity_id=identity, engine=PolicyEngine(POLICY), writer=cast(Any, writer)
    )
    if with_schema:
        interceptor._tool_schemas["echo"] = ECHO_SCHEMA
    return interceptor, writer


def request(method: str, params: dict | None = None, id: int = 1) -> SessionMessage:  # noqa: A002
    return SessionMessage(
        JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params))
    )


async def test_unhandled_method_passes_through_unmodified_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    message = request("weird/unknown", {"x": 1})
    interceptor, _ = make_interceptor()
    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        outcome = await interceptor.on_client_message(message)

    assert isinstance(outcome, Forward)
    assert outcome.message is message  # passed through, not rebuilt
    assert "weird/unknown" in caplog.text


async def test_unauthorized_tools_call_is_denied_with_canonical_decision() -> None:
    interceptor, writer = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "delete_repo", "arguments": {}})
    )

    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.id == 1
    assert error.error.data["event_type"] == "DENY_RBAC"
    assert error.error.data["decision"] == "deny"
    assert error.error.data["policy_version"] == 1
    assert error.error.data["audit_id"] == "42"  # the audit row's seq
    assert writer.events == [EventType.DENY_RBAC]


async def test_authorized_tools_call_is_audited_then_forwarded() -> None:
    interceptor, writer = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]  # recorded before forwarding


async def test_allow_that_cannot_be_recorded_is_denied() -> None:
    interceptor, writer = make_interceptor()

    async def broken_write(*args: Any, **kwargs: Any) -> int:
        raise ConnectionError("postgres down")

    writer.write = broken_write  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {}})
    )
    assert isinstance(outcome, Respond)  # no record, no action (§5)


async def test_call_without_cached_schema_is_denied_validation() -> None:
    interceptor, writer = make_interceptor(with_schema=False)
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_VALIDATION"
    assert writer.events == [EventType.DENY_VALIDATION]


async def test_invalid_arguments_are_denied_and_audited() -> None:
    interceptor, writer = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi", "bogus": 1}})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_VALIDATION"
    assert error.error.data["audit_id"] == "42"
    assert "bogus" in error.error.message
    assert writer.events == [EventType.DENY_VALIDATION]


async def test_forwarded_arguments_are_sanitized() -> None:
    interceptor, _ = make_interceptor()
    message = request("tools/call", {"name": "echo", "arguments": {"text": "../a\x00b"}})
    outcome = await interceptor.on_client_message(message)
    assert isinstance(outcome, Forward)
    assert outcome.message.message.root.params["arguments"] == {"text": "ab"}


async def test_tools_list_response_is_pruned_and_audited() -> None:
    interceptor, writer = make_interceptor()
    await interceptor.on_client_message(request("tools/list", id=7))
    response = SessionMessage(
        JSONRPCMessage(
            JSONRPCResponse(
                jsonrpc="2.0",
                id=7,
                result={"tools": [{"name": "echo"}, {"name": "delete_repo"}]},
            )
        )
    )

    out = await interceptor.on_upstream_message(response)

    assert out.message.root.result["tools"] == [{"name": "echo"}]
    assert writer.events == [EventType.TOOLS_LIST]
