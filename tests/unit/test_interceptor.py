import asyncio
import logging
from types import SimpleNamespace
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

ECHO_SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
}

FAKE_HASH = "cafe" * 16


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


class FakeDetector:
    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.checked: list[list[dict[str, Any]]] = []

    async def check(
        self, server_id: str, tools: list[dict[str, Any]], identity_id: str
    ) -> None:
        self.checked.append(tools)

    async def is_blocked(self, server_id: str, tool_name: str) -> bool:
        return tool_name in self.blocked


class FakeCache:
    def __init__(self) -> None:
        self.data: dict[str, list[dict[str, Any]]] = {}
        self.invalidated: list[str] = []

    async def get(self, server_id: str) -> list[dict[str, Any]] | None:
        return self.data.get(server_id)

    async def put(self, server_id: str, tools: list[dict[str, Any]]) -> str:
        self.data[server_id] = tools
        return FAKE_HASH

    async def invalidate(self, server_id: str) -> None:
        self.data.pop(server_id, None)
        self.invalidated.append(server_id)


async def _no_upstream(message: JSONRPCMessage) -> None:
    raise AssertionError("unexpected gateway-initiated upstream send")


def make_interceptor(
    identity: str = "agent-readonly", with_schema: bool = True
) -> tuple[Interceptor, FakeWriter, FakeCache, FakeDetector]:
    writer = FakeWriter()
    cache = FakeCache()
    detector = FakeDetector()
    if with_schema:
        cache.data["default"] = [{"name": "echo", "inputSchema": ECHO_SCHEMA}]
    interceptor = Interceptor(
        identity_id=identity,
        store=cast(Any, SimpleNamespace(engine=PolicyEngine(POLICY))),
        writer=cast(Any, writer),
        cache=cast(Any, cache),
        detector=cast(Any, detector),
        send_upstream=_no_upstream,
    )
    return interceptor, writer, cache, detector


def request(method: str, params: dict | None = None, id: int = 1) -> SessionMessage:  # noqa: A002
    return SessionMessage(
        JSONRPCMessage(JSONRPCRequest(jsonrpc="2.0", id=id, method=method, params=params))
    )


async def test_unhandled_method_passes_through_unmodified_but_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    message = request("weird/unknown", {"x": 1})
    interceptor, _, _, _ = make_interceptor()
    with caplog.at_level(logging.INFO, logger="services.gateway.jsonrpc_interceptor"):
        outcome = await interceptor.on_client_message(message)

    assert isinstance(outcome, Forward)
    assert outcome.message is message  # passed through, not rebuilt
    assert "weird/unknown" in caplog.text


async def test_unauthorized_tools_call_is_denied_with_canonical_decision() -> None:
    interceptor, writer, _, _ = make_interceptor()
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
    interceptor, writer, _, _ = make_interceptor()
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Forward)
    assert writer.events == [EventType.ALLOW]  # recorded before forwarding


async def test_allow_that_cannot_be_recorded_is_denied() -> None:
    interceptor, writer, _, _ = make_interceptor()

    async def broken_write(*args: Any, **kwargs: Any) -> int:
        raise ConnectionError("postgres down")

    writer.write = broken_write  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {}})
    )
    assert isinstance(outcome, Respond)  # no record, no action (§5)


async def test_drift_blocked_tool_is_denied() -> None:
    interceptor, writer, _, detector = make_interceptor()
    detector.blocked.add("echo")
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    error = outcome.message.message.root
    assert error.error.data["event_type"] == "DENY_DRIFT"
    assert error.error.data["audit_id"] == "42"
    assert writer.events == [EventType.DENY_DRIFT]


async def test_drift_status_lookup_failure_denies() -> None:
    interceptor, _, _, detector = make_interceptor()

    async def broken(server_id: str, tool_name: str) -> bool:
        raise ConnectionError("postgres down")

    detector.is_blocked = broken  # type: ignore[method-assign]
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_DRIFT"


async def test_initialize_invalidates_schema_cache() -> None:
    interceptor, _, cache, _ = make_interceptor()
    outcome = await interceptor.on_client_message(request("initialize", {}))
    assert isinstance(outcome, Forward)
    assert cache.invalidated == ["default"]


async def test_cache_miss_triggers_transparent_refetch_then_forwards() -> None:
    interceptor, writer, cache, _ = make_interceptor(with_schema=False)
    sent: list[JSONRPCMessage] = []

    async def capture(message: JSONRPCMessage) -> None:
        sent.append(message)

    interceptor.send_upstream = capture
    task = asyncio.create_task(
        interceptor.on_client_message(
            request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        )
    )
    while not sent:  # wait for the gateway's own tools/list to go out
        await asyncio.sleep(0.01)
    internal_id = sent[0].root.id
    assert str(internal_id).startswith("securmcp:")

    swallowed = await interceptor.on_upstream_message(
        SessionMessage(
            JSONRPCMessage(
                JSONRPCResponse(
                    jsonrpc="2.0",
                    id=internal_id,
                    result={"tools": [{"name": "echo", "inputSchema": ECHO_SCHEMA}]},
                )
            )
        )
    )
    assert swallowed is None  # internal responses never reach the client

    outcome = await task
    assert isinstance(outcome, Forward)
    assert cache.data["default"] == [{"name": "echo", "inputSchema": ECHO_SCHEMA}]
    assert writer.events == [EventType.ALLOW]


async def test_failed_refetch_is_denied_validation() -> None:
    interceptor, writer, _, _ = make_interceptor(with_schema=False)
    # send_upstream raises (default _no_upstream would too, but be explicit)

    async def broken(message: JSONRPCMessage) -> None:
        raise BrokenPipeError("upstream gone")

    interceptor.send_upstream = broken
    outcome = await interceptor.on_client_message(
        request("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
    )
    assert isinstance(outcome, Respond)
    assert outcome.message.message.root.error.data["event_type"] == "DENY_VALIDATION"
    assert writer.events == [EventType.DENY_VALIDATION]


async def test_invalid_arguments_are_denied_and_audited() -> None:
    interceptor, writer, _, _ = make_interceptor()
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
    interceptor, _, _, _ = make_interceptor()
    message = request("tools/call", {"name": "echo", "arguments": {"text": "../a\x00b"}})
    outcome = await interceptor.on_client_message(message)
    assert isinstance(outcome, Forward)
    assert outcome.message.message.root.params["arguments"] == {"text": "ab"}


async def test_tools_list_response_is_pruned_audited_and_etagged() -> None:
    interceptor, writer, cache, detector = make_interceptor(with_schema=False)
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

    assert out is not None
    assert out.message.root.result["tools"] == [{"name": "echo"}]
    assert out.message.root.result["_meta"] == {"etag": f"1-{FAKE_HASH}"}
    assert cache.data["default"] == [{"name": "echo"}, {"name": "delete_repo"}]
    assert writer.events == [EventType.TOOLS_LIST]
    assert detector.checked == [[{"name": "echo"}, {"name": "delete_repo"}]]  # full list
