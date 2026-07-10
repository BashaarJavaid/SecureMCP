"""ARCHITECTURE.md §11: an ABAC condition referencing a missing attribute resolves
the whole condition as not-satisfied — including specifically inside a `not(...)`
wrapper, the inversion bug §4.8 calls out (a naive False at the leaf would make
`not(False)` grant access). End to end through the real gateway: DENY_ABAC to the
client, a POLICY_ERROR audit row for the authoring bug, and no upstream forward."""

import secrets
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import yaml
from mcp import McpError
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import ECHO_SERVER, Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect


@asynccontextmanager
async def gateway_with_condition(tmp_path: Path, condition: str) -> AsyncIterator[Gateway]:
    """Echo upstream; the agent's grant carries `condition` referencing
    identity.department, which the identity's attributes map does not have."""
    keys = {"agent": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "agent",
                "api_key_hash": _key_hash(keys["agent"]),
                "attributes": {"team": "engineering"},  # department is absent, team isn't
                "allowed_servers": [
                    {
                        "server_id": "default",
                        "allowed_tools": ["echo"],
                        "conditions": [condition],
                    }
                ],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


@pytest.mark.parametrize(
    "condition",
    [
        "identity.department == 'ops'",
        "not (identity.department == 'ops')",  # must NOT invert into an allow
    ],
)
async def test_missing_attribute_is_deny_abac_and_policy_error(
    clean_audit: None, tmp_path: Path, condition: str
) -> None:
    async with gateway_with_condition(tmp_path, condition) as gw:
        async with connect(gw.url, gw.keys["agent"]) as session:
            with pytest.raises(McpError) as excinfo:
                await session.call_tool("echo", {"text": "hi"})

    data = excinfo.value.error.data
    assert data["event_type"] == "DENY_ABAC"
    assert data["decision"] == "deny"

    async with async_session() as db:
        events = list(
            (
                await db.execute(
                    select(AuditLog.event_type)
                    .where(AuditLog.tool_name == "echo")
                    .order_by(AuditLog.seq)
                )
            ).scalars()
        )
    # The unresolvable reference is visible as an authoring bug, the call is
    # denied fail-closed, and nothing was forwarded upstream.
    assert events == ["POLICY_ERROR", "DENY_ABAC"]
