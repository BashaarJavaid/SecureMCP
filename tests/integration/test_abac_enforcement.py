"""§4.2 stage 4 end-to-end: an RBAC-allowed call denied by an ABAC condition
returns the canonical Decision as DENY_ABAC and lands a DENY_ABAC audit row."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import yaml
from mcp import McpError
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import (
    ECHO_SERVER,
    Gateway,
    _key_hash,
    running_gateway,
)
from tests.integration.test_policy_scoping import connect


@pytest.fixture
async def abac_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    """Echo upstream where agent-readonly's grant carries a failing ABAC condition."""
    keys = {"agent-readonly": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "agent-readonly",
                "api_key_hash": _key_hash(keys["agent-readonly"]),
                "attributes": {"team": "engineering"},
                "allowed_servers": [
                    {
                        "server_id": "default",
                        "allowed_tools": ["echo"],
                        "conditions": ["identity.team == 'sales'"],
                    }
                ],
            }
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, f"{sys.executable} {ECHO_SERVER}", keys) as gw:
        yield gw


async def test_rbac_allowed_call_denied_by_abac_lands_in_audit_log(
    abac_gateway: Gateway,
) -> None:
    async with connect(abac_gateway.url, abac_gateway.keys["agent-readonly"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["echo"]  # pruning stays RBAC-only

        with pytest.raises(McpError) as excinfo:
            await session.call_tool("echo", {"text": "hi"})
    data = excinfo.value.error.data
    assert data["event_type"] == "DENY_ABAC"
    assert data["decision"] == "deny"
    assert data["matched_rules"] == ["policy-v1:abac:identity.team == 'sales'"]
    assert data["policy_version"] == 1
    assert data["audit_id"] is not None

    async with async_session() as db:
        rows = list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())
    deny_rows = [row for row in rows if row.event_type == "DENY_ABAC"]
    assert len(deny_rows) == 1
    assert deny_rows[0].seq == int(data["audit_id"])
    assert deny_rows[0].identity_id == "agent-readonly"
    assert deny_rows[0].tool_name == "echo"
    assert "identity.team == 'sales'" in deny_rows[0].payload["reason"]
