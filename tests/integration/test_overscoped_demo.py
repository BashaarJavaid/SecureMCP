"""The item-8 demo, verified before anyone records it: the overscoped demo server
exposes destructive tools to everyone; through the gateway, the developer identity
never sees them, the admin does, and the audit log holds the receipts."""

import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from services.gateway.db import AuditLog, async_session
from tests.integration.conftest import Gateway, _key_hash, running_gateway
from tests.integration.test_policy_scoping import connect

OVERSCOPED_SERVER = Path(__file__).parents[2] / "sample_target" / "overscoped_server.py"

ALL_TOOLS = ["read_file", "list_issues", "delete_repo", "merge_pr"]


@pytest.fixture
async def demo_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:
    keys = {"developer": secrets.token_urlsafe(32), "ops-admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "developer",
                "api_key_hash": _key_hash(keys["developer"]),
                "allowed_servers": [
                    {"server_id": "default", "allowed_tools": ["read_file", "list_issues"]}
                ],
            },
            {
                "id": "ops-admin",
                "api_key_hash": _key_hash(keys["ops-admin"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
        ],
    }
    policy_path = tmp_path / "demo-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(
        policy_path, f"{sys.executable} {OVERSCOPED_SERVER}", keys
    ) as gw:
        yield gw


async def test_developer_is_pruned_admin_is_not_and_audit_has_receipts(
    demo_gateway: Gateway,
) -> None:
    async with connect(demo_gateway.url, demo_gateway.keys["developer"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ["read_file", "list_issues"]

    async with connect(demo_gateway.url, demo_gateway.keys["ops-admin"]) as session:
        tools = await session.list_tools()
        assert [tool.name for tool in tools.tools] == ALL_TOOLS

    async with async_session() as db:
        rows = (
            (
                await db.execute(
                    select(AuditLog)
                    .where(AuditLog.event_type == "TOOLS_LIST")
                    .order_by(AuditLog.seq)
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2
    developer_row, admin_row = rows
    assert developer_row.identity_id == "developer"
    assert developer_row.payload["pruned_tools"] == ["delete_repo", "merge_pr"]
    assert admin_row.identity_id == "ops-admin"
    assert admin_row.payload["pruned_tools"] == []
