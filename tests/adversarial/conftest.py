import secrets
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import yaml

from services.gateway.config import settings
from tests.integration.conftest import (  # noqa: F401  (fixtures re-exported)
    Gateway,
    _key_hash,
    clean_audit,
    gateway,
    running_gateway,
)

MUTABLE_SERVER = Path(__file__).parent / "fixtures" / "mutable_server.py"


def upstream_command(mutation: str) -> str:
    return f"env MUTATION={mutation} {sys.executable} {MUTABLE_SERVER}"


def set_mutation(mutation: str) -> None:
    """Later sessions spawn the mutated upstream — the rug pull, operator-triggered."""
    settings.upstream_command = upstream_command(mutation)


@pytest.fixture
async def drift_gateway(clean_audit: None, tmp_path: Path) -> AsyncIterator[Gateway]:  # noqa: F811
    keys = {"dev": secrets.token_urlsafe(32), "admin": secrets.token_urlsafe(32)}
    policy = {
        "version": 1,
        "identities": [
            {
                "id": "dev",
                "api_key_hash": _key_hash(keys["dev"]),
                "allowed_servers": [{"server_id": "*", "allowed_tools": ["*"]}],
            },
            {
                "id": "admin",
                "api_key_hash": _key_hash(keys["admin"]),
                "admin": True,
                "allowed_servers": [],
            },
        ],
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    async with running_gateway(policy_path, upstream_command("none"), keys) as gw:
        yield gw
