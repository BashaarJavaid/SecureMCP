"""Loads the YAML policy, validates it, answers RBAC questions (ARCHITECTURE.md §4.8).

RBAC only for now: ABAC conditions are Phase 3 (item 17) and the schema rejects them
(extra="forbid") rather than silently ignoring them. Hot-reload is item 7; versioning
beyond the YAML `version` field is Phase 3 (item 19). A missing or invalid policy file
fails startup — fail closed (ARCHITECTURE.md §5).
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict


class ServerGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    allowed_tools: list[str] = []
    denied_tools: list[str] = []


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    api_key_hash: str
    allowed_servers: list[ServerGrant] = []


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    identities: list[Identity] = []


class PolicyEngine:
    def __init__(self, policy: PolicyFile) -> None:
        self.policy = policy
        self._identities = {identity.id: identity for identity in policy.identities}

    @property
    def version(self) -> int:
        return self.policy.version

    def is_allowed(self, identity_id: str | None, server_id: str, tool_name: str) -> bool:
        """RBAC resolution: unknown/missing identity denies; a grant matches by exact
        server_id or "*"; denied_tools overrides allowed_tools; "*" allows any tool."""
        if identity_id is None:
            return False
        identity = self._identities.get(identity_id)
        if identity is None:
            return False
        for grant in identity.allowed_servers:
            if grant.server_id not in (server_id, "*"):
                continue
            if tool_name in grant.denied_tools:
                return False
            if "*" in grant.allowed_tools or tool_name in grant.allowed_tools:
                return True
        return False


def load(path: str | Path) -> PolicyEngine:
    data = yaml.safe_load(Path(path).read_text())
    return PolicyEngine(PolicyFile.model_validate(data))
