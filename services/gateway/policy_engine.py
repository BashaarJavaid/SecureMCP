"""Loads the YAML policy, validates it, answers RBAC questions (ARCHITECTURE.md §4.8).

RBAC only for now: ABAC conditions are Phase 3 (item 17) and the schema rejects them
(extra="forbid") rather than silently ignoring them. Hot-reload is item 7; versioning
beyond the YAML `version` field is Phase 3 (item 19). A missing or invalid policy file
fails startup — fail closed (ARCHITECTURE.md §5).
"""

import hashlib
import logging
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)


class ServerGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    allowed_tools: list[str] = []
    denied_tools: list[str] = []


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    api_key_hash: str
    # Grants access to /admin endpoints (drift re-approval, and Phase 3's admin API).
    admin: bool = False
    allowed_servers: list[ServerGrant] = []


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    identities: list[Identity] = []


class PolicyEngine:
    def __init__(self, policy: PolicyFile, content_hash: str = "") -> None:
        self.policy = policy
        self.content_hash = content_hash
        self._identities = {identity.id: identity for identity in policy.identities}
        self._by_key_hash = {identity.api_key_hash: identity.id for identity in policy.identities}

    @property
    def version(self) -> int:
        return self.policy.version

    def identity_for_key_hash(self, key_hash: str) -> str | None:
        return self._by_key_hash.get(key_hash)

    def is_admin(self, identity_id: str) -> bool:
        identity = self._identities.get(identity_id)
        return identity is not None and identity.admin

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
    raw = Path(path).read_bytes()
    data = yaml.safe_load(raw)
    return PolicyEngine(
        PolicyFile.model_validate(data), content_hash=hashlib.sha256(raw).hexdigest()
    )


class PolicyStore:
    """Holds the live PolicyEngine; hot-swapped on SIGHUP (ARCHITECTURE.md §8). Readers
    go through .engine on every call, so in-flight sessions re-resolve against a new
    version on their next request rather than finishing out the old one."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.engine = load(self._path)

    def reload(self) -> bool:
        """Swap in the file's current contents; keep last-known-good on any error —
        a broken reload must not take the gateway down or weaken the active policy."""
        try:
            self.engine = load(self._path)
        except Exception:
            logger.exception("policy reload failed; keeping last-known-good policy")
            return False
        logger.info("policy reloaded: version %d", self.engine.version)
        return True
