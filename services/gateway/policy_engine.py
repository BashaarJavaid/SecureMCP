"""Loads the YAML policy, validates it, answers RBAC + ABAC questions
(ARCHITECTURE.md §4.8).

The base grant is RBAC (allowed/denied tools per server); each grant may carry
ABAC `conditions` (item 17), compiled at load via services.gateway.abac and
evaluated per tools/call by the interceptor — a malformed condition fails
validation, so startup fails and SIGHUP reload keeps last-known-good. Activation
record-keeping (revision snapshots, policy_versions rows, monotonicity — item 19)
lives in services.gateway.policy_versions. A missing or invalid policy file fails
startup — fail closed (ARCHITECTURE.md §5).
"""

import hashlib
from pathlib import Path
from typing import Literal

import structlog
import yaml
from pydantic import BaseModel, ConfigDict, PrivateAttr, model_validator

from services.gateway import abac

logger = structlog.get_logger(__name__)

SensitivityTier = Literal["low", "medium", "high", "critical"]


class RiskPolicy(BaseModel):
    """Static Risk Engine inputs (§4.8, item 16): the sensitivity tier per tool and the
    blast-radius protected list. Factor weights stay code constants in risk_engine."""

    model_config = ConfigDict(extra="forbid")

    # Tool name -> tier; unlisted tools contribute 0.
    tool_sensitivity: dict[str, SensitivityTier] = {}
    # fnmatch patterns matched against every string argument value (repos, paths).
    protected_repos: list[str] = []


class ServerGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str
    allowed_tools: list[str] = []
    denied_tools: list[str] = []
    # ABAC conditions (item 17): ALL must be satisfied once RBAC matches this grant.
    conditions: list[str] = []
    _compiled: list[abac.Condition] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _compile_conditions(self) -> "ServerGrant":
        self._compiled = [abac.compile_condition(source) for source in self.conditions]
        return self

    @property
    def compiled_conditions(self) -> list[abac.Condition]:
        return self._compiled


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    api_key_hash: str
    # Grants access to /admin endpoints (drift re-approval, and Phase 3's admin API).
    admin: bool = False
    allowed_servers: list[ServerGrant] = []
    # identity.* attributes for ABAC conditions (identity.id comes from `id` itself).
    attributes: dict[str, str | int | float | bool] = {}


class PolicyFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    identities: list[Identity] = []
    risk: RiskPolicy = RiskPolicy()


class PolicyEngine:
    def __init__(self, policy: PolicyFile, content_hash: str = "", raw: bytes = b"") -> None:
        self.policy = policy
        self.content_hash = content_hash
        # Exact file bytes, snapshotted verbatim on activation (item 19) — never
        # re-serialized through yaml.dump, which would change formatting.
        self.raw = raw
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

    def identity(self, identity_id: str) -> Identity | None:
        return self._identities.get(identity_id)

    def is_allowed(self, identity_id: str | None, server_id: str, tool_name: str) -> bool:
        return self.matching_grant(identity_id, server_id, tool_name) is not None

    def matching_grant(
        self, identity_id: str | None, server_id: str, tool_name: str
    ) -> ServerGrant | None:
        """RBAC resolution: unknown/missing identity denies; a grant matches by exact
        server_id or "*"; denied_tools overrides allowed_tools; "*" allows any tool.
        Returns the first allowing grant — its `conditions` are the ABAC layer the
        interceptor enforces on top (item 17)."""
        if identity_id is None:
            return None
        identity = self._identities.get(identity_id)
        if identity is None:
            return None
        for grant in identity.allowed_servers:
            if grant.server_id not in (server_id, "*"):
                continue
            if tool_name in grant.denied_tools:
                return None
            if "*" in grant.allowed_tools or tool_name in grant.allowed_tools:
                return grant
        return None


def load_bytes(raw: bytes) -> PolicyEngine:
    data = yaml.safe_load(raw)
    return PolicyEngine(
        PolicyFile.model_validate(data), content_hash=hashlib.sha256(raw).hexdigest(), raw=raw
    )


def load(path: str | Path) -> PolicyEngine:
    return load_bytes(Path(path).read_bytes())


class PolicyStore:
    """Holds the live PolicyEngine; hot-swapped on SIGHUP (ARCHITECTURE.md §8). Readers
    go through .engine on every call, so in-flight sessions re-resolve against a new
    version on their next request rather than finishing out the old one."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self.engine = load(self._path)

    def load_candidate(self) -> PolicyEngine | None:
        """Parse + validate the file's current contents without swapping; None on any
        error — a broken reload must not take the gateway down or weaken the active
        policy (last-known-good, item 7). The caller records the activation (item 19)
        before calling swap()."""
        try:
            return load(self._path)
        except Exception:
            logger.exception("policy_reload_failed_keeping_last_known_good")
            return None

    def swap(self, engine: PolicyEngine) -> None:
        self.engine = engine
        logger.info("policy_activated", version=engine.version)

    def reload(self) -> bool:
        """Load + swap in one step; keep last-known-good on any error. The gateway's
        SIGHUP path uses load_candidate()/swap() around activation record-keeping."""
        candidate = self.load_candidate()
        if candidate is None:
            return False
        self.swap(candidate)
        return True
