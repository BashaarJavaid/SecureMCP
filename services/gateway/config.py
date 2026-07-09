"""Environment-driven settings for the gateway."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Defaults are local-dev only; docker-compose.yml / .env override them.
    database_url: str = "postgresql+asyncpg://securmcp:securmcp@localhost:5432/securmcp"
    redis_url: str = "redis://localhost:6379/0"
    # Single upstream MCP server, spawned per session as a stdio subprocess (ROADMAP item 2:
    # one hardcoded upstream, no server registry). Empty = session creation fails.
    upstream_command: str = ""
    # Policy name for the single upstream until a server registry exists.
    upstream_server_id: str = "default"
    policy_file: str = "policies/example-policy.yaml"
    schema_cache_ttl: int = 600
    session_idle_ttl: int = 300
    shutdown_grace_seconds: int = 5
    # Half-width of the Replay Guard's accepted timestamp window (±30s, §4.8).
    replay_window_seconds: int = 30
    # Audit-log ECDSA keypair (§4.8): minted via scripts/generate_signing_key.py.
    # A gateway with no usable private key must not start (§5, fail closed).
    signing_key_file: str = "secrets/audit_signing_key.pem"
    signing_public_key_file: str = "secrets/audit_signing_key.pub.pem"
    # Risk Engine v1 (§4.8, item 16). Business hours are Mon-Fri in UTC — v1 has no
    # per-identity timezone; a policy timezone field is a documented later extension.
    business_hours_start_utc: int = 9
    business_hours_end_utc: int = 18
    # Call-frequency factor: spike when > threshold calls per identity+tool in window.
    risk_freq_window_seconds: int = 60
    risk_freq_threshold: int = 10
    # Risk decay (§4.8): offset added per admin approval, behavioral factors only.
    risk_decay_step: int = 5
    # Richer risk telemetry (§4.8, item 18). Prior-denial-rate: fires when an identity
    # collects more than this many DENY_* terminals within the window.
    risk_denial_window_seconds: int = 600
    risk_denial_threshold: int = 3
    # Auth-failure factor: one gateway-wide counter of failed API-key lookups; fires
    # for every identity while more than this many failures sit within the window.
    risk_auth_failure_window_seconds: int = 300
    risk_auth_failure_threshold: int = 5
    # Drift-history factor: fires when a tool has this many DRIFT_* audit events in
    # the window, even if re-approved ("changed shape twice in the last week").
    risk_drift_history_window_seconds: int = 604800
    risk_drift_history_threshold: int = 2
    # Human approval lifecycle (§4.8): pending approvals expire after this TTL.
    approval_ttl_seconds: int = 900


settings = Settings()
