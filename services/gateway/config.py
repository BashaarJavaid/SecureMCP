"""Environment-driven settings for the gateway."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Defaults are local-dev only; docker-compose.yml / .env override them.
    database_url: str = "postgresql+asyncpg://securmcp:securmcp@localhost:5432/securmcp"
    redis_url: str = "redis://localhost:6379/0"
    policy_file: str = "policies/example-policy.yaml"
    # Append-only revision snapshots written on every policy activation (§4.8, item 19).
    policy_revisions_dir: str = "policies/revisions"
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
    # Capped and expiring (item 33) so rubber-stamp approvals can dampen behavioral
    # scoring but never permanently zero it.
    risk_decay_step: int = 5
    risk_decay_max: int = 10
    risk_decay_ttl_seconds: int = 2592000  # 30 days
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
    # Prometheus scrape port (§7, item 25) — a separate internal-only listener,
    # never the published app port (labels carry identity ids and tool names).
    # The verifier sidecar sets its own via METRICS_PORT in compose.
    metrics_port: int = 9100
    # Bind address for that listener. Loopback by default so a gateway run directly
    # on a host does not expose identity ids and tool names on every interface;
    # compose sets METRICS_HOST=0.0.0.0, where container network isolation (the port
    # is deliberately not published) is the boundary instead.
    metrics_host: str = "127.0.0.1"


settings = Settings()
