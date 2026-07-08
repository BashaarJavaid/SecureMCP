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


settings = Settings()
