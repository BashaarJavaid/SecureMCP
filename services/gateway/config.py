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


settings = Settings()
