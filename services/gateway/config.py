"""Environment-driven settings for the gateway."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Defaults are local-dev only; docker-compose.yml / .env override them.
    database_url: str = "postgresql+asyncpg://securmcp:securmcp@localhost:5432/securmcp"
    redis_url: str = "redis://localhost:6379/0"


settings = Settings()
