from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://vulnwatch:vulnwatch@db:5432/vulnwatch"
    environment: str = "production"
    trusted_origins: list[str] = ["http://localhost:8080"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "api"]
    session_hours: int = 12
    nvd_api_key: str | None = None
    nvd_initial_days: int = 30
    sync_interval_seconds: int = 7200

    @model_validator(mode="after")
    def secure_production(self):
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("Invalid environment")
        if self.environment == "production" and any(
            not origin.startswith("https://") for origin in self.trusted_origins
        ):
            raise ValueError("Production requires HTTPS trusted origins")
        if not 1 <= self.nvd_initial_days <= 120 or not 1 <= self.session_hours <= 168:
            raise ValueError("Invalid synchronization or session configuration")
        if self.sync_interval_seconds < 7200:
            raise ValueError("NVD synchronization must be at least two hours apart")
        return self


@lru_cache
def get_settings():
    return Settings()
