from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables (or a .env file)."""

    database_url: str

    # JWT auth. A single fixed credential pair stands in for user
    # management in this prototype (see docs/assumptions.md).
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    auth_username: str
    auth_password: str

    # No default: the retention window is a policy decision (and may have
    # compliance implications - see docs/requirements.md Scenario C), so it
    # should be set deliberately rather than silently inherited from a
    # made-up default.
    retention_window_days: int = Field(gt=0)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
