from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.roles import Role


class UserRecord(BaseModel):
    """One entry in the prototype's configured user store (see
    docs/authorization-design.md). Pairs a credential with the role and
    tenant that authorization decisions are made from - not a general
    user-management record (no profile data, no self-service, no
    rotation/expiry), which is a deliberate prototype scope choice rather
    than an external identity provider or a full user-management system.

    tenant_id is the tenant this user's writes are attributed to, and (for
    a reader) the only tenant's data they may read - see
    app/api/routes/audit_events.py. None means "no tenant" and is only
    meaningful for auditor/admin, whose read access is not tenant-scoped
    to begin with.
    """

    username: str
    password: str
    role: Role
    tenant_id: str | None = None


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables (or a .env file)."""

    database_url: str

    # JWT auth mechanics.
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # Small configured user store standing in for user management in this
    # prototype (see docs/authorization-design.md) - not an external
    # identity provider. Parsed from a JSON array in AUTH_USERS.
    auth_users: list[UserRecord]

    # No default: the retention window is a policy decision (and may have
    # compliance implications - see docs/requirements.md Scenario C), so it
    # should be set deliberately rather than silently inherited from a
    # made-up default.
    retention_window_days: int = Field(gt=0)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
