from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.roles import Role

# Values known to be placeholders, defaults, or otherwise guessable -
# rejected outright regardless of length (see Settings._reject_weak_secret_key
# below). Not exhaustive - a real deployment's secret should come from a
# proper secret manager, not a hand-typed value at all - but it catches the
# most likely accidents: copying .env.example without editing it, or typing
# something short and memorable "for now."
_WEAK_SECRET_KEYS = {
    "change-me-to-a-random-secret",
    "changeme",
    "change-me",
    "secret",
    "password",
    "your-secret-key",
    "your-secret-key-here",
    "test",
    "testing",
    "insecure",
    "default",
    "example",
    "12345678",
    "secretkey",
}

# HS256 with a random key needs a key at least as long as the hash output
# (32 bytes / 256 bits) to have full-strength resistance to brute force;
# requiring at least that many *characters* is a conservative floor given
# SECRET_KEY is typically hex/base64 text, not raw bytes.
MIN_SECRET_KEY_LENGTH = 32


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

    password_hash is an Argon2 hash (see app/core/passwords.py), never a
    plaintext password - configured users are only ever compared by
    verifying a submitted password against this hash, never by direct
    string comparison (see app/core/security.py:authenticate_user).
    """

    username: str
    password_hash: str
    role: Role
    tenant_id: str | None = None


class Settings(BaseSettings):
    """Application configuration, loaded from environment variables (or a .env file)."""

    database_url: str

    # JWT auth mechanics. The signing algorithm is deliberately NOT a
    # setting - it's a fixed constant (app.core.security.JWT_ALGORITHM), so
    # it can never be relaxed via configuration to something weaker (or to
    # "none") by an env var typo or a compromised deployment config. See
    # docs/auth-hardening-design.md.
    secret_key: str
    access_token_expire_minutes: int = 30
    # Issuer/audience aren't secrets - just identifiers distinguishing "a
    # token this service issued, for this service's clients" from a token
    # that happens to be signed with the same key for some other purpose.
    # Defaults are fine for a single-service prototype; a real multi-service
    # deployment would set these per-environment.
    jwt_issuer: str = "audit-log-service"
    jwt_audience: str = "audit-log-service-clients"

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

    @field_validator("secret_key")
    @classmethod
    def _reject_weak_secret_key(cls, value: str) -> str:
        """Fail application startup outright rather than run with a
        signing key an attacker could guess or find in this file. A weak
        key here undermines every other authentication/authorization
        control, so this is checked before the app can serve a single
        request - not logged as a warning and allowed to continue.
        """
        if value.strip().lower() in _WEAK_SECRET_KEYS:
            raise ValueError(
                "SECRET_KEY is a known placeholder/default value. Generate a real random "
                "secret, e.g.: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters long.")
        return value


settings = Settings()
