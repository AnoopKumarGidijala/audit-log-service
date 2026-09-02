"""Redacting sensitive data out of structured log fields before they're
ever serialized (see docs/security-logging-design.md). Pure functions,
independent of the logging module and of app.core.config - callers
(app/core/logging_config.py) supply the set of known secret values
explicitly, the same explicit-parameter style already used by
app/services/hashing.py and app/core/payload_limits.py.

Two independent, complementary passes, applied to every log record's
fields (and its message) with no exceptions and no opt-out:

1. Key-name-based: any field whose name suggests a credential (password,
   token, secret, jwt, authorization, ...) has its value replaced
   outright, regardless of what the value actually contains. Catches
   anything logged under a recognizably sensitive key, deliberately or
   by accident.
2. Value-shape/content-based: any *string* value - even under an
   innocuous-looking key, or embedded in a log message - that is either
   shaped like a JWT (three dot-separated base64url segments) or
   contains one of the deployment's own known secret values verbatim
   (the signing key, the database password) is also redacted. This is
   the safety net for the case key-name matching can't cover: a secret
   value surfacing somewhere unexpected, e.g. inside a raw exception
   message from a database driver.
"""

import re
from typing import Any

REDACTED_VALUE = "[REDACTED]"

_SENSITIVE_KEY_MARKERS = (
    "password",
    "secret",
    "token",
    "jwt",
    "authorization",
    "signing_key",
    "api_key",
    "credential",
)

# Three dot-separated base64url segments, each long enough that a false
# positive (e.g. a short dotted version string) is very unlikely.
_JWT_LIKE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")

# Below this length, a "known secret" is too likely to coincidentally
# appear as a normal substring of unrelated text (a short password in a
# dev/test environment, say) - not worth the false-positive rate.
_MIN_KNOWN_SECRET_LENGTH = 8


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_KEY_MARKERS)


def _contains_a_known_secret(value: str, known_secrets: frozenset[str]) -> bool:
    return any(secret in value for secret in known_secrets)


def _sanitize_value(value: Any, known_secrets: frozenset[str]) -> Any:
    if isinstance(value, str):
        if _JWT_LIKE_PATTERN.match(value) or _contains_a_known_secret(value, known_secrets):
            return REDACTED_VALUE
        return value
    if isinstance(value, dict):
        return sanitize_log_fields(value, known_secrets=known_secrets)
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(v, known_secrets) for v in value]
    return value


def sanitize_log_fields(fields: dict[str, Any], *, known_secrets: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Returns a new dict with every sensitive key/value redacted,
    recursively. `known_secrets` should already be filtered to values at
    least _MIN_KNOWN_SECRET_LENGTH long - see
    app/core/logging_config.py:_known_secret_values() for how the caller
    builds this set from Settings.
    """
    sanitized: dict[str, Any] = {}
    for key, value in fields.items():
        if _is_sensitive_key(str(key)):
            sanitized[key] = REDACTED_VALUE
        else:
            sanitized[key] = _sanitize_value(value, known_secrets)
    return sanitized


def filter_known_secrets(values: Any) -> frozenset[str]:
    """Filters candidate secret values (e.g. Settings.secret_key, a
    database password) down to the ones worth matching against - long
    enough to be meaningfully specific, and not None/empty.
    """
    return frozenset(v for v in values if v and len(v) >= _MIN_KNOWN_SECRET_LENGTH)
