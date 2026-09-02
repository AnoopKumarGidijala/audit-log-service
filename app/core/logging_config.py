"""Structured (JSON-lines) application logging, configured once at
startup (see docs/security-logging-design.md). Deliberately lightweight -
stdlib `logging` plus a small custom formatter, writing to stdout. No
external logging platform/agent/SDK: a real deployment would typically
collect stdout via its container/process supervisor and ship it
elsewhere, which is exactly why writing plain JSON lines to stdout (not,
say, a proprietary SDK's wire format) is the right level of abstraction
for a prototype - it's immediately usable by essentially anything.

Every log record - not just ones from app/core/security_logging.py - is
sanitized the same way before being serialized (see
app/core/log_sanitizer.py), because a formatter is the one place that
can make that guarantee regardless of which code path produced the
record.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.engine import make_url

from app.core.log_sanitizer import filter_known_secrets, sanitize_log_fields

LOGGER_NAME = "audit_log_service"

# The standard attributes every LogRecord has regardless of what was
# passed via `extra=` - anything else on the record's __dict__ is a
# caller-supplied structured field (see app/core/security_logging.py).
_STANDARD_LOG_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__.keys())


def _known_secret_values() -> frozenset[str]:
    """The deployment's own actual secret values, computed once - used to
    catch a secret surfacing somewhere unexpected (see
    app/core/log_sanitizer.py's module docstring), not to enumerate every
    possible sensitive field name (that's the key-based pass).
    """
    from app.core.config import settings  # deferred: avoids a hard import-time dependency on Settings

    candidates = [settings.secret_key]
    db_password = make_url(settings.database_url).password
    if db_password:
        candidates.append(db_password)
    return filter_known_secrets(candidates)


class JSONLogFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__()
        self._known_secrets = _known_secret_values()

    def format(self, record: logging.LogRecord) -> str:
        extra: dict[str, Any] = {
            key: value for key, value in record.__dict__.items() if key not in _STANDARD_LOG_RECORD_ATTRS
        }

        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": extra.pop("event", record.getMessage()),
            "correlationId": extra.pop("correlation_id", None),
            **extra,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        sanitized = sanitize_log_fields(payload, known_secrets=self._known_secrets)
        return json.dumps(sanitized, separators=(",", ":"), default=str)


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent-in-effect: attaches exactly one stdout handler to the
    named logger (app.core.logging_config.LOGGER_NAME), clearing any
    handlers already there first, so calling this more than once (e.g.
    module re-import in some test runner configurations) doesn't
    duplicate log lines.

    Deliberately does NOT touch the root logger or disable propagation:
    records logged via this logger still propagate to root as normal
    (Python logging's default behavior), which is what lets pytest's
    `caplog` fixture see them in tests without any special wiring here.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONLogFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
