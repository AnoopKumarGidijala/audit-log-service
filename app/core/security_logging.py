"""The one entry point route handlers use to emit a structured
security-event log line (see docs/security-logging-design.md). A thin
wrapper over stdlib `logging`, not a new logging framework - its only
job is making the two things every one of these log calls needs easy to
get right by construction: the request's correlation id, and passing
fields through `extra=` in the shape app.core.logging_config.JSONLogFormatter
expects.

Sanitization (app/core/log_sanitizer.py) happens in the formatter, not
here - this module doesn't need to know anything about what's sensitive;
that guarantee applies uniformly to every log record regardless of which
code path produced it.
"""

import logging

from app.core.correlation import get_correlation_id
from app.core.logging_config import LOGGER_NAME

_logger = logging.getLogger(LOGGER_NAME)


def log_security_event(
    event: str,
    *,
    level: int = logging.INFO,
    correlation_id: str | None = None,
    exc_info: bool | BaseException | None = None,
    **fields: object,
) -> None:
    """Emits one structured log line for a security-relevant event (see
    docs/security-logging-design.md for the full list this service emits
    and why). `event` should be a short, stable, dot-namespaced name
    (e.g. "auth.login.failure") - it's the field code/log consumers key
    on, not free-text prose.

    correlation_id: normally omitted - the current request's id is read
    automatically from app.core.correlation.get_correlation_id(). Pass it
    explicitly only from a context where that automatic lookup isn't
    reliable, which today is exactly one place: app/core/error_handling.py's
    global exception handler (see its own docstring for why).

    exc_info: pass the caught exception (or True, inside an `except`
    block) to include its traceback in the server-side log line - see
    app/core/error_handling.py's use of this for the one place a full
    traceback is genuinely useful. The traceback text itself still passes
    through the same sanitization as every other field (see
    app/core/logging_config.py:JSONLogFormatter), so this is safe even if
    the traceback happens to include a sensitive value.

    `event` is passed to the underlying logging call as both the record's
    message *and* an explicit `event` extra field - the latter is what
    app.core.logging_config.JSONLogFormatter actually reads, and what
    tests assert on directly (record.event), rather than relying on
    LogRecord.getMessage()'s `%`-style formatting semantics, which
    `event` (an arbitrary event-name string, not a format string) was
    never meant to go through.
    """
    _logger.log(
        level,
        event,
        exc_info=exc_info,
        extra={
            "event": event,
            "correlation_id": correlation_id if correlation_id is not None else get_correlation_id(),
            **fields,
        },
    )
