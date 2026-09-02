"""Translates a genuinely unexpected exception into a safe API response,
while still logging full diagnostic detail server-side (see
docs/security-logging-design.md).

This only ever runs for an exception nothing else already handled -
every intentionally-raised HTTPException in this codebase (401/403/404/
409/413/422/429, all with hand-written, already-safe `detail` messages)
is matched by FastAPI's own, more specific HTTPException handler first
and never reaches this one. This is exclusively the catch-all for the
unanticipated case: a bug, a dependency failure (e.g. the database
connection dropping mid-request), anything that would otherwise surface
as a raw Python traceback.

Registered via app.add_exception_handler(Exception, ...) in app/main.py.
FastAPI wires a handler registered for the bare Exception class into
Starlette's ServerErrorMiddleware - which sits *outside* every
user-added middleware (including app.core.correlation.CorrelationIdMiddleware).
That means by the time this handler runs, an in-flight exception has
already unwound back out through CorrelationIdMiddleware's own
try/finally, which has already reset the correlation-id context var - so
this handler cannot rely on app.core.correlation.get_correlation_id() and
instead reads request.state.correlation_id directly, which
CorrelationIdMiddleware sets unconditionally before calling downstream
code, independent of the context var's lifetime.
"""

import logging

from fastapi import Request, status
from fastapi.responses import JSONResponse

from app.core.correlation import CORRELATION_ID_HEADER
from app.core.security_logging import log_security_event

SAFE_ERROR_DETAIL = "An internal error occurred. Please try again later."


async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    correlation_id = getattr(request.state, "correlation_id", None)

    log_security_event(
        "unhandled_exception",
        level=logging.ERROR,
        correlation_id=correlation_id,
        exc_info=exc,
        path=request.url.path,
        method=request.method,
        exception_type=type(exc).__name__,
        exception_message=str(exc),
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": SAFE_ERROR_DETAIL, "correlationId": correlation_id},
        headers={CORRELATION_ID_HEADER: correlation_id} if correlation_id else {},
    )
