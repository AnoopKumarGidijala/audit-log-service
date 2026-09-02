"""Request/correlation identifier propagation (see
docs/security-logging-design.md). One id per request, generated (or
adopted from an incoming request) at the very edge of the app and made
available two ways:

- via a `contextvars.ContextVar`, so any code running during that
  request - a route handler, a service function, a log call several
  layers deep - can read it without threading it through every function
  signature (app.core.security_logging.log_security_event reads it
  automatically).
- via `request.state.correlation_id`, for the one place that can't rely
  on the context var: the global exception handler
  (app/core/error_handling.py), which runs *outside* this middleware once
  an exception has propagated past it (see that module's own docstring
  for why the context var alone isn't enough there).
"""

import contextvars
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

CORRELATION_ID_HEADER = "X-Request-ID"

_correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


def get_correlation_id() -> str | None:
    return _correlation_id_var.get()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Adopts an incoming X-Request-ID if the caller sent one (so a
    request can be traced across services that all honor the header),
    otherwise generates a fresh one. Echoes it back on the response
    either way, so a client always has something to reference when
    reporting an issue.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(CORRELATION_ID_HEADER)
        correlation_id = incoming if incoming else str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        token = _correlation_id_var.set(correlation_id)
        try:
            response = await call_next(request)
        finally:
            _correlation_id_var.reset(token)

        response.headers[CORRELATION_ID_HEADER] = correlation_id
        return response
