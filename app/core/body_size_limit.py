"""A coarse, whole-request body size cap, enforced before the body is
parsed at all (see docs/defensive-limits-design.md). Complements the
`payload`-field-specific checks in app/core/payload_limits.py, which can
only run after FastAPI has already fully parsed the request body into
Python objects - too late to prevent the cost of parsing a single huge
request. This middleware rejects an oversized request before that
parsing ever happens.

Deliberately simple, and documented as such: it only checks the
Content-Length header. A client using chunked transfer encoding (no
Content-Length) bypasses this check entirely, and would only be caught
downstream by the payload-level checks (if the oversized data even ends
up in a JSON-parseable field) - not a hard guarantee, a best-effort
prototype-level defense against the common case of an oversized request.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_413_CONTENT_TOO_LARGE

from app.core.config import settings


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None
            if declared_size is not None and declared_size > settings.max_request_body_bytes:
                return JSONResponse(
                    status_code=HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "detail": (
                            f"Request body of {declared_size} bytes exceeds the maximum of "
                            f"{settings.max_request_body_bytes} bytes."
                        )
                    },
                )
        return await call_next(request)
