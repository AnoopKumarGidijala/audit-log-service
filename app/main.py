from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.audit_events import router as audit_events_router
from app.api.routes.audit_verify import router as audit_verify_router
from app.api.routes.auth import router as auth_router
from app.api.routes.compliance import router as compliance_router
from app.api.routes.export import router as export_router
from app.api.routes.health import router as health_router
from app.api.routes.redaction import router as redaction_router
from app.api.routes.retention import router as retention_router
from app.core.body_size_limit import MaxBodySizeMiddleware
from app.core.config import settings
from app.core.correlation import CorrelationIdMiddleware
from app.core.error_handling import handle_unexpected_exception
from app.core.logging_config import configure_logging

configure_logging()

# No startup lifespan hook creating tables: schema changes are applied
# explicitly via Alembic (`alembic upgrade head`), not implicitly by the
# application on every boot - see README.md's "Setup" section and
# migrations/versions/. A prototype-only assumption this project
# deliberately no longer makes: an application process should be able to
# start (and, via /health/live, report itself live) without silently
# mutating schema as a side effect of starting.
app = FastAPI(title="Tamper-Evident Audit Log Service")

# Runs before request parsing (see app/core/body_size_limit.py). Added
# first deliberately: Starlette's add_middleware() makes the *last*-added
# middleware outermost (it runs first, wrapping everything registered
# before it) - adding this one first, and CORSMiddleware after, means
# CORSMiddleware ends up outermost and still adds correct CORS headers
# even to a request this middleware rejects, rather than that rejection
# looking like a generic connection failure to a browser-based caller.
app.add_middleware(MaxBodySizeMiddleware)

# Explicit CORS policy (see docs/defensive-limits-design.md), not
# whatever the absence of configuration would otherwise mean. Deny by
# default (settings.cors_allowed_origins is [] unless a deployment
# configures it): no browser-based cross-origin caller is allowed unless
# explicitly listed. allow_credentials is False - this API authenticates
# via a Bearer token header, not cookies, so cross-origin credentialed
# requests (and the stricter CORS rules they'd trigger) aren't needed.
# Methods/headers are enumerated rather than wildcarded, matching the
# same "explicit, not accidental" intent.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)

# Added last, so it's the outermost middleware (see the module-order
# comment above) - the request/correlation id must be established before
# anything else runs, so it's available to every log line for the
# request's entire lifetime, including ones emitted by the other
# middleware above (neither currently logs, but this ordering is what
# would make that correct if either ever did).
app.add_middleware(CorrelationIdMiddleware)

# Catches only exceptions nothing more specific already handled - see
# app/core/error_handling.py's own docstring for the full explanation of
# why this exists and how it interacts with the middleware above.
app.add_exception_handler(Exception, handle_unexpected_exception)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(audit_events_router)
app.include_router(audit_verify_router)
app.include_router(retention_router)
app.include_router(redaction_router)
app.include_router(export_router)
app.include_router(compliance_router)


@app.get("/")
def read_root():
    return {"service": "audit-log-service", "status": "running"}
