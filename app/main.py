from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.audit_events import router as audit_events_router
from app.api.routes.audit_verify import router as audit_verify_router
from app.api.routes.auth import router as auth_router
from app.api.routes.compliance import router as compliance_router
from app.api.routes.export import router as export_router
from app.api.routes.redaction import router as redaction_router
from app.api.routes.retention import router as retention_router
from app.core.body_size_limit import MaxBodySizeMiddleware
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No migration tool is set up yet (see session notes); creating tables
    # on startup if they don't already exist is a prototype-scoped stand-in.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Tamper-Evident Audit Log Service", lifespan=lifespan)

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
