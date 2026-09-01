from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes.audit_events import router as audit_events_router
from app.api.routes.audit_verify import router as audit_verify_router
from app.api.routes.auth import router as auth_router
from app.api.routes.redaction import router as redaction_router
from app.api.routes.retention import router as retention_router
from app.db.base import Base
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No migration tool is set up yet (see session notes); creating tables
    # on startup if they don't already exist is a prototype-scoped stand-in.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Tamper-Evident Audit Log Service", lifespan=lifespan)

app.include_router(auth_router)
app.include_router(audit_events_router)
app.include_router(audit_verify_router)
app.include_router(retention_router)
app.include_router(redaction_router)


@app.get("/")
def read_root():
    return {"service": "audit-log-service", "status": "running"}
