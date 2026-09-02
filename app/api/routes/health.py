"""Basic health endpoints, deliberately split into two so a caller (a
load balancer, an uptime check, a human) can distinguish "the application
process is up and can handle HTTP requests at all" from "the application
AND its database dependency are both available" - two genuinely
different failure modes that call for different responses (e.g. don't
restart the process just because the database is briefly unreachable).

Unauthenticated, and not rate-limited or logged as security events (see
docs/defensive-limits-design.md, docs/security-logging-design.md) -
health checks are typically called frequently by infrastructure that has
no credentials and isn't itself a security-relevant actor; logging every
call would just be noise.
"""

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health/live")
def liveness() -> dict:
    """The process is running and able to handle a request at all.
    Deliberately checks nothing external - a database outage must not
    make this report unhealthy, since that's a different problem
    (/health/ready below) with a different correct response (don't kill
    and restart a perfectly healthy application process over a database
    blip).
    """
    return {"status": "ok"}


@router.get("/health/ready")
def readiness(db: Session = Depends(get_db)) -> JSONResponse:
    """The application AND its database dependency are both available.
    Runs the cheapest possible real query (SELECT 1) - enough to prove
    the connection pool can actually reach and query the database, not
    just that a Session object could be constructed (which never touches
    the network on its own).
    """
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        # Caught and translated the same way app/core/error_handling.py
        # handles any other unexpected failure: a safe, fixed response
        # here, never a raw driver/DB error message. This is anticipated
        # (a genuinely down database is an expected failure mode for this
        # endpoint to report), so it's handled locally rather than
        # falling through to that global catch-all.
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unavailable", "database": "unreachable"},
        )
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ok", "database": "reachable"})
