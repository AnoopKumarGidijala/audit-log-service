"""Simple in-memory rate limiting (see docs/defensive-limits-design.md).

Deliberately in-process, sliding-window, thread-safe via a single lock -
appropriate for a single-instance prototype, and nothing more. This
CANNOT correctly rate-limit a caller across multiple instances of this
service running behind a load balancer: each process has its own
independent counters, so a client could get up to (limit * instance
count) requests through before any single instance would reject them. A
real distributed deployment needs either a shared backing store (e.g.
Redis, so every instance sees the same counters) or - usually simpler and
more robust - rate limiting enforced at the gateway/reverse-proxy layer
in front of every instance. Not built here: out of scope for a prototype,
and the right answer depends on the actual deployment topology.
"""

import threading
import time
from collections import deque

from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings
from app.core.security import CurrentUser, get_current_user


class InMemoryRateLimiter:
    """Fixed-key sliding-window limiter: at most max_requests per key
    within any trailing window_seconds window. Each key (e.g. a username
    or client IP) is tracked independently via its own deque of recent
    request timestamps; old timestamps are pruned lazily on each check.

    No eviction of keys that stop being used - acceptable for a
    prototype's expected lifetime and key cardinality (a handful of
    configured users, or a modest number of client IPs), but a long-lived
    production process would eventually want to prune stale keys.
    """

    def __init__(self, *, max_requests: int, window_seconds: int):
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str) -> bool:
        """Records this attempt and returns whether it's allowed. Every
        call counts against the limit, whether or not the caller goes on
        to do anything else with the result - there is no separate
        "peek" that doesn't consume budget.
        """
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) >= self._max_requests:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        """Clears all tracked state. Not used by application code - only
        by tests, which need a clean slate between test functions since
        this limiter is a process-wide singleton (see tests/test_rate_limiting.py).
        """
        with self._lock:
            self._hits.clear()


login_rate_limiter = InMemoryRateLimiter(
    max_requests=settings.login_rate_limit_max_attempts,
    window_seconds=settings.login_rate_limit_window_seconds,
)

sensitive_endpoint_rate_limiter = InMemoryRateLimiter(
    max_requests=settings.sensitive_rate_limit_max_requests,
    window_seconds=settings.sensitive_rate_limit_window_seconds,
)

_RATE_LIMIT_ERROR_DETAIL = "Too many requests. Please wait before trying again."


def enforce_login_rate_limit(request: Request) -> None:
    """Limits repeated authentication attempts (see
    docs/defensive-limits-design.md) - keyed by client IP, since a login
    attempt is by definition not yet authenticated, so there is no
    username to key on until credentials are actually verified. Runs as a
    dependency, before the route body calls authenticate_user(), so an
    attempt over the limit never even reaches password verification.
    """
    client_host = request.client.host if request.client else "unknown"
    if not login_rate_limiter.check(client_host):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=_RATE_LIMIT_ERROR_DETAIL)


def enforce_sensitive_endpoint_rate_limit(current_user: CurrentUser = Depends(get_current_user)) -> None:
    """Limits high-frequency requests to computationally expensive,
    unpaginated endpoints - chain verification, export, and compliance
    reporting (see docs/defensive-limits-design.md and each of those
    routes). Keyed by authenticated username, not IP: the concern here is
    one caller hammering an expensive query, not anonymous abuse (these
    endpoints already require authentication - see
    app.core.authorization.require_roles), so the caller's identity is
    the more precise key.
    """
    if not sensitive_endpoint_rate_limiter.check(current_user.username):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=_RATE_LIMIT_ERROR_DETAIL)
