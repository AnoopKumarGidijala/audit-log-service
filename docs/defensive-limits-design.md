# Defensive Limits

Basic abuse-resistance limits appropriate for this prototype, added after reviewing the API's boundaries: payload structure limits, a whole-request body size cap, rate limiting on authentication and on computationally expensive endpoints, and an explicit CORS policy. None of this changes the hash-chain, authorization, or idempotency behavior built in earlier increments - it sits in front of it, as request-level validation and throttling.

## 1. Centralized configuration

Every threshold here is a field on `Settings` (`app/core/config.py`), not a constant hardcoded in a route handler - so the full set of limits this service enforces is visible in one place, and adjustable per deployment via environment variables without touching code. See `.env.example` for the full list and their built-in defaults.

## 2. Payload structure limits

`AuditEventCreate` (`app/schemas/audit_event.py`) enforces, on every `POST /audit/events`:

- **Identity field length** (`eventType`/`actorId`/`resourceType`/`resourceId`): `max_length` matching the corresponding `AuditEvent` DB column size exactly (100/255/100/255 - see `app/db/models.py`). Previously these fields had a `min_length` but no upper bound at all, so an overlong value would sail through Pydantic validation and only fail at the database with a raw `value too long for type character varying(N)` error - a 500, not a clean 422. Closing that gap was as much a correctness fix as a defensive limit.
- **Payload byte size** (`MAX_PAYLOAD_BYTES`, default 16 KiB): the `payload` field's own serialized size, measured after parsing (`app/core/payload_limits.py:compute_payload_byte_size`).
- **Payload nesting depth** (`MAX_PAYLOAD_DEPTH`, default 10): how many levels of nested dict/list `payload` may contain (`compute_payload_depth`). Guards against both accidental deeply-recursive client bugs and deliberate structures crafted to be expensive to walk (chain verification, export, and compliance reporting all eventually serialize every record's `payload` back out).
- **String value length** (`MAX_PAYLOAD_STRING_LENGTH`, default 2000 characters): the longest any single string - a value or a dict key - anywhere in `payload` may be (`payload_has_overlong_string`).

All three payload-content functions are pure and take their thresholds as explicit parameters (no implicit dependency on `Settings` or Pydantic) - the same style already used by `app/services/hashing.py`, and independently unit-testable without a running app.

**A real limitation, documented rather than silently accepted:** these checks run inside a Pydantic field validator, which only sees the payload *after* FastAPI has already fully parsed the JSON request body into Python objects. They cannot prevent the cost of parsing a single maliciously huge request in the first place - that's what the body-size middleware below is for.

## 3. Whole-request body size cap

`app/core/body_size_limit.py:MaxBodySizeMiddleware`, applied to every request via `app.add_middleware()` in `app/main.py`. Checks the `Content-Length` header against `MAX_REQUEST_BODY_BYTES` (default 32 KiB - larger than `MAX_PAYLOAD_BYTES` to leave room for the rest of the JSON envelope) and rejects with `413` before the body is read or parsed at all.

**Deliberately simple, and documented as such**: this only checks a header. A client using chunked transfer encoding without `Content-Length` bypasses it entirely (falling back on the payload-level checks above, if the oversized data even lands in a JSON-parseable field). This is a best-effort, prototype-appropriate defense against the common case, not a hard guarantee - a production deployment fronted by a reverse proxy or gateway would typically also enforce a body size limit there, before a request even reaches this service.

## 4. Rate limiting

`app/core/rate_limit.py`. Two independent limiters, both a simple in-memory, sliding-window implementation (`InMemoryRateLimiter`): a thread-safe dict of per-key timestamp deques, guarded by one `threading.Lock`, with old timestamps pruned lazily on each check.

- **Login attempts** (`enforce_login_rate_limit`, used by `POST /auth/token`): keyed by client IP (there's no authenticated identity yet at the point of a login attempt), default 5 attempts per 60-second window. Every attempt counts against the limit regardless of outcome (right password or wrong) - the goal is bounding the rate of attempts, not just failures. Runs as a dependency *before* the route body calls `authenticate_user()`, so a request over the limit is rejected before spending any Argon2 verification cost.
- **Sensitive-endpoint requests** (`enforce_sensitive_endpoint_rate_limit`, used by `GET /audit/verify`, `GET /audit/export`, and `GET /audit/compliance/account-access`): keyed by authenticated username, default 10 requests per 60-second window. These three were chosen because they share the same expensive shape: each does an unpaginated, effectively full-table-scan-style query (`list_all_events`/`list_events_including_archived`) and serializes every matching record back out - unlike `GET /audit/events`, which is paginated and bounded per request by design (see `docs/architecture.md`). Keyed by username, not IP, since these endpoints already require authentication (`auditor`/`admin` - see `docs/authorization-design.md`) and the concern is one identified caller hammering an expensive query, not anonymous traffic.

Both return `429 Too Many Requests` with the same generic message on rejection.

### Why in-memory, and what production would need instead

This is explicitly a **single-instance, single-process** rate limiter. Its counters live in a plain Python dict inside one running process - there is no shared state between multiple instances of this service. Run two instances behind a load balancer and each one independently allows up to the configured limit, so a client could get roughly `limit × instance count` requests through before being reliably throttled. This is an accepted, documented limitation for a prototype, not an oversight:

- A **shared backing store** (most commonly Redis, using something like a sliding-window or token-bucket algorithm implemented with Redis's atomic operations) would let every instance see and update the same counters.
- **Gateway/reverse-proxy-level enforcement** (an API gateway, a reverse proxy like nginx/Envoy with rate-limiting configured, or a managed service in front of the deployment) is usually the simpler and more robust answer in practice - it centralizes the concern outside the application entirely, works uniformly across every instance without any application code change, and is standard practice for this exact problem.

Neither is built here - which one fits depends on the actual deployment topology, which isn't decided for this prototype.

### Testing implication

The rate limiters are process-wide singletons that live for the lifetime of the test session, not reset between tests. Most of this suite calls `POST /auth/token` and the three sensitive endpoints dozens of times across many test functions (all via Starlette's `TestClient`, which sends every request from the same fake client host) - without accounting for this, unrelated tests would start failing with `429`s once the real limits were exhausted, long before any test actually about rate limiting ran. `tests/conftest.py`'s shared `client` fixture installs a FastAPI dependency override making both rate-limit dependencies no-ops for every test that doesn't care about them; `tests/test_rate_limiting.py` is the one place that uses the real, non-overridden dependencies (via its own `real_client` fixture) and explicitly resets the limiters' state between its own test functions.

## 5. CORS policy

`app/main.py`, `CORSMiddleware`, configured explicitly rather than left unconfigured:

- `allow_origins`: `Settings.cors_allowed_origins`, an empty list by default - **deny by default**. No browser-based cross-origin caller is allowed unless a deployment explicitly lists its origin(s) via `CORS_ALLOWED_ORIGINS`. This is a deliberate policy statement, not the same thing as simply never adding `CORSMiddleware` at all (which would also block cross-origin browser requests today, but silently, as an accident of omission rather than a decision anyone could point to or intentionally change).
- `allow_credentials=False`: this API authenticates via a `Bearer` token in the `Authorization` header, not cookies - cross-origin credentialed requests (and the stricter rules the CORS spec imposes once `allow_credentials=True`, including that `allow_origins` can no longer be `"*"`) aren't needed.
- `allow_methods`/`allow_headers`: enumerated explicitly (`GET`, `POST`; `Authorization`, `Content-Type`, `Idempotency-Key`) rather than wildcarded - matching exactly what this API's routes actually use, again favoring an explicit, auditable policy over a permissive default.

## 6. Trade-offs and limitations

- **In-memory rate limiting doesn't survive a process restart** (counters reset to zero) or work across multiple instances - see §4.
- **No `Retry-After` header** on a `429` response - the client knows to back off, not precisely how long for. Skipped for simplicity; the window sizes are short enough (60 seconds by default) that this isn't a significant UX gap for a prototype.
- **The body-size middleware only checks `Content-Length`** - see §3's own caveat.
- **Payload limits apply only to `POST /audit/events`**, not to every request schema in the app (e.g. redaction's `fields`/`reason`, or query parameters elsewhere) - scoped to where the review that prompted this work was focused: the audit event creation boundary specifically, which is also the one endpoint accepting genuinely free-form, caller-controlled structured content.
