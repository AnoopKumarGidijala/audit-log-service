# Security Event Logging & Safe Error Responses

Basic operational visibility for security-sensitive operations, and a hard guarantee that an unexpected internal failure never leaks implementation details to an API client. Deliberately lightweight - stdlib `logging` plus a small custom formatter, writing structured JSON lines to stdout. No external logging platform, agent, or SDK: a real deployment collects stdout via its container/process supervisor and ships it wherever it needs to go, which is exactly why plain JSON-on-stdout is the right level of abstraction here rather than integrating a specific vendor's client library.

## 1. What gets logged

| Event | Where | Level | Notable fields |
|---|---|---|---|
| `auth.login.success` | `app/api/routes/auth.py` | INFO | `username`, `role` |
| `auth.login.failure` | `app/api/routes/auth.py` | WARNING | `username` (attempted) |
| `authz.denied` | `app/core/authorization.py` | WARNING | `username`, `role`, `required_roles`, `path`, `method` |
| `retention.applied` | `app/api/routes/retention.py` | INFO | `requested_by`, `archived_count`, `cutoff`, `retention_window_days` |
| `redaction.applied` | `app/api/routes/redaction.py` | INFO | `redacted_by`, `event_id`, `newly_redacted_fields` (names only), `redaction_event_id` |
| `export.performed` | `app/api/routes/export.py` | INFO | `requested_by`, `actor_id`/`resource_id` filters, `record_count` |
| `compliance.report_accessed` | `app/api/routes/compliance.py` | INFO | `requested_by`, filters, `record_count` |
| `chain.verification_failed` | `app/api/routes/audit_verify.py` | ERROR | `requested_by`, `record_id`, `violation_type`, `records_checked` |
| `unhandled_exception` | `app/core/error_handling.py` | ERROR | `path`, `method`, `exception_type`, `exception_message` |

`auth.login.failure` and `authz.denied` are WARNING - negative security signals worth being able to alert on, but not on their own evidence of anything broken. `chain.verification_failed` and `unhandled_exception` are ERROR - the two things this service can log that genuinely mean something is wrong (tamper evidence, and a bug/failure respectively). Everything else is INFO: routine, authorized use of a sensitive capability, logged for the operational record, not because it's suspicious.

**Chain verification is logged only on failure**, not on every call. A routine intact result isn't itself a security event, and this endpoint is already rate-limited (`docs/defensive-limits-design.md`) - logging every successful check would just be noise proportional to how often a legitimate auditor calls it.

This list matches exactly what was asked for - it's not a generic "log everything" framework. Extending it to a new event is a one-line `log_security_event(...)` call at the relevant point, using the same `dot.namespaced` event-name convention.

## 2. Structured format

Every log line is one JSON object with a fixed envelope (`app/core/logging_config.py:JSONLogFormatter`):

```json
{"timestamp":"2026-01-01T00:00:00+00:00","level":"WARNING","logger":"audit_log_service","event":"auth.login.failure","correlationId":"c1c1c1c1-...","username":"writer"}
```

`timestamp`/`level`/`logger`/`event`/`correlationId` are always present; every other key is event-specific, passed through `log_security_event`'s `**fields` (`app/core/security_logging.py`). Using structured fields rather than interpolating everything into a free-text message is what makes these lines mechanically queryable (`event = "authz.denied" AND username = "..."`) without regex-parsing prose.

## 3. Correlation id

`app/core/correlation.py:CorrelationIdMiddleware` establishes one id per request - adopted from an incoming `X-Request-ID` header if the caller sent one, otherwise a fresh UUID4 - and:

- makes it available to any code running during that request via a `contextvars.ContextVar`, which `log_security_event` reads automatically, so no call site needs to pass it explicitly;
- echoes it back on every response via the same header, so a client can reference a specific request when reporting an issue, without that id revealing anything internal;
- stashes it on `request.state.correlation_id` too, for the one place that can't rely on the context var - see §4.

Registered as the outermost middleware (`app/main.py`), so it's established before anything else runs and torn down only after everything else (including CORS and the body-size cap) has finished.

## 4. Safe error responses

`app/core/error_handling.py:handle_unexpected_exception`, registered via `app.add_exception_handler(Exception, ...)`. This is a catch-all for exceptions nothing more specific already handled - every intentionally-raised `HTTPException` in this codebase (401/403/404/409/413/422/429, each with a hand-written, already-safe `detail` message) is matched by FastAPI's own more specific handler first and never reaches this one. This exists exclusively for the genuinely unanticipated case: a bug, a dropped database connection mid-request, anything that would otherwise surface as a raw Python traceback (or, worse, as FastAPI's debug-mode traceback HTML page if `debug=True` were ever accidentally set).

On any such exception:
- the client gets a fixed, safe response: `{"detail": "An internal error occurred. Please try again later.", "correlationId": "..."}`, status 500 - no exception type, no message, no traceback.
- the server logs the full detail - exception type, message, and (via `exc_info`) traceback - through the same structured/sanitized pipeline as every other event, at ERROR.

**Why this handler reads `request.state.correlation_id` instead of the context var it otherwise always uses:** FastAPI wires a handler registered for the bare `Exception` class into Starlette's `ServerErrorMiddleware`, which sits *outside* every user-added middleware, including `CorrelationIdMiddleware`. By the time an in-flight exception reaches that outer layer, it has already unwound back out through `CorrelationIdMiddleware`'s own `try/finally` - which has already reset the context var. `request.state.correlation_id`, set unconditionally before `call_next()` is even invoked, doesn't have this lifetime problem, so the exception handler reads that directly instead.

## 5. Sanitization guarantee

`app/core/log_sanitizer.py`, applied by the formatter to the *entire* assembled log payload before serialization - not opt-in per call site, and not bypassable by a call site that forgets to sanitize its own fields. Two independent passes:

1. **Key-name-based.** Any field whose name contains `password`, `secret`, `token`, `jwt`, `authorization`, `signing_key`, `api_key`, or `credential` (case-insensitive) has its value replaced outright, regardless of what the value actually is. Catches `password_hash`, `access_token`, a header literally named `Authorization`, etc.
2. **Value-shape/content-based.** Independent of key name: any string value that is either shaped like a JWT (three dot-separated base64url segments, matched with a regex) or contains one of the deployment's own actual secret values verbatim (`Settings.secret_key`, and the database password parsed out of `Settings.database_url`) is also redacted. This is the safety net for a secret surfacing somewhere a key-name check can't anticipate - most concretely, inside a raw exception message from a database driver, which is exactly the kind of string `unhandled_exception`'s `exception_message` field can contain.

Both passes are recursive (into nested dicts/lists) and apply to the log *message* field too, not just structured extras - a secret embedded in prose is caught the same as one under a suspicious key.

**What this deliberately does not attempt:** general-purpose PII scrubbing, or redacting business data (an `actorId`, a `resourceId`, a redacted-field *name* like `"accountNumber"`) - none of that is a credential, and this service's whole purpose is recording exactly that kind of identifying information in its own audit trail already. The guarantee here is scoped precisely to what was asked: passwords, JWTs, signing secrets, and (by simple discipline at the one call site that could ever touch them - `redaction.applied` logs field *names*, never `event.payload[field]`'s value) the original values of redacted fields.

## 6. Testing

`tests/test_security_logging.py` - each of the eight events above is actually emitted (via `caplog`, asserting `record.event`/`record.<field>` on the captured `LogRecord`, not the serialized JSON - that's a structural check on *what* gets logged), plus that the `X-Request-ID` response header is present, that it echoes an id the caller supplied, and that it differs across two independent requests when the caller doesn't supply one.

`tests/test_log_sanitization.py` - direct unit tests against `JSONLogFormatter`/`log_sanitizer` (constructing `LogRecord`s or calling `sanitize_log_fields` directly, no HTTP layer involved): a field named `password`/`token`/`secret`/etc. is redacted regardless of value; a JWT-shaped string is redacted regardless of its key name; a value containing a known configured secret verbatim is redacted; ordinary business fields (`username`, `actorId`, a redacted field *name*) pass through unchanged. Plus one end-to-end test confirming a real login response's JWT never appears verbatim in a captured log line for that request.

`tests/test_safe_error_responses.py` - a route wired to deliberately raise an unexpected, non-`HTTPException` error confirms the client receives the fixed safe response (no exception type/message/traceback in the body) while the *full* detail is still visible server-side via `caplog`; existing intentional error paths (404/422/etc.) are confirmed unaffected by the new catch-all handler.

## 7. Trade-offs and limitations

- **No log rotation, shipping, or retention policy** - this is what "no external logging platform" means taken to its natural conclusion. Whatever consumes this service's stdout (a container runtime, `systemd`, a process supervisor) owns that; not this codebase's concern.
- **In-process only, same limitation as rate limiting** (`docs/defensive-limits-design.md` §4): multiple instances each write their own independent stream. Correlating a request across instances is why the correlation id is in the response header - a caller (or a fronting proxy) can propagate `X-Request-ID` and a log aggregator downstream can group on it, but this service doesn't do that aggregation itself.
- **The known-secrets content scan is a safety net, not the primary defense.** It only catches a secret value that's at least 8 characters and appears byte-for-byte; it will not catch a *transformation* of a secret (partially truncated, re-encoded, etc.). Call-site discipline (never intentionally logging a password/token) remains the primary guarantee; this catches the accidental case.
