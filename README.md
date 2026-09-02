# Audit Log Service

A tamper-evident audit log service that records application and system events in a way that allows their integrity to be independently verified after the fact.

## Contents

- [What this service does](#what-this-service-does)
- [Architecture](#architecture)
- [Authentication and authorization](#authentication-and-authorization)
- [Audit hash-chain design](#audit-hash-chain-design)
- [Retention and redaction](#retention-and-redaction)
- [Verifiable export](#verifiable-export)
- [Compliance reporting](#compliance-reporting)
- [Other request-boundary behavior](#other-request-boundary-behavior)
- [API overview](#api-overview)
- [Setup](#setup)
- [Testing](#testing)
- [Requirement-to-test traceability](#requirement-to-test-traceability)
- [Prototype limitations](#prototype-limitations)
- [Production improvements](#production-improvements)
- [Documentation index](#documentation-index)

## What this service does

Client applications and internal systems submit **audit events** — "who did what, to which resource, when" — through an authenticated write API. Every event is appended to a single, ordered, tamper-evident log: each stored record carries a SHA-256 hash of its own content plus the hash of the record immediately before it, forming a **hash chain**. A verification endpoint walks the whole chain and reports whether it's still intact, and — if not — exactly which record was tampered with and how.

On top of that core (Scenario A of the original assignment), the service adds **retention** (archiving old records without breaking the chain), **structured redaction** (removing sensitive `payload` fields from a record while keeping the rest of it, and the chain, verifiable), **verifiable bulk export** (a self-contained, independently-checkable bundle of records for a given actor or resource), and a **compliance report** over account-access events (Scenario B and C). All of it sits behind role-based authorization, hardened JWT authentication, and a set of basic abuse-resistance limits appropriate for a prototype — see the sections below.

## Architecture

```
Client -> FastAPI API layer -> Service layer -> Repository layer -> PostgreSQL
```

A small, layered FastAPI service — no message queues, caches, or microservices. The API layer handles HTTP routing, request/response schemas, authentication, and authorization; the service layer holds business logic (hashing, chaining, verification, retention/redaction/export/compliance rules); the repository layer is the only place that talks to the database. Full detail, including the concurrency design that keeps the hash chain a single linear sequence under concurrent writes (a PostgreSQL advisory lock), is in [`docs/architecture.md`](docs/architecture.md).

## Authentication and authorization

**Authentication:** `POST /auth/token` exchanges a username/password for a JWT Bearer token; every other endpoint (except the two health endpoints) requires `Authorization: Bearer <token>`. Credentials come from a small configured user store (`Settings.auth_users`, one JSON array in the `AUTH_USERS` environment variable) — not an external identity provider. Passwords are stored as Argon2id hashes, never plaintext. The JWT itself is hardened: a fixed, non-configurable signing algorithm (HS256 - can't be relaxed via env var), validated issuer/audience/expiry, and the application refuses to start at all with a weak or default `SECRET_KEY`. Every authentication failure — wrong password, unknown user, expired/malformed/forged token — returns the same generic response, so a client (or an attacker) can't distinguish *why* a request was rejected. Full design: [`docs/auth-hardening-design.md`](docs/auth-hardening-design.md).

**Authorization** is role-based and kept as a separate concern from authentication in code (`app/core/security.py` resolves *who* is calling; `app/core/authorization.py` decides *whether* their role may do what the endpoint requires). Four roles:

| Role | Can do |
|---|---|
| `writer` | Create audit events |
| `reader` | Query audit events — scoped to their own tenant only |
| `auditor` | Everything `reader` can, plus verify the chain, export, and view compliance reports — across every tenant |
| `admin` | Everything, including retention and redaction |

A `reader`'s queries are unconditionally restricted to their own tenant, even against an explicit filter guessing at another tenant's data; `auditor`/`admin` read across all tenants by design — their whole purpose is cross-tenant oversight, made explicit in the code as a single, deliberate branch rather than an accidentally-missing filter. Full design, the tenant-scoping rationale, and the complete endpoint/role table: [`docs/authorization-design.md`](docs/authorization-design.md).

## Audit hash-chain design

Every stored event carries `previousHash` (the `eventHash` of the record immediately before it) and `eventHash` (SHA-256 over the record's own canonical content, including `previousHash`). The first record in the log uses a fixed all-zeros genesis value in place of a real `previousHash`. Canonicalization (`app/services/hashing.py:canonicalize()`) sorts keys and uses compact separators, so the same logical event always produces the same hash regardless of dict ordering.

`GET /audit/verify` walks every record in insertion order, recomputing each one's hash from its current stored content and checking it against both the stored `eventHash` and the previous record's `eventHash`. It stops at the first inconsistency and reports the violating record's ID and the violation type (`EVENT_HASH_MISMATCH` — a record's own content was changed; `PREVIOUS_HASH_MISMATCH` — the link between two individually-consistent records is broken; plus two redaction-specific types, see below).

Concurrent writes are serialized with a PostgreSQL transaction-level advisory lock (`pg_advisory_xact_lock`), so two simultaneous append requests can never both read the same "last record" and fork the chain — proven with real concurrent requests against a real database, not simulated, in `tests/test_append_concurrency.py`.

## Retention and redaction

**Retention** (`POST /audit/retention/apply`, `admin` only) archives every record older than a configured window (`RETENTION_WINDOW_DAYS`) by setting a nullable `archivedAt` timestamp — never physical deletion. `archivedAt` is deliberately outside the hashed content, so archiving a record can never change its `eventHash`; chain verification keeps working across archived records with no special-casing, while everyday queries (`GET /audit/events`) exclude them by default.

**Redaction** (`POST /audit/events/{id}/redact`, `admin` only) replaces a named `payload` field's value with a fixed marker, without ever recomputing the record's `eventHash`. To keep verification meaningful for everything *except* the redacted field, redaction appends a companion audit event carrying a commitment hash over the record's full post-redaction content; verification checks a redacted record's current content against that commitment instead of skipping the check entirely — so tampering with any other field, or replacing the redaction marker with something else, is still caught (`REDACTED_CONTENT_MISMATCH`), and a forged "redacted" flag with no genuine companion event is caught too (`REDACTION_COMMITMENT_MISSING`). Full design and the alternatives considered (field-level hashing, crypto-shredding): [`docs/redaction-design.md`](docs/redaction-design.md).

## Verifiable export

`GET /audit/export?actorId=...` or `?resourceId=...` (`auditor`/`admin`, at least one filter required) returns a self-contained JSON bundle of matching records, each keeping its real `previousHash`/`eventHash`, plus a `manifestHash` — a commitment over exactly which records, in what order, the bundle contains. A filtered subset generally isn't chain-adjacent (the records weren't necessarily next to each other in the real chain), so the bundle can't simply be re-verified with the normal chain-verification recipe; a recipient instead recomputes each record's own hash and the manifest hash from the bundle's JSON alone, which proves the bundle hasn't been altered since export but — stated explicitly, not glossed over — cannot prove *completeness* (that no matching record was omitted) without also querying the live service. Full design and the exact verification recipe: [`docs/export-design.md`](docs/export-design.md).

## Compliance reporting

`GET /audit/compliance/account-access` (`auditor`/`admin`) reports every event recorded against `resourceType="ACCOUNT"`, optionally filtered by `actorId`/`resourceId`/`from`/`to`. The original assignment requirement ("regulators need to be able to audit access to client account data") was ambiguous; the specific, narrow interpretation this prototype implements — and the open questions that remain genuinely unresolved for a real regulatory deployment — are documented explicitly in [`docs/requirements.md`](docs/requirements.md)'s Scenario C section, so the ambiguity doesn't silently turn into an ambiguous implementation.

## Other request-boundary behavior

A few things that apply broadly rather than to one specific feature:

- **Idempotent writes:** `POST /audit/events` accepts an optional `Idempotency-Key` header, scoped per `(authenticated caller, key)`. A retry with the same key and identical content replays the original event instead of appending a duplicate; the same key reused with different content is rejected (`409`). This rides entirely on the same advisory lock used for chain-fork prevention — no second locking mechanism. Full design: [`docs/idempotency-design.md`](docs/idempotency-design.md).
- **Defensive limits:** payload size/nesting-depth/string-length limits and identity-field length caps on event creation (`422`), a whole-request body size cap checked before parsing (`413`), in-memory rate limiting on login attempts and on the computationally expensive `verify`/`export`/`compliance` endpoints (`429`), and an explicit deny-by-default CORS policy. Every threshold is a `Settings` field, not a constant scattered in a route handler. Full design, including why the rate limiter is explicitly single-instance-only: [`docs/defensive-limits-design.md`](docs/defensive-limits-design.md).
- **Structured security logging:** login success/failure, authorization denial, retention/redaction execution, export, compliance access, and chain-verification failure are all logged as structured JSON lines to stdout, each carrying an automatic request/correlation ID (`X-Request-ID`, echoed on every response). A sanitization pass guarantees no log line ever contains a password, JWT, signing secret, or a redacted field's original value. Any genuinely unexpected internal failure is translated into a fixed, detail-free `500` response to the client while the full diagnostic detail is still logged server-side. Full design: [`docs/security-logging-design.md`](docs/security-logging-design.md).

## API overview

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /auth/token` | — | Exchange credentials for a JWT. |
| `POST /audit/events` | `writer`, `admin` | Append a new audit event. |
| `GET /audit/events` | `reader`, `auditor`, `admin` | Query events with filters and pagination. |
| `GET /audit/verify` | `auditor`, `admin` | Verify the hash chain. |
| `POST /audit/retention/apply` | `admin` | Archive records older than the retention window. |
| `POST /audit/events/{id}/redact` | `admin` | Redact named `payload` fields on a record. |
| `GET /audit/export` | `auditor`, `admin` | Export a verifiable bundle for an actor/resource. |
| `GET /audit/compliance/account-access` | `auditor`, `admin` | Report on `ACCOUNT`-resource events. |
| `GET /health/live` | — | Liveness — the process can handle a request. |
| `GET /health/ready` | — | Readiness — the database is also reachable. |

Interactive, always-current API docs (generated from the actual request/response schemas) are available at `/docs` once the app is running.

## Setup

Prerequisites: Docker, and Python 3 with a virtual environment.

1. **Configure the environment.** Copy `.env.example` to `.env` and adjust values for your machine (generate a real `SECRET_KEY`, pick your own local Postgres credentials, etc. - see the comments in the file itself).

   ```bash
   cp .env.example .env
   ```

2. **Start the development database:**

   ```bash
   docker compose up -d
   ```

3. **Install the pinned Python dependencies**, ideally into a virtual environment:

   ```bash
   pip install -r requirements.txt
   ```

   Versions are pinned to exactly what this project is tested against (see the comment at the top of `requirements.txt`), so this install is reproducible rather than picking up whatever the latest compatible release happens to be on a given day.

4. **Apply database migrations.** The application does not create tables automatically on startup - schema changes are applied explicitly via [Alembic](https://alembic.sqlalchemy.org/), the standard SQLAlchemy migration tool:

   ```bash
   alembic upgrade head
   ```

   This is the same command a fresh environment (a new developer's machine, a new deployment) runs to go from an empty database to the current schema - `migrations/versions/` contains one migration, `7ab42bede884_initial_schema.py`, which represents the complete schema as of this point in the project's history. Future schema changes are added as new migrations the same way (see "Changing the schema" below), not by editing that first one.

5. **Run the application:**

   ```bash
   uvicorn app.main:app --reload
   ```

   `GET /health/live` confirms the process is up; `GET /health/ready` additionally confirms the database is reachable (see "API overview" above). Interactive API docs are then available at `http://127.0.0.1:8000/docs`.

### Changing the schema

After changing a model in `app/db/models.py`, generate a new migration rather than hand-writing one from scratch, then review the generated file before committing it (autogenerate is reliable for the common cases - new tables/columns/indexes - but doesn't reliably detect everything, e.g. some constraint renames):

```bash
alembic revision --autogenerate -m "describe the change"
```

`tests/test_migrations.py` fails the test suite if a model and the applied migrations ever drift apart - a model changed without a matching migration (or vice versa) is caught there, not discovered later against a real database.

## Testing

The test suite runs against a dedicated, disposable PostgreSQL database - see `docker-compose.test.yml` and `.env.test` (committed; it holds only throwaway test credentials, never real secrets). This is a separate container, volume, port, and database name from the development database in `docker-compose.yml`/`.env`, so running tests can never touch a developer's normal local database. `tests/conftest.py` enforces this at two independent levels: it always loads `.env.test`, regardless of what's already set in your shell environment, and it refuses to run at all if the configured database's name doesn't end in `_test`.

Prerequisites: Docker, and the Python dependencies installed (`pip install -r requirements.txt`, ideally in a virtual environment).

1. **Start the test dependency:**

   ```bash
   docker compose -f docker-compose.test.yml up -d
   ```

2. **Run the complete test suite:**

   ```bash
   pytest
   ```

3. **Run the suite with coverage** (line and branch coverage; fails the command if total coverage drops below 70%, per `pyproject.toml`):

   ```bash
   pytest --cov=app --cov-report=term-missing
   ```

4. **Clean up the test environment:**

   ```bash
   docker compose -f docker-compose.test.yml down -v
   ```

No other setup is required - `tests/conftest.py` applies the same Alembic migrations described in "Setup" above automatically (against the dedicated test database only) the first time the suite runs, and also asserts the applied migrations still match `app/db/models.py` exactly (`tests/test_migrations.py`), so schema drift is caught here, not in a real deployment.

As of this writing the suite has over 230 tests across the areas below, at around 99% statement and branch coverage — comfortably above the required 70% floor `pyproject.toml` enforces.

## Requirement-to-test traceability

IDs match `docs/requirements.md`, which carries the full text of each requirement and its "Decided" design notes. Cross-cutting hardening added beyond the original Scenario A/B/C requirements (authorization, auth hardening, idempotency, defensive limits, security logging, migrations) isn't part of this table — see `docs/assumptions.md` for that list and each item's own design document.

| ID | Requirement | Primary implementation | Tests |
|---|---|---|---|
| A1 | Append-only audit events (no update/delete API) | No update/delete route or repository method exists anywhere in `app/` | `tests/test_audit_events.py` |
| A2 | Write API (`POST /audit/events`) | `app/api/routes/audit_events.py`, `app/services/audit_event_service.py` | `tests/test_audit_events.py` |
| A3 | Query API with filters | `GET /audit/events`, `app/repositories/audit_event_repository.py::list_events` | `tests/test_audit_events_list.py` |
| A4 | Pagination | `limit`/`offset` on `GET /audit/events` | `tests/test_audit_events_list.py` (pagination cases) |
| A5 | Hash-chain tamper evidence | `app/services/hashing.py`, `previousHash`/`eventHash` columns | `tests/test_audit_events.py`, `tests/test_append_concurrency.py` |
| A6 | Verification endpoint (`GET /audit/verify`) | `app/services/chain_verification_service.py` | `tests/test_audit_verify.py` |
| A7 | End-to-end tamper detection demonstration | Same verify endpoint, exercised against a direct (non-API) database change | `tests/test_audit_verify.py::test_verify_detects_content_tampering`, `::test_verify_detects_broken_link` |
| B1 | Retention | `app/services/retention_service.py`, `POST /audit/retention/apply` | `tests/test_retention.py` |
| B2 | Structured redaction | `app/services/redaction_service.py`, `POST /audit/events/{id}/redact` | `tests/test_redaction.py` |
| B3 | Verifiable bulk export | `app/services/export_service.py`, `GET /audit/export` | `tests/test_export.py` |
| C1 | Compliance reporting (account access) | `app/services/compliance_service.py`, `GET /audit/compliance/account-access` | `tests/test_compliance.py` |
| X1 | All APIs authenticated | `app/core/security.py`, `app/core/authorization.py` | `tests/test_auth.py`, `tests/test_auth_security.py`, `tests/test_authorization.py` |
| X2 | Minimum 70% test coverage | `pyproject.toml` (`[tool.coverage.report] fail_under = 70`) | Enforced automatically by `pytest --cov=app` on every run, not a specific test file |

## Prototype limitations

Deliberate, disclosed scope boundaries — each one has a fuller discussion in its own design document, linked above, rather than being silently absent:

- **User management is a small configured store, not an identity provider.** No self-service registration, password reset, or MFA; a user's role/tenant is a line in `AUTH_USERS`, not a database record with a lifecycle.
- **No token revocation.** A JWT is valid until it naturally expires; there's no server-side session or blacklist.
- **Rate limiting is in-memory and single-instance-only.** Correct for one running process; multiple instances behind a load balancer would each enforce the limit independently (see `docs/defensive-limits-design.md` §4).
- **No log shipping, rotation, or retention policy.** Structured JSON goes to stdout; what happens to it after that is left to whatever's running the process.
- **Export and the compliance report have no pagination or size bound**, and export's bundle can prove it wasn't altered since export but not that it's complete (no record was silently omitted) — both stated explicitly in their design docs rather than left implicit.
- **Redaction only redacts top-level `payload` keys**, not nested structure within a field.
- **No regulator-specific role, report template, or scheduled delivery** for compliance reporting — a regulator is modeled as an `auditor` user.
- **Idempotency keys never expire or get cleaned up** — a claimed key stays claimed indefinitely.
- **No deployment/runtime environment is chosen** — deliberately out of scope for this assignment; see "Production improvements" below for what that would involve.

## Production improvements

What a real, non-prototype deployment would need on top of what's here — none of this is built, and it isn't meant to be for this assignment:

- **An external identity provider** (OIDC) in place of the configured user store — real credential storage, MFA, self-service password reset, and token issuance/verification against the IdP's rotating JWKS keys instead of one long-lived symmetric secret. See `docs/auth-hardening-design.md` §6 for the specific list of what would move where.
- **A shared backing store (e.g. Redis) or gateway-level rate limiting**, so limits are enforced consistently across multiple running instances rather than per-process.
- **Centralized log aggregation** ingesting this service's structured JSON stdout (the format is already aggregator-friendly by design), plus alerting on the WARNING/ERROR-level security events it already emits.
- **Token revocation / session management**, for revoking access before natural JWT expiry (e.g. on a detected compromise).
- **Pagination and a completeness proof for export and compliance reporting**, for result sets too large for one response, and to let a recipient verify nothing was silently omitted without trusting the live service.
- **A real deployment/runtime environment decision** — containerizing the application itself (today only its PostgreSQL dependency is containerized), choosing an orchestration/hosting platform, and the operational concerns that come with it (secrets management, horizontal scaling, zero-downtime migrations). Explicitly not decided here, and no Kubernetes/cloud-specific tooling has been introduced, per this assignment's own scope.

## Documentation index

| Document | Covers |
|---|---|
| [`docs/requirements.md`](docs/requirements.md) | The original Scenario A/B/C requirements, with stable IDs and "Decided" notes |
| [`docs/assumptions.md`](docs/assumptions.md) | Every design decision made along the way, including the cross-cutting work beyond the original scenarios |
| [`docs/architecture.md`](docs/architecture.md) | The layered request-flow design, canonicalization, and the concurrency/advisory-lock design |
| [`docs/redaction-design.md`](docs/redaction-design.md) | Structured redaction — alternatives considered, the chosen design, trade-offs |
| [`docs/export-design.md`](docs/export-design.md) | Verifiable bulk export — bundle format, the verification recipe, what it does/doesn't prove |
| [`docs/authorization-design.md`](docs/authorization-design.md) | The role model, tenant scoping, and the endpoint/role table |
| [`docs/auth-hardening-design.md`](docs/auth-hardening-design.md) | Password hashing, JWT hardening, and what would move to an enterprise IdP |
| [`docs/idempotency-design.md`](docs/idempotency-design.md) | Idempotent writes and how they stay safe under concurrency |
| [`docs/defensive-limits-design.md`](docs/defensive-limits-design.md) | Payload/body limits, rate limiting, CORS |
| [`docs/security-logging-design.md`](docs/security-logging-design.md) | Structured logging, correlation IDs, sanitization, safe error responses |
