# Architecture

This document describes the layered request-flow architecture of the tamper-evident audit log service, in the depth it was originally designed at: Scenario A (the core service). That layering (API → service → repository → PostgreSQL) is what every later increment - Scenario B (retention, redaction, export), Scenario C (compliance reporting), and the cross-cutting hardening built on top (authorization, auth hardening, idempotency, defensive limits, security logging, migrations) - was built directly on top of, unchanged. Each of those has its own focused design document (see "Design Documents" near the end of this file); this document is not being kept in sync with every detail of them, only with the core flow it originally described.

For a complete, up-to-date, reviewer-oriented description of the whole service as it exists today, see the top-level `README.md` - it's the document to read first.

## Guiding Principle

Keep it simple. This is a small FastAPI service, not a distributed system. A single, layered request flow is sufficient — no message queues, caches, or microservices at this stage.

## Main Flow

```
Client/Postman -> FastAPI API layer -> Service layer -> Repository layer -> PostgreSQL
```

- **Client/Postman** — issues HTTP requests, including obtaining and sending a JWT Bearer token.
- **FastAPI API layer** — HTTP routing, request/response schemas, input validation, authentication (JWT verification). No business logic here.
- **Service layer** — business logic: constructing the canonical event representation, computing hashes, chaining records, and running chain verification.
- **Repository layer** — database access including inserting records, querying events with filters and pagination, and retrieving records required for chain verification.
- **PostgreSQL** — durable, storage of audit records.

Each layer only talks to the layer directly below it.

## ASCII Diagram

```
+------------------+
|  Client/Postman  |
+---------+--------+
          |  HTTP/HTTPS + JWT Bearer token
          v
+------------------------+
|   FastAPI API layer    |
|  - routing              |
|  - request validation   |
|  - JWT authentication   |
+---------+---------------+
          |
          v
+------------------------+
|     Service layer       |
|  - canonicalize event   |
|  - compute SHA-256 hash |
|  - chain to prev record |
|  - verify chain         |
+---------+---------------+
          |
          v
+------------------------+
|   Repository layer      |
|  - insert / select only |
|  -  query with filters  |
|  -  pagination          |
|  -  retrieve records    |
+---------+---------------+
          |
          v
+------------------------+
|      PostgreSQL          |
|  audit events table      |
+--------------------------+
```

## Authentication and Authorization

- Authentication uses **JWT Bearer tokens**. `POST /auth/token` issues a token; all other endpoints require a valid `Authorization: Bearer <token>` header. Token verification happens in the API layer, before a request reaches the service layer.
- Credentials come from a small configured user store (`Settings.auth_users`), not an external identity provider. Passwords are stored as Argon2 hashes, never plaintext; the JWT itself validates a fixed algorithm, issuer, audience, and expiry, and the app refuses to start with a weak/default signing secret. Full hardening design: see `docs/auth-hardening-design.md`.
- Authorization is role-based (`writer`/`reader`/`auditor`/`admin`) and deliberately kept as a separate concern from authentication in code: `app/core/security.py` resolves *who* is calling, `app/core/authorization.py` decides *whether* their role may perform the operation the endpoint declares. `reader` queries are additionally scoped to the caller's own tenant; `auditor`/`admin` read across all tenants. Full design and the endpoint/role table: see `docs/authorization-design.md`.

## APIs (Scenario A)

| Method & Path | Purpose |
|---|---|
| `POST /auth/token` | Authenticate and obtain a JWT Bearer token. |
| `POST /audit/events` | Append a new audit event to the log. |
| `GET /audit/events` | Query audit events with filters and pagination. |
| `GET /audit/verify` | Verify the integrity of the hash chain. |

These four are Scenario A's own endpoints, in the scope this document was originally written for. The service has grown well beyond them since - retention, redaction, export, compliance reporting, and two health endpoints - see README.md's "API Overview" for the complete, current list; this table is kept here only as the historical Scenario A subset.

Request/response schemas, status codes, and error formats are all finalized and implemented (see `app/schemas/` and `app/api/routes/`) - this line originally said otherwise, written before implementation began.

## Audit Event Data Model

Conceptual fields for a stored audit record (not a database schema yet):

| Field | Description |
|---|---|
| `id` | Internal identifier for the record (e.g. surrogate primary key). |
| `eventType` | What happened, e.g. `USER_LOGIN`, `RECORD_UPDATED`. |
| `actorId` | Who or what caused the event. |
| `resourceType` | Type of resource affected. |
| `resourceId` | Specific resource affected. |
| `payload` | Structured details about the event, stored as structured JSON. |
| `timestamp` | When the event occurred (server-generated, UTC). |
| `previous_hash` | The `event_hash` of the record immediately before this one in the chain. |
| `event_hash` | The hash of this record's own canonical content (including `previous_hash`). |

## How the Hash Chain Works (Simple Explanation)

1. Every record's `event_hash` is a SHA-256 hash computed over that record's content, which includes the `previous_hash` field.
2. The **first record** in the log has no predecessor, so it uses a defined **genesis value** in place of `previous_hash` (e.g. a fixed constant such as all-zeros).
3. Each **subsequent record** stores the previous record's `event_hash` as its own `previous_hash`, then computes its own `event_hash` over its content.
4. This links every record to the one before it. Changing any past record's content changes that record's `event_hash`, which no longer matches the `previous_hash` stored in the next record — making the modification detectable.
5. Verifying the chain means walking the records in order and recomputing each `event_hash` from its content, checking that:
   - the recomputed hash matches the stored `event_hash`, and
   - the stored `previous_hash` matches the previous record's stored `event_hash`.

## Canonical Representation Before Hashing

The same logical event data must always hash to the same value. JSON does not guarantee a stable field order, and formatting differences (whitespace, key order, number formatting) would produce different byte sequences — and therefore different hashes — for what is logically the same data.

Before computing `event_hash`, the record's content must be converted to a **canonical representation** (e.g. keys sorted deterministically, fixed whitespace/encoding rules) so that hashing is deterministic and reproducible.

**Decided and implemented:** `app/services/hashing.py:canonicalize()` - `json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, encoded to UTF-8. Sorted keys make dict insertion order irrelevant; compact separators (no incidental whitespace) and `ensure_ascii=True` make the byte output fully deterministic regardless of what produced the input dict. Every hash this service computes - `event_hash`, redaction's field-value and content commitments, export's manifest hash, and the idempotency request fingerprint - reuses this one function, not a separate canonicalization scheme each.

## Concurrency Concern: Conflicting Writes

Because each new record must reference the `event_hash` of the current last record, two concurrent write requests could both read the same "current last record," each compute a `previous_hash` pointing to it, and both attempt to append — producing a fork in the chain rather than a single linear sequence.

**Decided:** appends are serialized with a PostgreSQL transaction-level advisory lock (`pg_advisory_xact_lock`), taken in the repository layer before the last record is read, and released automatically when the append transaction commits or rolls back. This guarantees only one write can be constructing the "next" record at a time, keeping the chain a single linear sequence. The trade-off is that audit-event writes are serialized — concurrent write requests queue up behind the lock rather than committing in parallel — which is acceptable for this service's expected write volume.

This same lock is what makes idempotent retries of `POST /audit/events` safe under concurrency (an optional `Idempotency-Key` header - see `docs/idempotency-design.md`): the idempotency check, the event insert, and its idempotency bookkeeping row all happen inside the one transaction the lock is held for, so two concurrent retries can never both pass the "is this key already used" check before either has committed.

## Scenario B and C: Implemented on Top of This Layering, Not Designed Here

This document originally listed retention, redaction, and export as undesigned future extensions. All three are now implemented, each with its own focused design document, and none of them required changing the layering described above - they're new services/repository functions/routes slotted into the same API → service → repository → PostgreSQL flow:

- **Retention** (`[B1]`) — soft-delete via a nullable `archived_at` column, deliberately outside the hashed content. See `docs/assumptions.md`'s retention entry and `app/services/retention_service.py`.
- **Redaction** (`[B2]`) — tombstones a payload field in place without ever recomputing `event_hash`, backed by a companion audit event carrying a content commitment. See `docs/redaction-design.md`.
- **Export** (`[B3]`) — a self-contained JSON bundle with a manifest hash, for a filtered (non-chain-adjacent) subset of records. See `docs/export-design.md`.
- **Compliance reporting** (`[C1]`, Scenario C) — reuses this document's layering unchanged, scoped to `resourceType="ACCOUNT"` events. See `docs/requirements.md` Scenario C, "Decided (Prototype Scope)".

## Design Documents

Later, cross-cutting work - beyond Scenario A/B/C - also builds on this same layering without changing it, each documented separately: idempotent writes (`docs/idempotency-design.md`), the authorization/role model (`docs/authorization-design.md`), authentication hardening (`docs/auth-hardening-design.md`), defensive limits and rate limiting (`docs/defensive-limits-design.md`), and structured security logging (`docs/security-logging-design.md`). `README.md` ties all of this together for a reviewer; this document remains the detailed record of Scenario A's own request flow and its concurrency design above.

## Out of Scope for This Document

- Database schema / migration mechanics — decided (Alembic); see README.md's "Setup" section and `docs/assumptions.md`.
- Python module structure or dependencies
- Detailed request/response contracts — see `app/schemas/` and README.md's "API Overview" instead.
