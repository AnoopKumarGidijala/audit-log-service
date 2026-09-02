# Architecture

This document describes the initial architecture for the tamper-evident audit log service. It covers Scenario A (the core service) in detail. Scenario B features are mentioned only as future extension points — their implementation is not designed here.

This is an initial architecture for review, not a final design. It will be refined during implementation.

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
- Credentials come from a small configured user store (`Settings.auth_users`), not an external identity provider.
- Authorization is role-based (`writer`/`reader`/`auditor`/`admin`) and deliberately kept as a separate concern from authentication in code: `app/core/security.py` resolves *who* is calling, `app/core/authorization.py` decides *whether* their role may perform the operation the endpoint declares. `reader` queries are additionally scoped to the caller's own tenant; `auditor`/`admin` read across all tenants. Full design and the endpoint/role table: see `docs/authorization-design.md`.

## APIs (Scenario A)

| Method & Path | Purpose |
|---|---|
| `POST /auth/token` | Authenticate and obtain a JWT Bearer token. |
| `POST /audit/events` | Append a new audit event to the log. |
| `GET /audit/events` | Query audit events with filters and pagination. |
| `GET /audit/verify` | Verify the integrity of the hash chain. |

Request/response schemas, status codes, and error formats are not finalized and will be defined during implementation.

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

Before computing `event_hash`, the record's content must be converted to a **canonical representation** (e.g. keys sorted deterministically, fixed whitespace/encoding rules) so that hashing is deterministic and reproducible. The exact canonicalization method (e.g. a specific canonical JSON scheme) is not finalized and will be decided during implementation.

## Concurrency Concern: Conflicting Writes

Because each new record must reference the `event_hash` of the current last record, two concurrent write requests could both read the same "current last record," each compute a `previous_hash` pointing to it, and both attempt to append — producing a fork in the chain rather than a single linear sequence.

**Decided:** appends are serialized with a PostgreSQL transaction-level advisory lock (`pg_advisory_xact_lock`), taken in the repository layer before the last record is read, and released automatically when the append transaction commits or rolls back. This guarantees only one write can be constructing the "next" record at a time, keeping the chain a single linear sequence. The trade-off is that audit-event writes are serialized — concurrent write requests queue up behind the lock rather than committing in parallel — which is acceptable for this service's expected write volume.

## Future Extensions (Scenario B — Not Designed Yet)

The following are anticipated extensions to this architecture. They are noted here as future work only; their implementation approach is intentionally left undesigned pending further requirements discussion (see `requirements.md` and `assumptions.md`):

- **Retention** — archiving or soft-deleting records older than a configurable window, while keeping chain verification valid.
- **Redaction** — redacting sensitive `payload` fields without invalidating the hash chain.
- **Export** — producing a verifiable bundle of records for a given `resourceId` or `actorId`.

## Out of Scope for This Document

- Database schema / migrations
- Python module structure or dependencies
- Detailed request/response contracts
- Scenario C (compliance reporting) design — this document remains Scenario-A-scoped; the compliance reporting endpoint reuses this document's existing layering unchanged (see `docs/requirements.md` Scenario C, "Decided (Prototype Scope)" for what was implemented and why)
