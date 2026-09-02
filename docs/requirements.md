# Requirements

This document summarizes the requirements for the tamper-evident audit log service, organized by scenario. Scenario A is the core service. Scenarios B and C extend it. We will decide later how much of Scenario C we implement.

## Cross-Cutting Requirements

- **Authentication:** All APIs are authenticated. Unauthenticated requests must be rejected.
- **Test coverage:** Minimum required test coverage is 70%. We will target around 80% to maintain a safe margin.

---

## Scenario A - Core Audit Log Service

A tamper-evident audit log service that maintains an append-only history of events.

### 1. Append-Only Audit Events

Audit records are append-only. There are no update or delete APIs for existing audit records — once written, a record cannot be modified or removed through normal service operation.

### 2. Write API

An API for submitting a new audit event. Each event contains, at minimum:

| Field | Description |
|---|---|
| `eventType` | What happened, e.g. `USER_LOGIN`, `RECORD_UPDATED`, `PERMISSION_GRANTED` |
| `actorId` | Who or what caused the event |
| `resourceType` | Type of resource affected |
| `resourceId` | Specific resource affected |
| `payload` | Structured details about the event |
| `timestamp` | When the event occurred |

### 3. Query API with Filters

An API for retrieving audit events, supporting filtering by:

- `actorId`
- `resourceType` and `resourceId`
- `eventType`
- `from` / `to` time range

### 4. Pagination

Query results must be paginated rather than returned in full, to support large result sets.

### 5. Hash-Chain Tamper Evidence

Each stored record includes:

- a hash of its own content, and
- the hash of the previous record.

This forms a hash chain across the full sequence of records. The first record in the chain uses a defined genesis value in place of a "previous hash."

### 6. Verification Endpoint

`GET /audit/verify`

Verifies the full hash chain and reports:

- whether the chain is intact,
- the first inconsistent record if verification fails, and
- the type of violation detected.

### 7. Tamper Detection Demonstration

The service should allow us to demonstrate tamper detection end-to-end:

1. create events through the API,
2. query the stored events,
3. verify the chain (intact),
4. modify a record directly in the database (bypassing the API),
5. verify the chain again (detects the change).

---

## Scenario B - Retention and Redaction

Extends the core service with retention, structured redaction, and bulk export.

### 8. Retention

Records older than a configurable window should be archivable or soft-deletable. Chain verification must be able to account for legitimately archived records without reporting a false chain break.

### 9. Structured Redaction

Some fields inside a record's `payload` may contain sensitive information (e.g. account numbers, personal identifiers). These fields should be redactable to meet privacy requirements, without losing the ability to verify the audit history.

**Decided:** redacting a field inside `payload` would, if hashed naively, break the chain as originally computed. The chosen approach — freeze the record's existing `event_hash` (never recompute it), tombstone the specific redacted field(s) in place, and require a companion audit event logging the redaction — resolves this without changing the hash format, so every record already in the chain is immediately redactable with no migration. Full design, alternatives considered, and trade-offs: see `docs/redaction-design.md`.

### 10. Verifiable Bulk Export

An export capability for all records belonging to a given `resourceId` or `actorId`.

The exported bundle must be self-contained and contain enough chain metadata for the recipient to independently verify that the records have not been modified since export.

**Decided:** a filtered export isn't chain-adjacent (see `docs/export-design.md` §1), so records keep their original `previousHash`/`eventHash` as references into the original chain, and the bundle additionally carries a `manifestHash` — a commitment over exactly which records, in what order, it contains — so a recipient can detect any change to the bundle after export using only the bundle itself. What that does and doesn't prove without also querying the live service is documented explicitly. Full design: see `docs/export-design.md`.

---

## Scenario C - Compliance Reporting

The requirement as given is:

> "Regulators need to be able to audit access to client account data."

This requirement is **not fully clear** as stated. Before implementing any part of it, we need to clarify the following. These are open questions, not confirmed requirements or assumptions we are locking in.

### Open Questions

1. **What counts as "access"?** Does this mean read access only, or does it also include writes/updates, exports, failed/denied access attempts, and administrative access?
2. **What is "client account data"?** Which resource types / fields are in scope? Is this all data belonging to a client account, or a specific subset (e.g. PII, financial fields)?
3. **Which actors should be tracked?** Human users only, or also service accounts, background jobs, and internal admin tooling?
4. **What do regulators need to see?** A raw event feed, a summarized report, or both? Is there a required report format (e.g. a specific regulatory template)?
5. **What filters/reports are required?** By client, by date range, by actor, by data field accessed, by access outcome (granted/denied)?
6. **Who is allowed to access these reports?** What authorization level is required to run a compliance report or view regulator-facing audit data?
7. **How long must this information be retained?** Does this differ from the general retention policy in Scenario B, and is there a regulatory minimum retention period?
8. **Delivery/format:** Do reports need to be exported in a specific format for regulators (e.g. CSV, PDF, a signed export), and does the Scenario B verifiable export mechanism satisfy this?

We will scope and implement a subset of Scenario C only after these questions are answered or reasonable assumptions are explicitly agreed and documented.

### Decided (Prototype Scope)

The open questions above are **not** all resolved — most remain genuinely open for a real regulatory deployment. What follows is the narrow, explicit interpretation this prototype implements, so the ambiguity in the original requirement doesn't silently turn into an ambiguous implementation.

**Assumptions made for this prototype** (answering only as much of the Open Questions list above as implementation requires, and no more):

- **"Client account data"** (Q2) is represented by audit events whose `resourceType` is exactly `"ACCOUNT"`. This is a fixed, non-configurable filter built into the reporting endpoint, not a value the caller supplies — the endpoint reports on account access specifically, not arbitrary resource types.
- **"Access"** (Q1) is *not* narrowed to a specific `eventType` (e.g. read-only). Every event already recorded against an `ACCOUNT` resource — however it was categorized at write time — is treated as "access" to that account for this prototype. The audit log has no canonical read-vs-write event-type taxonomy today, and inventing one here would mean guessing at a business rule nobody has actually specified; it's simpler and more honest to report everything tied to the resource and let a human reviewer interpret `eventType` themselves.
- **Actors** (Q3) are whatever `actorId` values already appear in the audit log — no distinction is drawn between human users, service accounts, or anything else, since the audit log doesn't currently distinguish them either.
- **What regulators/compliance users need to see** (Q4, Q5) is a filterable raw event feed — who accessed which account and when — not a summarized or templated report. Filters supported: account/resource ID, actor ID, and a time range (`from`/`to`), matching the filter dimensions already established for `GET /audit/events`.
- **Retention and redaction interact with this report exactly as they do with export** (not a new decision — reapplying the ones already made in Scenario B): archived records remain visible to compliance reporting (retention changes routine-query visibility, not historical availability for this purpose), and redacted fields stay redacted (the report reads the same stored rows every other read path reads, so a redacted value is simply not there to expose).
- **Authorization** (Q6) is now decided project-wide (see `docs/authorization-design.md`, added after this Scenario C increment): this endpoint requires the `auditor` or `admin` role. There is still no *regulator-specific* role separate from `auditor` - a regulator is modeled as an `auditor` user in the configured user store, not a distinct fifth role.
- **Retention period for compliance data itself, and delivery/export format** (Q7, Q8) are not addressed by this increment — the report is a live query API, not a scheduled export or archive with its own retention policy. Scenario B's `GET /audit/export` remains the answer if a compliance user needs a portable, verifiable bundle instead of a live query.

**What is implemented:** `GET /audit/compliance/account-access` — an authenticated endpoint returning matching `resourceType=ACCOUNT` audit events, optionally filtered by `resourceId`, `actorId`, and/or `from`/`to`, reusing the existing audit record store (no separate compliance database or schema).

**What is intentionally not implemented** (explicitly out of scope for this increment, not overlooked):

- Regulator-specific report templates or a fixed regulatory output format.
- PDF or other rendered/printable report generation.
- A *regulator-specific* role distinct from `auditor` (see `docs/authorization-design.md` for the general role model now in place) - regulator access is modeled as an `auditor` user, not a fifth role.
- Scheduled or recurring report generation/delivery.
- External regulator system integrations (e.g. submitting reports to a regulator's own portal or API).
- A separate reporting database, warehouse, or read replica — this endpoint queries the same `audit_events` table as everything else.
- Pagination on the report (matching the same accepted, disclosed limitation as `GET /audit/export` — see `docs/export-design.md`) and any `eventType`-based filtering (deliberately not built, per the "access" assumption above).
