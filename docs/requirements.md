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

**Open design question:** Redacting a field inside `payload` would normally change that record's content hash, which would break the chain as originally computed. How redaction coexists with hash-chain verification is not yet decided — see `assumptions.md`. This is documented here as a problem to be designed, not a solution to be assumed.

### 10. Verifiable Bulk Export

An export capability for all records belonging to a given `resourceId` or `actorId`.

The exported bundle must be self-contained and contain enough chain metadata for the recipient to independently verify that the records have not been modified since export.

The exact export format and verification metadata will be decided during design.

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
