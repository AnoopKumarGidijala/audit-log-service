# Assumptions

This document captures assumptions and open decisions for the project. Items here are not finalized and may change as the design is worked out.

## Initial Technical Choices

These are our **own initial technical decisions for this implementation** — they are not technologies mandated by the assignment. They are a starting point and may change as we learn more.

| Choice | Reason |
|---|---|
| **Python** | Team familiarity; good ecosystem for API services and hashing/crypto utilities. |
| **FastAPI** | Lightweight, async-friendly, built-in request validation and OpenAPI docs generation, well suited to a small API service. |
| **PostgreSQL** | Mature relational database with strong support for ordering, transactions, and indexing needed for an append-only, queryable log. |
| **JWT Bearer authentication** | Simple, standard, stateless way to authenticate API requests without the service needing to manage sessions. |
| **SHA-256 for hashing** | Widely used, well-vetted cryptographic hash function, adequate collision resistance for tamper-evidence purposes. |
| **Server-generated timestamps stored in UTC** | Avoids trusting client-supplied timestamps for ordering/integrity, and avoids timezone ambiguity in stored records and comparisons. |

## Open / Not Finalized

- **Redaction mechanism (Scenario B):** Decided — freeze the record's `event_hash` (never recompute it after redaction), tombstone the specific redacted `payload` field(s) in place, and require a companion audit event logging the redaction (who/when/which fields) plus a commitment hash over the record's full approved post-redaction content. Verification checks a redacted record's current content against that commitment, so tampering with any field outside the authorized redaction is still caught - not just the chain link. Chosen over field-level (Merkle-style) hashing and crypto-shredding specifically because it works immediately on every record already in the chain, with no hash-format change or migration. Full design, alternatives, and trade-offs: see `docs/redaction-design.md`.
- **Retention mechanism (Scenario B):** Whether archived/soft-deleted records are removed from primary storage, moved to cold storage, or merely flagged is not yet decided. The mechanism must preserve the ability to verify the chain despite legitimately archived records.
- **Compliance reporting scope (Scenario C):** Decided (prototype scope only, most of the original open questions remain genuinely unresolved for a real deployment) — `GET /audit/compliance/account-access` reports on audit events with `resourceType="ACCOUNT"`, filterable by `resourceId`/`actorId`/`from`/`to`, reusing the existing audit record store. No report templates, PDF output, regulator role management, scheduled delivery, or external regulator integrations. Full assumptions and what's intentionally out of scope: see `requirements.md` Scenario C, "Decided (Prototype Scope)".
- **Export format (Scenario B):** Decided — a JSON bundle (`GET /audit/export?actorId=...|resourceId=...`) containing the matching records (unchanged `AuditEventOut` shape, including original `previousHash`/`eventHash`, archived and redacted records included as currently stored) plus a `manifestHash` committing to exactly which records/order the bundle contains. Full design, verification recipe, and what it does/doesn't prove without the live service: see `docs/export-design.md`.
- **Deployment/runtime environment:** Not yet decided.
- **Authorization model beyond authentication:** Decided — four roles (`writer`, `reader`, `auditor`, `admin`), each endpoint gated to an explicit allow-list of roles, authentication (`app/core/security.py`) kept as a separate module from authorization (`app/core/authorization.py`). Readers are additionally scoped to their own tenant on every query; auditor/admin read across all tenants by design. Users come from a small configured store (`Settings.auth_users`), not an external identity provider. Full design, the endpoint/role table, and trade-offs: see `docs/authorization-design.md`.
