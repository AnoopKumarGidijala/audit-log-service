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

- **Redaction mechanism (Scenario B):** How a redacted `payload` field can be handled without invalidating the hash chain is not yet decided. Candidate directions to evaluate later include hashing field values individually (so a field can be blanked while its hash is retained for verification), or storing a separate "redaction record" rather than mutating the original. No approach is chosen yet — see `requirements.md` Scenario B, item 9.
- **Retention mechanism (Scenario B):** Whether archived/soft-deleted records are removed from primary storage, moved to cold storage, or merely flagged is not yet decided. The mechanism must preserve the ability to verify the chain despite legitimately archived records.
- **Compliance reporting scope (Scenario C):** Which parts of Scenario C we will build, if any, is not yet decided — pending clarification of the open questions listed in `requirements.md`.
- **Export format (Scenario B):** Not yet decided (e.g. JSON, CSV, or a signed/structured format).
- **Deployment/runtime environment:** Not yet decided.
- **Authorization model beyond authentication:** JWT Bearer covers authentication; role/permission distinctions between callers (e.g. who can write vs. query vs. verify vs. run compliance reports) are not yet decided.
