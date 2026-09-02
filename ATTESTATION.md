# Attestation

**Name:** AnoopKumar Gidijala
**Email:** anoopkumargidijala111@gmail.com
**Assignment:** Build an AI-Assisted Software Engineering System — Audit Log Service
**Repository:** https://github.com/AnoopKumarGidijala/audit-log-service
**Branch:** main
**Start Date:** 2026-09-01
**Submission Date:** 2026-09-02


## Delivered Scope

The submitted prototype includes:

- Authenticated and role-authorized audit APIs with tenant-aware access control
- Append-only audit event creation backed by PostgreSQL
- SHA-256 based tamper-evident hash chaining
- Audit querying with filtering and pagination
- Full-chain verification and direct datastore tamper detection
- Configurable retention using archival metadata
- Structured field redaction with auditable redaction events
- Bulk export by actor ID or resource ID with manifest integrity metadata
- Compliance reporting for client account activity
- Idempotent audit event creation
- Request limits, rate limiting and explicit CORS controls
- Structured security logging and safe error handling
- Alembic database migrations and health/readiness endpoints
- PostgreSQL-backed automated tests with enforced line and branch coverage

## AI Usage

I used Claude Code as an AI-assisted development tool during this assignment.

AI was used to assist with implementation, tests, documentation, design exploration, debugging and code review. I worked incrementally rather than generating the complete solution in a single step.

I reviewed the generated changes before accepting them and requested changes when proposed implementations did not meet the intended correctness or security requirements. Examples include revising the initial redaction verification approach so that non-redacted fields remained tamper-evident and correcting database/transaction design decisions during development.

The prompts, outcomes, engineering reviews and decisions for material AI-assisted work are documented in `AI_USAGE.md`.

I understand the submitted implementation and take responsibility for the final design and code.

## Validation

Final local validation was performed against the dedicated PostgreSQL test environment.

- Automated tests: 232 passed
- Coverage: minimum 70% line/branch coverage enforced by pytest configuration
- Manual API testing completed for event creation, querying, verification, redaction, export and compliance reporting
- Direct PostgreSQL tampering was manually performed and successfully detected by `/audit/verify`
- Working tree was clean before final attestation update

## Known Prototype Limitations

- Export bundles include a SHA-256 manifest hash but are not digitally signed. Asymmetric signing and trusted key management would be added for stronger independent export authenticity.
- Rate limiting is implemented in memory and is suitable for the single-instance prototype. A distributed deployment would use shared storage or gateway-level enforcement.
- Authentication uses a configured prototype user store. A production deployment would normally delegate authentication, MFA, provisioning, token revocation and key rotation to an enterprise identity provider.
- The audit hash chain is tamper-evident rather than tamper-proof. Stronger production protection could include externally anchored checkpoints or immutable/WORM storage.




I, AnoopKumar Gidijala, attest that this submission is my own individual work, completed on my own machine and accounts, and  that it honestly reflects my development process and use of AI.