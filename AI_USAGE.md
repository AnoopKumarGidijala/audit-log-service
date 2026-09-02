# AI Usage

This document tracks how AI tools were used while building this project, in accordance with the disclosure referenced in [ATTESTATION.md](ATTESTATION.md).

---

## Interaction 001

**Date:** 2026-09-01

**Tool:** Claude Code

**Task:** Initial repository setup and documentation.

**Prompt Summary:**  
Asked Claude Code to create the initial repository files including README, .gitignore, ATTESTATION, AI usage log, requirements, and assumptions documentation. No application code was requested.

**Outcome:**  
Accepted after review.

**Engineer Review:**  
Reviewed the generated files and verified that the initial requirements matched the assignment. Updated attestation.md file with necessary information.

**Decision:**  
Accepted with minor manual review/changes.

**Reason:**  
The generated structure was suitable as a starting point. Application design and implementation decisions were intentionally deferred to later milestones.



## Interaction 002

**Tool:** Claude Code

**Task:** Requirement analysis

**Prompt Summary:**
Asked Claude to organize the requirements for the three scenarios and document the initial technical assumptions before starting implementation.

**Outcome:**
Accepted after review.

**Engineer Review:**
Checked the documented requirements against the assignment and reviewed the initial technology choices and assumptions. Corrected the test coverage wording, added the missing query step to the tamper validation flow, and removed premature implementation suggestions from the redaction and export requirements.

**Reason:**
The generated requirements covered the three scenarios correctly. Minor changes were made to keep the documentation aligned with the assignment and avoid making design decisions too early.



## Interaction 003

**Tool:** Claude Code

**Task:** Initial architecture design

**Prompt Summary:**
Asked Claude to document the initial FastAPI service architecture, API flow, audit data model, authentication and hash-chain design.

**Outcome:**
Accepted with minor changes.

**Engineer Review:**
Reviewed the architecture, API responsibilities, data model, hash-chain flow and concurrency considerations. Moved database filtering and pagination responsibilities to the repository layer and clarified the local HTTP/deployed HTTPS and PostgreSQL storage descriptions.

**Decision:**
Accepted with minor changes.

**Reason:**
The proposed architecture was simple and suitable for the prototype. Minor changes were made to keep database responsibilities clearly separated from business logic and avoid implying PostgreSQL itself is append-only. 



## Interaction 004

**Tool:** Claude Code

**Task:** Initial FastAPI application setup

**Prompt Summary:**
Asked Claude to create the initial FastAPI application structure, a simple root endpoint, dependency file, and a basic API test.

**Outcome:**
Accepted after review.

**Engineer Review:**
Reviewed the generated application structure and test. Started the FastAPI application locally, verified the root endpoint and Swagger UI, and ran the pytest test successfully.

**Decision:**
Accepted.

**Reason:**
The generated setup provided a small working FastAPI foundation without introducing database or audit functionality prematurely.


## Interaction 005

**Tool:** Claude Code

**Task:** PostgreSQL and SQLAlchemy database setup

**Prompt Summary:**
Asked Claude to add the database foundation using PostgreSQL, SQLAlchemy, Docker Compose, environment-based configuration and reusable database session handling.

**Outcome:**
Accepted after review and local validation.

**Engineer Review:**
Reviewed the generated database configuration and session setup. The initial Docker validation could not be completed because WSL/Windows virtualization components were not configured correctly. After fixing the local Docker environment, started PostgreSQL successfully and verified the application database connection using SELECT 1. Existing tests were also run successfully.

**Decision:**
Accepted after environment issue was resolved.

**Reason:**
The implementation provides a simple reusable database foundation without introducing audit models or business logic prematurely.




## Interaction 006

**Tool:** Claude Code

**Task:** Scenario A - authenticated audit event creation

**Prompt Summary:**
Asked Claude to implement the first Scenario A increment covering JWT authentication, append-only audit event creation, PostgreSQL persistence and initial SHA-256 hash chaining.

**Outcome:**
Accepted with changes after review.

**Engineer Review:**
Reviewed the generated authentication, model, repository, service, hashing and API implementation. Questioned the generated unique constraint on previous_hash and removed it after review while retaining the transaction-level append locking mechanism. Verified authentication, event creation and hash-chain behavior against PostgreSQL.

**Decision:**
Accepted with minor design changes.

**Reason:**
The implementation provided the required authenticated write flow and hash-chain foundation. A generated database constraint was adjusted to keep chain concurrency enforcement in the append transaction logic.


## Interaction 007

**Tool:** Claude Code

**Task:** Scenario A - basic audit event querying

**Prompt Summary:**
Asked Claude to add authenticated retrieval of audit events with actor ID and event type filtering while keeping filtering at the database layer.

**Outcome:**
Accepted after review.

**Engineer Review:**
Reviewed the API, service and repository changes. Verified that filters are applied through the database query rather than in Python and that results use deterministic ordering. Existing authentication and database components were reused.

**Decision:**
Accepted.

**Reason:**
The implementation adds a focused first increment of audit event retrieval without introducing the remaining filters or pagination early.


## Interaction 008

**Tool:** Claude Code

**Task:** Scenario A - audit filters and pagination

**Prompt Summary:**
Asked Claude to complete the audit event query requirements by adding resource filters, UTC time-range filtering and pagination to the existing authenticated query API.

**Outcome:**
Accepted after review.

**Engineer Review:**
Reviewed the database-level filtering, deterministic ordering, limit/offset pagination and time-range validation. Verified that timezone-aware inputs are normalized consistently and invalid or ambiguous time ranges are rejected. Reviewed the indexes added for frequently filtered columns.

**Decision:**
Accepted.

**Reason:**
The implementation completes the Scenario A query requirements while keeping filtering and pagination in PostgreSQL and reusing the existing API, service and repository layers.



## Interaction 009

**Tool:** Claude Code

**Task:** Scenario A - hash chain verification and tamper detection

**Prompt Summary:**
Asked Claude to implement authenticated verification of the audit hash chain, identify the first inconsistent record, report the type of violation, and add tests that demonstrate detection of direct database tampering.

**Outcome:**
Accepted after review and automated testing.

**Engineer Review:**
Reviewed the chain verification flow and confirmed that it reuses the same hashing logic used during event creation. Verification walks the complete audit chain from the beginning and stops at the first inconsistency. Reviewed handling for both event hash mismatches and previous hash mismatches. Tests include direct database modification rather than exposing update or delete APIs.

**Decision:**
Accepted.

**Reason:**
The implementation completes Scenario A tamper verification while preserving the append-only API design and clearly reporting the first detected chain violation.




## Interaction 010

**Tool:** Claude Code

**Task:** Scenario B - audit retention

**Prompt Summary:**
Asked Claude to implement configurable retention for audit records while ensuring legitimate retention does not cause hash-chain verification failures.

**Outcome:**
Accepted after review and testing.

**Engineer Review:**
Reviewed the soft-delete approach using archive metadata. Confirmed that archived records are excluded from normal audit queries but remain available to chain verification and when determining the current chain tail. Verified that archive metadata is not included in the immutable event hash.

During testing, timestamp modification used to create old test data was identified as invalid because it changed hashed event content. The test setup was corrected to create old records with valid hashes from the start.

**Decision:**
Accepted.

**Reason:**
Soft deletion preserves the complete physical hash chain while allowing records outside the configured retention window to be hidden from normal queries.



## Interaction 011

**Tool:** Claude Code

**Task:** Scenario B - structured audit field redaction

**Prompt Summary:**
Asked Claude to design and implement field-level redaction for sensitive audit payload data without invalidating the existing hash chain.

**Outcome:**
Accepted with design changes after review.

**Engineer Review:**
Reviewed the proposed redaction scheme and its alternatives. The initial implementation stopped content verification for an entire record after redaction, which would allow later changes to non-redacted fields to go undetected. Requested a refinement so authorized redaction remains possible while non-redacted content continues to be integrity checked.
Reviewed the companion audit-event approach, compatibility with existing records, verification behavior, and documented privacy/trade-off limitations.

**Decision:**
Accepted after refinement.

**Reason:**
The refined design preserves the original audit history and records the redaction as a new append-only event while retaining tamper detection for content that was not authorized for redaction.




## Interaction 012

**Tool:** Claude Code

**Task:** Improve integrity verification after redaction

**Prompt Summary:**
Asked Claude to improve the redaction design so that redacting an authorized sensitive field does not disable integrity checking for the remaining non-redacted content.

**Outcome:**
Accepted after review and testing.

**Engineer Review:**
Reviewed the updated verification behavior and confirmed that authorized redaction can occur without changing the original event hash while unexpected changes to non-redacted content remain detectable.

**Decision:**
Accepted.

**Reason:**
The refinement closes an integrity gap in the initial redaction approach while keeping redaction compatible with the existing audit history.



## Interaction 013

**Tool:** Claude Code

**Task:** Scenario C - compliance reporting

**Prompt Summary:**
Asked Claude to clarify the ambiguous regulatory audit requirement, document prototype assumptions and implement a basic authenticated report for access to client account data using the existing audit history.

**Outcome:**
Accepted after review and testing.

**Engineer Review:**
Reviewed the Scenario C assumptions, implementation scope and compliance query behavior. Confirmed that account-access reporting reuses the existing audit history, supports basic actor/account/time filtering, includes applicable archived history and respects existing redaction behavior.

Also reviewed the explicitly scoped-out regulatory functionality and
limitations.

**Decision:**
Accepted.

**Reason:**
The implementation provides a practical prototype interpretation of the ambiguous compliance requirement while clearly separating assumptions from confirmed requirements and avoiding unsupported regulatory complexity.



## Interaction 014

**Tool:** Claude Code

**Task:** Add role-based authorization and tenant-aware access control

**Prompt Summary:**
Asked Claude to separate authentication from authorization and introduce least-privilege roles for audit operations. The requested model included writer, reader, auditor and admin permissions, along with tenant/resource access restrictions and negative authorization tests.

**Outcome:**
Accepted after review and testing.

**Engineer Review:**
Reviewed the endpoint permission model and confirmed that sensitive operations no longer rely only on possession of a valid JWT. Verified that roles are enforced per endpoint, high-impact operations such as retention and redaction require elevated privileges, and cross-tenant access is denied where applicable.

Reviewed negative tests for wrong-role access, unauthorized sensitive operations and tenant/resource isolation.

**Decision:**
Accepted.

**Reason:**
The change closes the gap between authentication and authorization by adding explicit least-privilege access controls without changing the existing audit hash-chain behavior.


## Interaction 015

**Tool:** Claude Code

**Task:** Harden authentication and JWT validation

**Prompt Summary:** Asked Claude to improve the prototype authentication flow by replacing plaintext password comparison with secure password hashing and strengthening JWT validation. The requested changes included password-hash verification, fixed algorithm handling, issuer and audience checks, rejection of weak signing secrets, generic authentication failures and focused negative tests.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the password verification flow and confirmed configured credentials are represented as Argon2id hashes rather than plaintext passwords. Verified that unknown usernames use equivalent password-verification work to reduce timing-based username enumeration.

Reviewed JWT validation and confirmed the accepted algorithm is fixed in code, issuer and audience are checked, expiry remains enforced and weak/default signing secrets are rejected during configuration startup. Authentication failures return a common response rather than exposing the specific validation failure.

Reviewed negative tests for incorrect passwords, expired tokens, invalid signatures, malformed tokens, incorrect issuer or audience, unexpected algorithms and missing authentication.

**Decision:** Accepted.

**Reason:** The change strengthens identity verification and token validation while keeping the authentication model appropriately small for the prototype.



## Interaction 016

**Tool:** Claude Code

**Task:** Add idempotency for audit event creation

**Prompt Summary:** Asked Claude to make audit event creation safe for client retries by supporting an idempotency key scoped to the authenticated caller. Identical retries should return the original event, conflicting reuse should be rejected, and concurrent duplicate requests must not create multiple audit records.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the idempotency design and confirmed the key is supplied through a request header and does not become part of the immutable audit-event hash content. Idempotency is scoped by authenticated caller and key, and a request fingerprint is used to distinguish legitimate retries from conflicting key reuse.

Reviewed the transaction flow and confirmed the audit event and idempotency record are created within the same advisory-lock-protected transaction. This prevents a concurrent retry from creating a second event between the event insert and idempotency record creation.

Reviewed tests for normal creation, identical retries, conflicting key reuse, caller isolation and concurrent duplicate requests against PostgreSQL. Also confirmed the resulting audit chain remains intact.

**Decision:** Accepted.

**Reason:** The change prevents duplicate audit events caused by client retries while preserving the existing append-only hash-chain semantics and transaction safety.





## Interaction 017

**Tool:** Claude Code

**Task:** Add concurrency and transaction rollback tests

**Prompt Summary:** Asked Claude to prove the existing PostgreSQL advisory-lock append design using integration tests against a real PostgreSQL database. The requested tests covered concurrent event creation, prevention of hash-chain forks, transaction rollback after an append failure, correct recovery on the next append, and concurrent requests using the same idempotency key.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the new integration tests and confirmed they exercise real PostgreSQL concurrency rather than mocking database locking. Concurrent event creation is validated through both the audit verification endpoint and a direct database query checking for multiple records sharing the same previous hash.

Reviewed the forced transaction-failure test and confirmed that a failed append leaves no partial audit record and that the next successful append continues from the correct chain tail. Also reviewed concurrent idempotency testing to confirm duplicate retries produce only one audit event.

The concurrency tests were executed repeatedly to check for timing-related flakiness, and the full test suite remained successful without requiring production-code changes.

**Decision:** Accepted.

**Reason:** The tests provide direct evidence that the existing transaction and advisory-lock design prevents chain forks, rolls back failed writes cleanly and remains safe under concurrent retries.



## Interaction 018

**Tool:** Claude Code

**Task:** Make the test environment reproducible and enforce coverage

**Prompt Summary:** Asked Claude to make the PostgreSQL-backed test suite reproducible for a fresh reviewer, isolate tests from the normal development database, enforce line and branch coverage with a minimum 70 percent threshold, and document the exact test workflow.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the dedicated Docker Compose test database and confirmed it is isolated from the normal development database. Verified that the test configuration is loaded before application imports and that an additional runtime guard prevents tests from running against a database that is not explicitly identified as a test database.

Reviewed the pytest coverage configuration and confirmed branch coverage is enabled with a 70 percent minimum threshold. The failure path was also checked to ensure the test command returns a non-zero exit code when coverage falls below the required level.

Reviewed the documented setup from a fresh environment. The complete suite passed with 159 tests and 99.57 percent coverage without weakening existing tests.

**Decision:** Accepted.

**Reason:** The change makes the test suite safe and reproducible for an independent reviewer while providing measurable and automatically enforced coverage evidence.



## Interaction 019

**Tool:** Claude Code

**Task:** Add API request limits and abuse protection

**Prompt Summary:** Asked Claude to add configurable defensive limits for audit requests, including payload size and nesting restrictions, whole-request size limits, rate limiting for authentication and expensive audit operations, and an explicit CORS policy.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the payload validation and confirmed limits are applied to identity fields as well as payload size, nesting depth and string length. Verified oversized request bodies are rejected before normal request processing.

Reviewed the rate-limiting design and confirmed login attempts are limited by client IP while expensive authenticated operations such as verification, export and compliance reporting are limited by authenticated user. The in-memory implementation is intentionally scoped to a single-instance prototype, with distributed enforcement documented as a production improvement.

Reviewed the explicit deny-by-default CORS configuration and the test isolation used for process-wide rate limiters. Tests cover allowed and rejected payloads, request-size limits, rate-limit behavior and CORS handling. Live HTTP validation confirmed the expected 422, 413 and 429 responses.

**Decision:** Accepted.

**Reason:** The change adds practical protection against oversized, deeply nested and high-frequency requests while keeping the implementation appropriate for the prototype.



## Interaction 020

**Tool:** Claude Code

**Task:** Add security logging and safe error handling

**Prompt Summary:** Asked Claude to add structured logging for security-sensitive operations, correlation IDs for request tracing, automatic protection against sensitive values appearing in logs, and safe handling of unexpected application errors.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the structured JSON logging and confirmed security-relevant events are recorded for authentication, authorization denial, retention, redaction, export, compliance access and chain-verification failures.

Verified that request correlation IDs are propagated through logs and returned with responses. Reviewed the sanitization layer and confirmed sensitive keys, JWT-shaped values and configured secret values are automatically removed from log output. Redaction logging records field names only and does not expose original sensitive values.

Reviewed unexpected-error handling and confirmed clients receive a generic server error while detailed diagnostics remain available server-side. Existing expected HTTP error responses remain unchanged. Tests and live validation confirmed sensitive values do not leak through structured logs.

**Decision:** Accepted.

**Reason:** The change improves security visibility and troubleshooting while preventing credentials, tokens, redacted values and internal exception details from being exposed.







## Interaction 021

**Tool:** Claude Code

**Task:** Add database migrations and deployment readiness checks

**Prompt Summary:** Asked Claude to replace automatic table creation, pin direct dependencies to tested versions, add application health and database readiness endpoints, and document the setup and schema-change workflow.

**Outcome:** Accepted after review and testing.

**Engineer Review:** Reviewed the setup and confirmed application startup no longer creates tables automatically. The initial migration was generated and validated against an empty PostgreSQL database, and schema comparison confirmed that the migration matches the current SQLAlchemy models.

Reviewed the migration drift test and confirmed future model changes without corresponding migrations will fail the test suite. Also reviewed the dependency pinning and confirmed direct dependencies use tested versions.

Reviewed the separate liveness and readiness endpoints. Liveness does not depend on the database, while readiness performs a database check and returns a safe failure response without exposing database or driver details.

The complete migration lifecycle was exercised against PostgreSQL and the full test suite passed.

**Decision:** Accepted.

**Reason:** The change replaces prototype-only schema creation with a repeatable migration process and adds basic deployment-readiness checks while improving dependency reproducibility.