# Authorization Design

## 1. Problem

Every endpoint required a valid JWT, but once a caller had *any* valid token they could do everything: write events, read across every tenant, verify the chain, export, run compliance reports, apply retention, and redact fields. `docs/assumptions.md` had this flagged as an open item ("Authorization model beyond authentication ... not yet decided"). This increment resolves it for the prototype: role-based access control, plus tenant-scoped reads so one tenant's normal users can't see another tenant's audit data.

Explicitly out of scope, per the request that drove this: no external identity provider, no self-service user management, no fine-grained per-resource ACLs beyond tenant, no token revocation/rotation.

## 2. Roles

| Role | Can do |
|---|---|
| `writer` | Create audit events (`POST /audit/events`) |
| `reader` | Query audit events (`GET /audit/events`), scoped to their own tenant |
| `auditor` | Everything `reader` can, plus verify the chain, export, and view compliance reports - across every tenant |
| `admin` | Everything, including retention and redaction |

Roles are fixed and non-hierarchical in the sense that matters here: `admin` isn't "auditor plus more" via inheritance in code - each endpoint declares its own exact allow-list of roles (`Depends(require_roles(...))`), and `admin` is simply listed wherever it needs to be. This keeps each endpoint's actual permission requirement visible at its own declaration, rather than implied by a role hierarchy defined somewhere else.

| Endpoint | Allowed roles |
|---|---|
| `POST /audit/events` | writer, admin |
| `GET /audit/events` | reader, auditor, admin |
| `GET /audit/verify` | auditor, admin |
| `GET /audit/export` | auditor, admin |
| `GET /audit/compliance/account-access` | auditor, admin |
| `POST /audit/retention/apply` | admin |
| `POST /audit/events/{id}/redact` | admin |

## 3. Authentication vs. authorization - kept as two separate modules

- `app/core/security.py` — **authentication only**. `get_current_user()` verifies the JWT and resolves a `CurrentUser(username, role, tenant_id)`. It has no opinion on what that identity is allowed to do.
- `app/core/authorization.py` — **authorization only**. `require_roles(*roles)` is a dependency factory: it depends on `get_current_user`, then rejects (403) if the resolved role isn't in the allowed set. Every protected route calls it directly with its own required roles, so the permission model lives at the route, not buried in shared middleware.

This split means a wrong-role request always fails in two visibly distinct steps: authentication first (401 if the token itself is missing/invalid), authorization second (403 if the token is valid but the role doesn't qualify) - the standard, and testable, separation between "who are you" and "are you allowed to do this."

## 4. User store

`Settings.auth_users` is a small, fixed list of `UserRecord(username, password, role, tenant_id)` entries, configured as one JSON array in a single `AUTH_USERS` environment variable (parsed by `pydantic-settings`, same env-file convention the rest of `Settings` already uses). This is the "small configured user store" called for - not an external IdP, not a database-backed user table with self-service signup/rotation. Passwords are plaintext in config, matching the precedent already set by the single-credential prototype auth this replaces - acceptable for a prototype, explicitly not production-grade (see Trade-offs).

`POST /auth/token` is unchanged in shape (`OAuth2PasswordRequestForm` in, `Token` out) - it now looks the submitted username/password up in `auth_users` instead of comparing against one fixed pair, and the issued JWT carries `role` and `tenantId` claims alongside the existing `sub`.

## 5. Tenant scoping

### Where tenant_id lives

`AuditEvent` gained a `tenant_id` column, always set server-side from the authenticated caller - never a client-supplied field on `AuditEventCreate`. Keeping it out of the write request schema entirely makes it impossible to forge via the API; a writer or admin literally cannot request that an event be attributed to a tenant other than their own configured one.

`tenant_id` is included in the hashed content (`compute_event_hash`), exactly like `actorId`/`resourceType`/etc. A record's tenant is real event data, and tampering with it directly in the DB is now caught by `GET /audit/verify` like any other field-level tamper.

If an authenticated writer/admin has no tenant configured (`tenant_id is None`), a create request is rejected with `422` rather than silently writing a blank/null tenant.

### Who gets filtered, and why

- **reader**: every `GET /audit/events` call is automatically ANDed with `tenant_id = <reader's own tenant>`, regardless of what other filters the caller supplies. A tenant-a reader who happens to guess a tenant-b `actorId`/`resourceId` still gets an empty result - the scoping isn't just "the default when no filter is given," it's unconditional. If a reader has no tenant configured, they're rejected with `403` rather than falling through to an unfiltered (and therefore cross-tenant) query.
- **auditor / admin**: reads are *not* tenant-filtered. This is deliberate, not an oversight - an auditor's whole purpose is oversight across the organization, and restricting them to one tenant would defeat it. The request behind this feature explicitly asked that "administrative/auditor behavior should be explicit rather than accidental" - the code expresses that literally: the tenant filter is applied in exactly one place (the reader branch), so auditor/admin's cross-tenant visibility is a visible, intentional omission at that one call site, not a filter that silently failed to apply.
- **writer**: has no read endpoint to reach, so its own `tenant_id` only ever matters for what gets stamped on the events it creates.

### Redaction's companion event

The redaction service creates a companion `AUDIT_EVENT_REDACTED` audit event through the ordinary write path. Its `tenant_id` is taken from the *target record being redacted*, not from the redacting admin's own tenant (an admin may have none, or a different one) - so the companion event lands in the same tenant as the record it documents, and that tenant's own auditor/reader can see the redaction alongside the record.

### What's still global

`GET /audit/verify` (chain integrity) and `POST /audit/retention/apply` operate over the whole chain, unfiltered by tenant, exactly as before this change. Both are auditor/admin-or-admin-only operations already; the hash chain itself is one continuous global sequence by design (see `docs/architecture.md`), and splitting it per-tenant was out of scope for this change and unnecessary for what was asked.

## 6. Trade-offs and limitations

- **Plaintext passwords in config.** Consistent with the single-credential prototype this replaces, not a new regression - still not production-grade. A real deployment would need hashed credentials at minimum, more realistically an external IdP.
- **No token revocation.** A JWT with a stale role/tenant claim remains valid until it expires (`access_token_expire_minutes`); there's no server-side session/blacklist. Changing a user's role or tenant in `AUTH_USERS` doesn't affect already-issued tokens.
- **Tenant is the only ownership dimension.** There's no per-resource ACL below tenant (e.g. "this reader may only see `resourceType=SESSION` events"). If that's ever needed, it composes naturally with the existing filter pattern in `list_events()`, but wasn't asked for here.
- **Auditor/admin cross-tenant access is unconditional, not audited-with-a-reason.** The prototype trusts the role itself as sufficient justification for cross-tenant visibility; it doesn't log *why* an auditor queried a given tenant's data (that would itself just be another audit event, but wasn't in scope here).
- **A misconfigured tenant-less writer/reader is rejected, not defaulted.** A writer/reader with `tenant_id: null` in `AUTH_USERS` gets `422`/`403` rather than silently falling back to "no tenant" (which, for a reader, would mean an unfiltered - i.e. cross-tenant - query, defeating the whole point). This is a deliberate fail-closed choice.
