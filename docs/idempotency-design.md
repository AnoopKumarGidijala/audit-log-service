# Idempotency for Audit Event Creation

## 1. Problem

A client that times out waiting for `POST /audit/events` to respond doesn't know whether the write actually landed - the request may have succeeded server-side even though the client never saw the response. The natural client behavior is to retry the same request. Without idempotency support, that retry creates a second, distinct audit event with its own `id`/`eventHash`, chained after the first - a duplicate that's indistinguishable, from the chain's point of view, from two genuinely separate events.

## 2. Interface: an `Idempotency-Key` header, not a body field

The client optionally sends `Idempotency-Key: <opaque string>` on `POST /audit/events`. Chosen over adding a field to the request body for two reasons:

- It keeps the idempotency key out of `AuditEventCreate` and therefore out of `compute_event_hash()`'s input entirely - the hash-chain content model is completely unchanged, and the key can never be mistaken for part of the audited event data.
- It's the established REST convention for this exact problem (the same pattern Stripe, GitHub, and most modern write APIs use), so it's the least surprising interface for an API client to reach for.

A request with no `Idempotency-Key` header behaves exactly as it did before this feature existed - idempotency is opt-in per request, not a required field.

## 3. Scope: per authenticated caller, per key

"The same idempotency key" is scoped to `(requested_by, idempotency_key)`, where `requested_by` is the authenticated caller's username (the JWT `sub` claim - see `docs/auth-hardening-design.md`) - matching the requirement's own framing, "for the same authenticated caller and idempotency key." Two different callers using the identical key string are unrelated requests, each tracked independently; a caller doesn't need to worry about picking a key another caller (or tenant) might also pick. Scoping by username rather than, say, `(tenant_id, idempotency_key)` was a deliberate choice: a username already determines exactly one tenant (`Settings.auth_users`), so scoping by username is at least as precise, and matches "authenticated caller" literally rather than the broader "tenant."

## 4. Conflict detection: a content fingerprint, not just presence

Storing "this key was used" isn't enough on its own - a client could accidentally (or a different, unrelated request could coincidentally) reuse a key for genuinely different content, and that must be rejected rather than silently returning someone else's event. Each idempotency record stores `request_fingerprint`: a SHA-256 over exactly the caller-controlled fields (`tenantId`, `eventType`, `actorId`, `resourceType`, `resourceId`, `payload` - see `app/services/hashing.py:compute_request_fingerprint()`), reusing the same `canonicalize()` used everywhere else in this system for deterministic hashing (no new hashing approach introduced). Deliberately excludes `timestamp`/`previousHash`, which are server-generated and will legitimately differ between the original request and a true retry.

On a request with an idempotency key already on record:

- **Fingerprint matches** → this is a legitimate replay. The original event is returned, unchanged, with no new row appended.
- **Fingerprint differs** → the key was reused for different content. Rejected with `409 Conflict`, and nothing is appended.

## 5. Concurrency: reusing the existing advisory lock, not a new one

The append path already serializes all writes with a single, transaction-scoped Postgres advisory lock (`lock_for_append()` / `pg_advisory_xact_lock`, unchanged from before this feature - see `docs/architecture.md`'s Concurrency Concern). Two concurrent appends already can't interleave; the second blocks until the first's transaction commits (or rolls back), and Postgres's default READ COMMITTED isolation means the second, once unblocked, sees everything the first committed.

Idempotency support rides entirely on that existing lock rather than introducing a second one:

1. `lock_for_append()` runs first, exactly as before.
2. Still inside that same lock-held transaction, the idempotency table is checked (`repo.get_idempotency_record`). Not found → proceed to create the event, as before.
3. The new event is *inserted but not yet committed* (`repo.insert_event` - a flush, not a commit, so the row gets its id without releasing the lock).
4. The idempotency bookkeeping row (referencing that id) is inserted, also not yet committed.
5. **One `db.commit()`** commits the event and its idempotency row together, and only then releases the advisory lock.

A second, concurrent request for the identical (caller, key, content) that arrives while step 1-5 is in flight blocks at step 1 until the first request's commit. Once unblocked, its own step 2 now finds the first request's committed idempotency row and returns a replay - it never reaches event creation at all. This is exactly why no fork or duplicate chain entry can occur under concurrent retries: **the two requests are never inside the critical section at the same time**, and by the time the second one is, the first's outcome is already durable and visible.

`AuditEvent.event_hash`'s pre-existing `unique=True` constraint, plus a new `UniqueConstraint("username", "idempotency_key")` on the new `audit_event_idempotency_keys` table, are DB-enforced backstops for these invariants - not the mechanism the correctness guarantee actually rests on (that's the lock, per above), but a defense-in-depth match for the precedent already set elsewhere in this schema. Neither constraint is expected to ever actually fire given the locking discipline is followed; if one did, that would indicate the discipline was bypassed somewhere - worth a loud failure (an unhandled `IntegrityError`, surfaced as a 500), not a case worth silently working around.

## 6. What's stored, and where

New table, `audit_event_idempotency_keys` (`app/db/models.py:IdempotencyKey`) - deliberately not new columns on `audit_events`. This is bookkeeping for the write API's retry-safety, not part of the audit record itself, and `chain_verification_service` never reads it - chain verification is completely unaffected by this feature, by construction (a replayed request never appends anything for verification to see).

Columns: `username`, `idempotency_key`, `request_fingerprint`, `event_id` (FK to the resulting event, for replay retrieval), `created_at`. No expiry/cleanup mechanism for old rows - out of scope for this pass; a real deployment would likely want a retention policy for this table too (similar in spirit to `docs/requirements.md` Scenario B's retention for audit events, but not the same table and not addressed here).

## 7. What didn't change

- Hash-chain construction, `compute_event_hash()`'s inputs, and `chain_verification_service` - byte-for-byte unchanged. A replay never touches them (nothing is appended); a fresh create with an idempotency key hashes exactly what it would have without one.
- `redaction_service`'s companion-event append (`audit_event_service.create_audit_event()` called without `idempotency_key`/`requested_by`) - both parameters default to `None`, so this call site, and any other pre-existing caller, behaves exactly as before.
- Every other endpoint. Idempotency support is scoped to `POST /audit/events` only, per the request that drove this change - not a generic idempotency framework applied everywhere.

## 8. Trade-offs and limitations

- **No expiry on idempotency records.** A key stays "used" forever once claimed; a real deployment would likely want a TTL (idempotency keys are usually meant to protect a retry window of minutes-to-hours, not indefinitely) plus a cleanup job - not built here, out of scope for this pass.
- **A conflicting reuse (`409`) doesn't say what actually differed.** The response confirms the key was reused with different content, not which field(s) changed - deliberately terse, matching this codebase's general posture of not over-explaining error internals; a caller that hits this should treat it as "pick a new key," not attempt to reconcile.
- **The idempotency table has no tenant column of its own.** Not needed for correctness (username already determines tenant, see §3), but means a query directly against `audit_event_idempotency_keys` for "this tenant's idempotency activity" would need a join through `audit_events` - not something anything in this codebase currently needs to do.
