# Verifiable Bulk Export — Design

Scenario B, `docs/requirements.md` item 10 (`B3`). This document explains why a filtered export can't simply replay the existing chain-verification logic, the chosen bundle format, the exact recipe a recipient follows to verify it, and — as required — precisely what that recipient can and cannot prove without going back to the live service.

## 1. Why a filtered subset isn't chain-verifiable the normal way

`app/services/chain_verification_service.py::verify_chain()` proves the *whole* chain is intact by walking every record in `id` order and checking, for each one, that its `previous_hash` equals the *immediately preceding record's* `event_hash`. That check is only meaningful because it walks the **complete, contiguous** sequence.

An export filtered by `actorId` or `resourceId` is neither complete nor contiguous: if actor `user-1` wrote records 2, 7, and 15 out of a chain of twenty, the exported set is `{2, 7, 15}`. Record 7's `previous_hash` refers to record 6's `event_hash` — but record 6 isn't in the export. Trying to "verify the subset" by checking record 7's `previous_hash` against record 2's `event_hash` (the previous record *in the export*) would be checking two values that were never meant to relate to each other, and would report a false break on every correctly-exported bundle. So: **an exported record's `previous_hash` must be preserved as-is (it's a real reference into the original chain), but it cannot be used to link records within the bundle** — that link simply doesn't exist for a filtered set. The bundle needs its own, different, self-consistency mechanism.

## 2. What the bundle needs to prove, and what it can't

Two genuinely different properties are in play:

1. **"This record's content is exactly what was recorded"** — provable from the bundle alone, per record, by recomputing `compute_event_hash()` from the record's own fields and comparing to its included `event_hash`. This doesn't depend on chain adjacency at all; it only depends on the record's own content, which is exactly what a filtered export still has intact for every record it includes.
2. **"This is genuinely, completely what the live service has for this actor/resource, not a doctored or incomplete subset"** — **not** provable from the bundle alone. A recipient with only the bundle has no way to know whether the exporter (or someone downstream) silently dropped a matching record, or fabricated the whole thing wholesale with self-consistent-looking hashes. That requires an independent channel: querying the live service's chain (`GET /audit/verify`, `GET /audit/events`) and cross-checking the `id`/`event_hash` pairs the bundle claims.

This is the same trust boundary this whole project has disclosed consistently since Scenario A: a hash alone (with no external signature or independent channel) only catches *careless or accidental* changes to what's in front of you — not a fully capable attacker who controls the entire artifact and is willing to recompute hashes to match. Export doesn't get a stronger guarantee than the base chain has; it inherits the same one, explicitly, per record and per bundle (§4).

## 3. Chosen bundle format

```json
{
  "exportedAt": "2026-09-01T16:00:00Z",
  "filter": {"actorId": "user-1", "resourceId": null},
  "recordCount": 3,
  "records": [ /* AuditEventOut-shaped objects, ascending id order */ ],
  "manifestHash": "<sha256 hex>"
}
```

- **`records`** reuses the *existing* `AuditEventOut` schema unchanged — the same fields returned by `GET /audit/events`, including each record's own `previousHash`/`eventHash` exactly as stored, `archivedAt` (§5), and `redactedAt`/`redactedFields` when applicable (§6). No new per-record representation was invented.
- **`manifestHash`** is new: `compute_manifest_hash()` (`app/services/hashing.py`, reusing `canonicalize()` — no second hashing algorithm) over the ordered list of `{id, eventHash}` pairs for exactly the records in `records`. This is the bundle's *self*-consistency commitment: it doesn't (and can't) prove completeness or authenticity relative to the live chain (§2), but it does let a recipient detect a record being added, dropped, reordered, or swapped for a different one *after* the bundle left the service, in one check, without needing to re-verify every record's own hash individually first.

**Why not a per-field Merkle tree or a signature/HMAC over the bundle?** Both would be stronger, and both were considered. A Merkle tree buys little here beyond what per-record hashes already give (each record is already independently checkable). An HMAC (e.g. reusing `SECRET_KEY`) would let the service itself verify a bundle came from it unmodified even without an independent channel — but it reuses a secret already serving a different purpose (JWT signing) for a second one, and doesn't fit "a simple approach suitable for this prototype." A plain hash, with the two-tier verification story documented plainly (§2, §4), is what was asked for; nothing stronger is implemented.

## 4. The verification recipe

A recipient with **only the bundle** (no service access) can perform, entirely offline:

1. **Per-record check**, for every record in `records`: recompute `compute_event_hash(eventType, actorId, resourceType, resourceId, payload, timestamp, previousHash)` and confirm it equals that record's own `eventHash`. Detects any record whose *content* was altered without a matching hash update.
2. **Bundle check**: recompute `compute_manifest_hash()` over `[{id, eventHash} for record in records]` (in the order they appear) and confirm it equals `manifestHash`. Detects a record being added, removed, reordered, or swapped since export.

Both checks use functions already public in this codebase (`app/services/hashing.py`) — nothing export-specific needs to be reverse-engineered, and `tests/test_export.py` exercises exactly this recipe (including deliberately breaking each check to confirm it fires).

**What this recipe proves:** the bundle you're holding right now is internally self-consistent - it wasn't corrupted or edited since you received it, assuming whoever might have tampered with it didn't also recompute both hashes to match (§2 - the same disclosed limitation as the base chain).

**What it does NOT prove, and requires the live service for:**
- That these are genuinely part of the *real* audit chain, not fabricated. Requires cross-checking one or more `id`/`eventHash` pairs against `GET /audit/verify` (confirms the chain those ids belong to is currently intact) or `GET /audit/events` (confirms a record with that `id` currently exists with that exact `eventHash`).
- That the export is *complete* - that no matching record was omitted. Nothing in the bundle can prove a negative like this; only re-querying the live service with the same filter and comparing record counts/ids can.
- That the export reflects the *current* state - a record could legitimately be redacted or archived by the service *after* this export was taken, and the bundle has no way to know that happened.

## 5. Retention: archived records are included

`export_service.export_events()` calls `app/repositories/audit_event_repository.py::list_events_including_archived()` — deliberately **not** `list_events()` (the paginated query API, which excludes archived records by design) and **not** `list_all_events()` (used by verification, which takes no filter at all). Export needs both: filtered, and archive-inclusive. `list_events_including_archived()` never filters on `archived_at`, so a record that retention has archived is still exported - retention changes what's *visible in routine queries*, not what's *exportable history* for a specific actor or resource. `archivedAt` is included per record (via the reused `AuditEventOut` schema) so a recipient can see which records were archived at export time. (This function also serves `GET /audit/compliance/account-access`, which needs the same "filtered, archive-inclusive" shape with an additional `resourceType` filter - see `docs/requirements.md` Scenario C.)

## 6. Redaction: redacted values are never re-exposed

No special handling was needed here, by construction: redaction (`docs/redaction-design.md`) tombstones a sensitive field's value **in the stored row itself** — the original value is gone from `payload`, replaced with `"[REDACTED]"`, before export ever runs. `export_events()` reads the *current* stored `payload` via the same `AuditEvent` rows every other read path uses; there is no separate, unredacted copy anywhere for export to accidentally reach. `redactedAt`/`redactedFields` are included (again via the reused `AuditEventOut` schema, which already deliberately excludes `redactedFieldHashes` from any API response — see `docs/redaction-design.md` §6's low-entropy caveat) so the recipient knows a record was redacted rather than silently seeing a bare marker with no context. `tests/test_export.py::test_export_redacted_record_shows_marker_not_original_value` confirms the original value never appears in an exported bundle.

## 7. Filter validation

`GET /audit/export` requires at least one of `actorId`/`resourceId` (empty strings rejected too, via `Query(min_length=1)`); providing neither is a 422, not an unbounded full-log dump. Both may be supplied together (`AND` semantics, matching `GET /audit/events`'s existing filter combination behavior) for a narrower export. No other filters (`eventType`, time range) are supported for export — not asked for, and out of scope for this increment.

## 8. Trade-offs and limitations, summarized

- **No pagination or size bound on export** — a filter matching a very large history returns one large response. Not implemented; acceptable for a prototype, worth revisiting if this becomes a real operational concern.
- **The manifest hash is a plain SHA-256, not a signature or HMAC** — protects against careless/accidental post-export corruption, not a fully capable attacker with the bundle in hand (§2, §3). Consistent with, not weaker than, every other integrity mechanism already in this service.
- **Completeness is not provable from the bundle** (§4) — only re-querying the live service can confirm no matching record was silently omitted.
- **An export is a point-in-time snapshot** — subsequent legitimate retention/redaction on the same records isn't reflected and isn't something the bundle can detect on its own (§4).
- **Authorization** for *who* may export was open when this was first written; it's since been decided project-wide - `GET /audit/export` requires the `auditor` or `admin` role (see `docs/authorization-design.md`), and is additionally rate-limited (see `docs/defensive-limits-design.md`).
- **Not covered:** export formats other than JSON (e.g. CSV, a signed PDF) — `docs/assumptions.md`'s "Export format" item is resolved to JSON with the bundle described here.
