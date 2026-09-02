# Structured Redaction — Design

Scenario B, `docs/requirements.md` item 9 (`B2`). This document reviews the current hash-chain design, analyzes the practical options for redacting sensitive `payload` fields without invalidating chain verification, and records the chosen approach, the alternatives considered, and its trade-offs and limitations. The implementation follows this design (see `app/services/redaction_service.py`, `app/db/models.py`, `app/services/chain_verification_service.py`).

## 1. The problem, precisely

`app/services/hashing.py::compute_event_hash()` computes a single SHA-256 over a canonical JSON representation of `eventType`, `actorId`, `resourceType`, `resourceId`, the **entire `payload` dict**, `timestamp`, and `previousHash`. That hash is stored as `event_hash`. Verification (`app/services/chain_verification_service.py::verify_chain()`) walks every record in `id` order and, for each one, recomputes this same hash from the record's *current* stored content and compares it to the stored `event_hash`.

This means: changing **any** byte of `payload` changes the record's `event_hash`. If a sensitive field inside `payload` is blanked directly, a plain recompute will no longer match the stored `event_hash` — verification will report `EVENT_HASH_MISMATCH`, indistinguishable from actual tampering. That is the conflict item 9 names, and it is a real cryptographic constraint, not a bug: SHA-256 over a flat blob gives no way to prove "only field X changed, nothing else did" against a hash computed before the change. Any design has to work around this, not through it.

A second constraint, stated explicitly by the user for this design: **the hashing rules, and the verifiability of every record already written, must not silently change.** All records created so far (Scenario A, retention) were hashed with the rule above. Whatever is chosen has to keep working for them without modification, migration, or re-hashing.

## 2. What "remains" for verification, concretely, no matter which option is picked

- The **chain link** (`previous_hash` pointing at the true previous record's `event_hash`) is a separate, independent check from the content-hash check. Nothing about redaction needs to touch `previous_hash`/`event_hash` of *any* record — those values are what downstream records and verification actually trust for ordering/linkage. Any workable design should leave them alone.
- The **content-hash check** is what's fundamentally in tension with redaction. The real design question is: what happens to that specific check for a record whose payload has been intentionally, legitimately modified?

## 3. Alternatives considered

### A. Field-level (Merkle-style) hashing of the payload

Instead of hashing the payload as one blob, compute a per-field hash at write time (`{fieldName: sha256(canonical(value))}`), and feed a *digest* of that map into `compute_event_hash()` instead of the raw payload. To redact a field, blank its raw value but keep its stored per-field hash — the digest, and therefore `event_hash`, is unaffected, because it was never a function of the raw value directly. Verification can still confirm every *non-redacted* field's value hashes to its stored commitment.

**Why not chosen (for this increment):** this changes what `compute_event_hash()` hashes — a new hash format. Records already written were hashed over the raw payload directly; there is no way to retroactively decompose an already-computed `sha256(raw_payload_json)` into a per-field commitment structure and get the same digest. **This can only apply to records created after the new format is introduced.** Every record that exists today (and any created before adoption) would be permanently excluded from ever being redactable under this scheme — a real problem, since redaction requests (e.g. "erase this customer's data") apply to old data at least as often as new. It also requires a hash-version field and branching verification logic to keep both formats alive side by side, adding real complexity for a prototype.

**Where it's the right answer:** the strongest guarantee (can still prove non-redacted fields are untouched, per-field, after redaction) is genuinely worth it once the format-versioning cost is justified — noted below as the natural upgrade path.

### B. Frozen event_hash + payload tombstone + mandatory companion audit event carrying a content commitment — chosen

Never recompute or touch a record's `event_hash`/`previous_hash`. To redact, overwrite the specific payload key(s) in place with a tombstone marker, record when/which fields were redacted as metadata on the row, and — through the *existing, unmodified* write path — append a normal audit event describing the redaction (who, when, which fields, why). That companion event's payload also carries `redactedContentHash`: a fresh commitment, computed with the same `compute_event_hash()` logic, over the record's *entire current* (post-redaction) content. Verification, for a redacted record, stops comparing against the frozen original `event_hash` (which is expected not to match post-redaction content, by design) and instead recomputes the record's current content hash and checks it against this commitment — so every field that *wasn't* part of the authorized redaction is still fully verified, not just the chain link.

**Why chosen:** it requires no change to `compute_event_hash()`, `canonicalize()`, or the hash format at all — every record ever written, including all of Scenario A's and retention's existing rows, is immediately eligible for redaction with zero migration. The commitment is carried by an *ordinary* event (never itself redacted), so it's automatically covered by the existing, unmodified content-hash check the moment `verify_chain()` reaches that companion record in its own right — no separate signing mechanism was needed to protect it. For every record that's never been redacted (today, that's all of them), verification runs through the exact same code path as before, byte-for-byte. This is what makes the backward-compatibility requirement trivially satisfied rather than carefully engineered around, while still giving redacted records materially more protection than "just skip the check."

### C. Crypto-shredding (encrypt sensitive fields at write time; redaction = destroy the key)

Store sensitive `payload` fields as ciphertext from the start (per-record or per-field data key, stored separately). "Redacting" a field means deleting its key — the ciphertext bytes in `payload` never change, so `event_hash` never needs touching at all, and `verify_chain()` needs *no* changes whatsoever, not even Option B's small guard.

**Why not chosen:** elegant, and a legitimate production answer, but (like A) it only protects fields that were encrypted **at write time** — it cannot retroactively apply to any already-written plaintext record, including everything in this database today. It also needs real key-management infrastructure (a key store, at minimum, ideally a KMS) to be worth anything, which is more than "a design appropriate for this prototype" calls for. Worth revisiting if this service moves toward production and sensitive fields can be identified in advance.

### D. Just blank the field and accept the chain-break report

Rejected outright — this is precisely the false integrity failure the requirement says must not happen. Noted only for completeness.

## 4. Comparison

| | A: Field-level hashing | B: Frozen hash + tombstone (chosen) | C: Crypto-shredding |
|---|---|---|---|
| Works on records that already exist | No — format-incompatible | **Yes, immediately** | No — never encrypted |
| Changes `compute_event_hash()` / hash format | Yes (versioned) | No | No |
| Change to `verify_chain()` | New branch per hash version | Additive branch + commitment lookup | None |
| Provable after redaction | Non-redacted fields, per-field, always | Non-redacted fields (and the redacted marker itself), via a companion commitment | Full record (still just ciphertext) |
| New infrastructure needed | Hash versioning | None (reuses `compute_event_hash()`) | Key store / KMS |
| Appropriate for this prototype | Not now (real future upgrade) | **Yes** | Not now |

## 5. Chosen design, in detail

### Schema (`app/db/models.py`)

Three new nullable columns on `AuditEvent`, the same additive pattern as retention's `archived_at`:

- `redacted_at: DateTime(timezone=True)` — `NULL` = never redacted; a timestamp = when last redacted.
- `redacted_fields: JSON` — the cumulative list of top-level payload keys redacted so far.
- `redacted_field_hashes: JSON` — `{fieldName: sha256(canonical(originalValue))}`, captured immediately before each field is overwritten (see §6).

None of these three columns are read by `compute_event_hash()`. That is the entire mechanism: redaction cannot, by construction, change what any record's `event_hash` was computed from.

### Operation (`app/services/redaction_service.py::redact_event_fields()`)

1. Look up the target record.
2. For each requested field that both (a) exists in the current payload and (b) hasn't already been redacted, hash its current value (`hash_field_value()`, reusing `canonicalize()` from `app/services/hashing.py` — no second hashing algorithm) and record the hash (§6 - this is the *disclosed-value* commitment, independent of what follows).
3. Overwrite those fields in `payload` with a tombstone marker (`"[REDACTED]"`); leave every other key untouched.
4. Compute `redacted_content_hash = compute_event_hash(eventType, actorId, resourceType, resourceId, <new payload>, timestamp, previous_hash)` — the *same function* used for the record's real `event_hash`, just fed the post-redaction payload instead of the original one. This is the "approved post-redaction representation": a single commitment to everything the record is now allowed to contain.
5. Persist the new payload plus the redaction metadata via `app/repositories/audit_event_repository.py::redact_event_fields()` — a narrow function that only ever touches these specific columns, never `event_hash`/`previous_hash`/`timestamp`.
6. Append a normal audit event (`eventType: "AUDIT_EVENT_REDACTED"`, `resourceType: "AUDIT_EVENT"`, `resourceId: <target id>`, payload naming the target event, the fields redacted, and `redactedContentHash`) through the ordinary, unmodified `audit_event_service.create_audit_event()` write path.

Step 6 is what makes the commitment from step 4 itself tamper-evident: it isn't stored anywhere unprotected. It travels inside a normal event's `payload`, and that event gets its own `event_hash` over that payload exactly like any other event — so tampering with the commitment later is caught by the ordinary content-hash check applied to the companion event, not by anything redaction-specific. The redaction is a normal, permanently queryable, hash-chained log entry (`GET /audit/events?resourceType=AUDIT_EVENT&resourceId=<id>`), never itself redacted.

Requesting redaction of an already-redacted field is a no-op for that field (guarded explicitly in `redaction_service.py`) — recomputing a hash over the tombstone value instead of the true original would silently destroy the one commitment that made §6 meaningful. Redacting a record more than once (different fields each time) appends a new companion event each time, with a fresh `redactedContentHash` covering the record's full state as of that call - verification always uses the *most recent* commitment for a given record (see below).

### Verification (`app/services/chain_verification_service.py::verify_chain()`)

Before the main walk, verification builds a lookup of `targetEventId -> redactedContentHash`, sourced from every `AUDIT_EVENT_REDACTED` companion event **whose own content is currently internally consistent** (its own recomputed hash still matches its own stored `event_hash` — a companion event that's been tampered with directly is not trusted as a source of truth for anything). If a record was redacted more than once, walking in ascending `id` order and letting a later companion overwrite an earlier one for the same target naturally keeps only the latest commitment.

```python
for event in events:
    if event.redacted_at is None:
        recomputed = compute_event_hash(... event's current content ...)
        if recomputed != event.event_hash:
            ...EVENT_HASH_MISMATCH...                        # unchanged from before this design
    else:
        commitment = redaction_commitments.get(event.id)
        if commitment is None:
            ...REDACTION_COMMITMENT_MISSING...                # new: flagged redacted, but no trustworthy commitment exists
        recomputed = compute_event_hash(... event's current content ...)
        if recomputed != commitment:
            ...REDACTED_CONTENT_MISMATCH...                   # new: something outside the authorized redaction changed

    if event.previous_hash != expected_previous_hash:          # unchanged, always runs, uses the frozen original event_hash
        ...PREVIOUS_HASH_MISMATCH...

    expected_previous_hash = event.event_hash                  # unchanged - the frozen original value, never the commitment
```

For a record that's never been redacted (every record today), this is byte-for-byte the same code path as before this design existed. For a redacted record, the content check now still runs — just against a different, but equally chain-protected, expected value.

**A structural attribution note:** because a redaction's companion event always has a *higher* `id` than the record it targets (you can only redact a record that already exists), and verification stops at the *first* record (in ascending `id` order) that fails any check, a corrupted companion event's own tampering is discovered *at the target it was backing*, not at the companion's own `id` - see `tests/test_redaction.py::test_verify_detects_tampering_with_companion_event_commitment`. The chain is still correctly reported as broken either way (`intact: false`); only the specific record/violation-type attributed can point at the record whose *trust* was compromised rather than the record whose *bytes* were. This is an inherent consequence of "stop at the first inconsistency" combined with commitments always arriving after their target, not a gap in what's detected.

## 6. The optional per-field hash, and its limits

`redacted_field_hashes` is not required for the chain to stay linked or verifiable; it's an added integrity aid. If a field's true original value is ever disclosed out of band (e.g. during a legal or compliance process), hashing the disclosed value and comparing it to the stored commitment independently confirms it's genuinely what was redacted — without this record ever having had to retain the value itself.

**Limitation:** a bare hash only protects a value with enough entropy to resist brute-forcing. For a low-entropy field (a short PIN, a small enum, a yes/no flag), an attacker could simply hash every possible value and find a match — the hash doesn't actually keep such a value secret. The standard mitigation (a per-field salt and a slow KDF such as bcrypt/scrypt/Argon2) is not implemented here; this is disclosed as a known gap for anyone relying on `redacted_field_hashes` for a low-entropy field, not solved in this increment. It's why `redacted_field_hashes` is deliberately **not** exposed via `AuditEventOut` / `GET /audit/events` — keeping it out of routine API responses narrows who can even attempt that brute-force, though it doesn't eliminate the underlying limitation for an operator with direct DB access.

## 7. What an attacker could and could not change undetected

- **A record that has never been redacted:** exactly as much protection as before this design existed. Any content change is caught by the (unmodified) content-hash check; any reordering/relinking is caught by the (unmodified) link check. Zero change in protection — this is the overwhelming majority of records.
- **A record after it has been legitimately redacted - a non-redacted field changed:** detected. Verification recomputes the record's *current* content hash and checks it against the `redactedContentHash` commitment from its companion event; any field other than the one(s) actually authorized for redaction is still fully covered (`REDACTED_CONTENT_MISMATCH` — verified in `tests/test_redaction.py::test_verify_detects_tampering_on_a_non_redacted_field_of_a_redacted_record`).
- **The redacted field changed to something other than the approved marker** (e.g. planting a fake "unredacted" value): also detected, by the same check — the marker's exact value is itself part of what the commitment covers (`tests/test_redaction.py::test_verify_detects_tampering_on_the_redacted_field_itself`).
- **The companion event's own commitment tampered with directly:** detected — `intact: false` either way, since a companion event whose own content no longer matches its own `event_hash` is excluded as untrustworthy before its commitment is used for anything (`tests/test_redaction.py::test_verify_detects_tampering_with_companion_event_commitment`). One nuance, not a gap: because the companion always has a higher `id` than its target and verification stops at the first record (ascending `id`) that fails, this surfaces as `REDACTION_COMMITMENT_MISSING` at the *target*, not as `EVENT_HASH_MISMATCH` at the companion - see the attribution note in §5.
- **A forged redaction (`redacted_at` set directly via SQL, no real companion event created):** detected as `REDACTION_COMMITMENT_MISSING` - a record can no longer silently gain content-hash exemption just by having its flag set (`tests/test_redaction.py::test_verify_detects_forged_redaction_flag_without_companion_event`). This closes the gap noted as an unimplemented "future strengthening" in the previous revision of this document.
- **What remains out of reach, and always will without a signing key:** an attacker with full, unrestricted database write access who *also* correctly recomputes every hash a genuine redaction would have produced - a fully "resigned" forgery (new payload, a matching `event_hash`... no, `event_hash` itself is never touched, so this specifically means: a matching, internally-consistent companion event *and* correctly re-linking whatever comes after it, if anything does) is cryptographically indistinguishable from a real one. This is not new to redaction - it has been true of `event_hash`/`previous_hash` since Scenario A. No design considered here (nor Option A, nor C) changes this: none of them involve a private signing key, so all of them ultimately assume the threat model is *detecting careless/accidental/unauthorized* modification, not defending against an attacker who has both full DB access and full knowledge of (freely available, public) hashing logic and is willing to recompute an entire consistent forged segment.

## 8. Trade-offs and limitations, summarized

- **Strength:** works immediately and identically on every record that exists today, with no migration, no re-hashing, and no hash-format versioning — a genuine advantage over both other alternatives considered.
- **Strength:** zero behavior change for any record that is never redacted (which is most of them) — the backward-compatibility requirement is met by construction, not by careful special-casing.
- **Strength (revised from the previous version of this design):** a redacted record's content-hash coverage is *not* switched off entirely - only the specific field(s) actually authorized for redaction are exempt. Tampering with anything else on that record, including replacing the redaction marker itself, is still caught (§7). The commitment that makes this possible is itself protected by the ordinary hash chain, with no new cryptographic mechanism (signing, MACs) introduced.
- **Limitation:** still weaker than Option A's guarantee in one specific way - Option A can prove a non-redacted field's value *individually*, field by field; this design proves the record's *entire current content* against one combined commitment. In practice this distinction rarely matters (any change is still caught either way), but Option A's per-field granularity would let a verifier confirm one specific field without needing the commitment to cover the whole record. Noted as the remaining edge Option A has, not a functional gap in what tampering is detected.
- **Limitation:** the redacted value's raw content is gone from primary storage permanently — that's the intent, not a bug, but worth being explicit that nothing here recovers it. Only the optional field-hash commitment (§6) survives, and only for verifying a value disclosed from elsewhere.
- **Limitation:** the optional per-field hash doesn't safely protect low-entropy values without added salting/KDF work not done here (§6).
- **Limitation:** the redaction-and-companion-event pair is committed in two separate transactions (the payload update, then the audit-event write), not one atomic transaction — reusing the existing `create_audit_event()` write path as-is rather than duplicating its internals to force full atomicity. In the rare case of a crash between the two, a field could show as redacted slightly before its companion log entry is durable; the chain itself stays fully consistent either way, and this does not open any tampering window, only a small bookkeeping lag. Considered an acceptable simplification for this prototype.
- **Limitation (attribution, not detection):** when a companion event itself is tampered with, the violation surfaces at its target record (`REDACTION_COMMITMENT_MISSING`), not at the companion's own `id` - see the attribution note in §5. The chain is still correctly reported broken; only which record gets named can point one step away from where the bytes actually changed.
- **Not a new limitation, but worth restating:** this design (like every other integrity mechanism in this service) assumes the threat model is *detecting* unauthorized modification of stored data, not preventing an attacker with full, unrestricted database write access and full knowledge of the (public) hashing logic from recomputing an entire self-consistent forged segment. That has been true of `event_hash`/`previous_hash` since Scenario A; redaction doesn't change that boundary (§7).
- **Upgrade path, if ever needed:** adopt Option A (field-level hashing, versioned) for records created going forward, once per-field (rather than whole-record) provability is worth the format-versioning cost. Existing records (including any redacted under this design) stay on the current scheme permanently — that's not a bug either, it's the same reason B was chosen over A in the first place.

## 9. Not covered by this design

- Authorization for *who* may call the redaction endpoint was open when this design was first written; it's since been decided project-wide (not specific to redaction) - `POST /audit/events/{id}/redact` requires the `admin` role. See `docs/authorization-design.md`.
- Nested/deep redaction within a payload field's own structure — this design only redacts top-level `payload` keys, matching requirements.md item 9's "fields inside a record's payload."
- Retention interaction: redaction and archival (`archived_at`) are independent, orthogonal metadata — a record can be archived, redacted, both, or neither, and neither operation checks the other's flag. Not something this increment needed to resolve further.
