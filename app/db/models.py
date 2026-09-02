from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint

from app.db.base import Base


class AuditEvent(Base):
    """An append-only audit record. No update/delete columns or methods are
    provided anywhere in this codebase — records are only ever inserted."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # The tenant this record belongs to, always derived server-side from
    # the authenticated writer's configured tenant (never client-supplied
    # - see app/api/routes/audit_events.py) so it can't be forged. Part of
    # the hashed content (see app/services/hashing.py), so tampering with
    # it directly in the DB is caught like any other field. Used to scope
    # a reader's queries to their own tenant (see
    # docs/authorization-design.md) - auditor/admin reads are deliberately
    # not filtered by it.
    tenant_id = Column(String(100), nullable=False, index=True)
    # Indexed: all four are query filters on GET /audit/events, and this
    # log is expected to grow large, so filtering needs to use an index
    # rather than a full table scan.
    event_type = Column(String(100), nullable=False, index=True)
    actor_id = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    # Linearity of the chain (at most one record follows any given record)
    # is enforced by serializing appends with the advisory lock in the
    # repository layer, not by a DB constraint here (see
    # app/repositories/audit_event_repository.py) - a unique constraint
    # would rule out future designs (e.g. retention/redaction) that may
    # need more than one record to reference the same previous_hash.
    # Indexed since it's looked up when validating/walking the chain.
    previous_hash = Column(String(64), nullable=False, index=True)
    event_hash = Column(String(64), nullable=False, unique=True)

    # Retention metadata: NULL means active, a timestamp means the record
    # was archived (soft-deleted) by retention, and when. Deliberately not
    # part of the hashed content - compute_event_hash() never reads this
    # column, so archiving a record can never change its event_hash and can
    # never affect chain verification (see
    # app/services/retention_service.py).
    archived_at = Column(DateTime(timezone=True), nullable=True, index=True)

    # Redaction metadata. NULL means never redacted. Once set, event_hash is
    # deliberately left as it was computed at write time (never
    # recomputed) - it's what chain_verification_service still checks the
    # *next* record's previous_hash against, so the link is unaffected.
    # Only the content-hash recompute check is skipped for a record with
    # redacted_at set, since its payload was intentionally changed after
    # that hash was computed (see app/services/redaction_service.py and
    # docs/redaction-design.md).
    redacted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    # Top-level payload keys redacted so far (cumulative across repeated
    # redaction calls on the same record).
    redacted_fields = Column(JSON, nullable=True)
    # {field_name: sha256(canonical(original_value))}, captured at the
    # moment of redaction, before the value is overwritten. Not required
    # for chain-link integrity - an optional stronger-verification aid: if
    # the true original value is ever disclosed out of band (e.g. during a
    # legal process), hashing it and comparing against this stored value
    # confirms it's genuinely what was redacted, without this record ever
    # having to retain the value itself. Not exposed via the query API (see
    # docs/redaction-design.md for why).
    redacted_field_hashes = Column(JSON, nullable=True)


class IdempotencyKey(Base):
    """Records that a given (username, idempotency_key) pair has already
    produced a specific audit event, so a retried POST /audit/events can be
    recognized and answered without appending a second event (see
    app/services/audit_event_service.py and docs/idempotency-design.md).

    Deliberately a separate table from audit_events, not extra columns on
    it: this is bookkeeping for the write API's retry safety, not part of
    the audit record itself, and is never read by chain verification.

    The unique constraint on (username, idempotency_key) is a DB-enforced
    backstop for the exact invariant this feature exists to guarantee -
    matching the precedent already set by event_hash's own unique=True
    above. It is expected to never actually fire: create_audit_event()
    always calls lock_for_append() first, which already fully serializes
    every append (idempotent or not) via a single global advisory lock, so
    two concurrent requests can never both pass the "is this key already
    used" check before either has committed. If this constraint is ever
    violated in practice, that means the locking discipline was bypassed
    somewhere - a real bug worth a loud failure, not a case to silently
    handle here.
    """

    __tablename__ = "audit_event_idempotency_keys"
    __table_args__ = (UniqueConstraint("username", "idempotency_key", name="uq_idempotency_username_key"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False, index=True)
    idempotency_key = Column(String(255), nullable=False)
    # SHA-256 over the caller-supplied request content (see
    # app/services/hashing.py:compute_request_fingerprint) - compared
    # against a retry's own fingerprint to distinguish a legitimate replay
    # from a conflicting reuse of the same key with different content.
    request_fingerprint = Column(String(64), nullable=False)
    event_id = Column(Integer, ForeignKey("audit_events.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
