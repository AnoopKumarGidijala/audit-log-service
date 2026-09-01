from sqlalchemy import JSON, Column, DateTime, Integer, String

from app.db.base import Base


class AuditEvent(Base):
    """An append-only audit record. No update/delete columns or methods are
    provided anywhere in this codebase — records are only ever inserted."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
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
