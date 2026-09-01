from sqlalchemy import JSON, Column, DateTime, Integer, String

from app.db.base import Base


class AuditEvent(Base):
    """An append-only audit record. No update/delete columns or methods are
    provided anywhere in this codebase — records are only ever inserted."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(100), nullable=False)
    actor_id = Column(String(255), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=False)
    payload = Column(JSON, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    # Linearity of the chain (at most one record follows any given record)
    # is enforced by serializing appends with the advisory lock in the
    # repository layer, not by a DB constraint here (see
    # app/repositories/audit_event_repository.py) - a unique constraint
    # would rule out future designs (e.g. retention/redaction) that may
    # need more than one record to reference the same previous_hash.
    # Indexed since it's looked up when validating/walking the chain.
    previous_hash = Column(String(64), nullable=False, index=True)
    event_hash = Column(String(64), nullable=False, unique=True)
