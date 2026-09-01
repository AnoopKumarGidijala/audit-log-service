from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session

from app.repositories import audit_event_repository as repo
from app.services.hashing import GENESIS_HASH, compute_event_hash


class ChainViolationType(str, Enum):
    # This record's stored event_hash no longer matches a hash recomputed
    # from its own current stored content - the record itself was changed.
    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    # This record's stored previous_hash doesn't match the previous record's
    # (verified) event_hash, or the genesis value for the first record - the
    # link between two records is broken, even though each record considered
    # on its own is internally consistent.
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"


@dataclass
class ChainViolation:
    record_id: int
    violation_type: ChainViolationType
    detail: str


@dataclass
class ChainVerificationResult:
    intact: bool
    records_checked: int
    violation: ChainViolation | None


def verify_chain(db: Session) -> ChainVerificationResult:
    """Walk the full chain from the beginning and check every record.

    For each record, in order:
      1. Recompute its hash from its own current stored content (using the
         same compute_event_hash() used at write time) and compare against
         the stored event_hash - catches a record whose content was changed
         directly in the database.
      2. Compare its stored previous_hash against the expected value: the
         genesis value for the first record, or the previous record's
         event_hash otherwise - catches a broken link between two records
         that are each individually self-consistent (e.g. a record whose
         previous_hash was changed and its own event_hash "re-signed" to
         match, without updating the record that follows it).

    Stops at the first record that fails either check and reports it, since
    every record's own validity (in check 2) depends on already having
    confirmed the previous record passed both checks - there's no point
    continuing once the chain of trust is broken.
    """
    events = repo.list_all_events(db)

    expected_previous_hash = GENESIS_HASH
    for index, event in enumerate(events):
        recomputed_hash = compute_event_hash(
            event_type=event.event_type,
            actor_id=event.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            payload=event.payload,
            timestamp=event.timestamp,
            previous_hash=event.previous_hash,
        )
        if recomputed_hash != event.event_hash:
            return ChainVerificationResult(
                intact=False,
                records_checked=index + 1,
                violation=ChainViolation(
                    record_id=event.id,
                    violation_type=ChainViolationType.EVENT_HASH_MISMATCH,
                    detail=(
                        f"Recomputed hash {recomputed_hash!r} does not match the stored "
                        f"event_hash {event.event_hash!r} for record {event.id}."
                    ),
                ),
            )

        if event.previous_hash != expected_previous_hash:
            return ChainVerificationResult(
                intact=False,
                records_checked=index + 1,
                violation=ChainViolation(
                    record_id=event.id,
                    violation_type=ChainViolationType.PREVIOUS_HASH_MISMATCH,
                    detail=(
                        f"Record {event.id}'s stored previous_hash {event.previous_hash!r} does "
                        f"not match the expected value {expected_previous_hash!r} (the prior "
                        f"record's event_hash, or the genesis value for the first record)."
                    ),
                ),
            )

        expected_previous_hash = event.event_hash

    return ChainVerificationResult(intact=True, records_checked=len(events), violation=None)
