from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from app.repositories import audit_event_repository as repo
from app.services.hashing import GENESIS_HASH, compute_event_hash
from app.services.redaction_service import REDACTION_EVENT_TYPE


class ChainViolationType(str, Enum):
    # This record's stored event_hash no longer matches a hash recomputed
    # from its own current stored content - the record itself was changed.
    EVENT_HASH_MISMATCH = "EVENT_HASH_MISMATCH"
    # This record's stored previous_hash doesn't match the previous record's
    # (verified) event_hash, or the genesis value for the first record - the
    # link between two records is broken, even though each record considered
    # on its own is internally consistent.
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    # This record was redacted, but its current content no longer matches
    # the approved post-redaction commitment recorded at redaction time -
    # a non-redacted field was changed, or the redacted field was changed
    # to something other than the approved marker, after redaction.
    REDACTED_CONTENT_MISMATCH = "REDACTED_CONTENT_MISMATCH"
    # This record is flagged redacted (redacted_at is set) but no companion
    # AUDIT_EVENT_REDACTED event with a matching commitment exists anywhere
    # in the chain - the redacted_at flag was set without going through the
    # real redaction path.
    REDACTION_COMMITMENT_MISSING = "REDACTION_COMMITMENT_MISSING"


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


def _content_hash(event: AuditEvent) -> str:
    return compute_event_hash(
        event_type=event.event_type,
        actor_id=event.actor_id,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        payload=event.payload,
        timestamp=event.timestamp,
        previous_hash=event.previous_hash,
    )


def _latest_redaction_commitments(events: list[AuditEvent]) -> dict[int, str]:
    """Map targetEventId -> the most recently committed redactedContentHash,
    sourced from AUDIT_EVENT_REDACTED companion events.

    A companion event's payload is only trusted here if the companion
    event's OWN content is currently internally consistent (its own
    recomputed hash still matches its own stored event_hash) - a companion
    event whose payload was tampered with directly is not a source of
    truth for anything, so its (possibly forged) commitment is excluded
    rather than trusted. That tampering is still guaranteed to surface as
    intact=False: if this exclusion causes a redacted record to have no
    trustworthy commitment, the main walk below reports
    REDACTION_COMMITMENT_MISSING for it; a companion event that hasn't
    (yet, in walk order) been implicated this way is still checked as an
    ordinary record by the main walk's own EVENT_HASH_MISMATCH check
    regardless. Walking in ascending id order and letting a later
    companion event overwrite an earlier one for the same target correctly
    keeps only the commitment for a record's current content, even if it's
    been redacted more than once.
    """
    commitments: dict[int, str] = {}
    for event in events:
        if event.event_type == REDACTION_EVENT_TYPE and _content_hash(event) == event.event_hash:
            target_id = event.payload.get("targetEventId")
            commitment = event.payload.get("redactedContentHash")
            if target_id is not None and commitment is not None:
                commitments[target_id] = commitment
    return commitments


def verify_chain(db: Session) -> ChainVerificationResult:
    """Walk the full chain from the beginning and check every record.

    For each record, in order:
      1. Content check.
         - Not redacted: recompute its hash from its own current stored
           content (using the same compute_event_hash() used at write
           time) and compare against the stored event_hash - catches a
           record whose content was changed directly in the database.
         - Redacted (redacted_at is set): event_hash was computed over the
           pre-redaction content and is deliberately never recomputed or
           touched again, so comparing against it would always "fail" by
           design. Instead, recompute a hash of the record's CURRENT
           content and compare against the redactedContentHash commitment
           recorded in its companion AUDIT_EVENT_REDACTED event (see
           app/services/redaction_service.py and
           docs/redaction-design.md). This still catches tampering with
           any field that wasn't part of the authorized redaction - the
           only content change treated as expected is exactly the
           redaction that was actually logged.
      2. Compare its stored previous_hash against the expected value: the
         genesis value for the first record, or the previous record's
         event_hash otherwise - catches a broken link between two records
         that are each individually self-consistent. This uses the
         record's real, original, never-modified event_hash regardless of
         whether it's been redacted - redaction never affects chain
         linkage.

    Stops at the first record that fails any check and reports it, since
    every record's own validity depends on already having confirmed the
    previous record passed - there's no point continuing once the chain of
    trust is broken.
    """
    events = repo.list_all_events(db)
    redaction_commitments = _latest_redaction_commitments(events)

    expected_previous_hash = GENESIS_HASH
    for index, event in enumerate(events):
        if event.redacted_at is None:
            recomputed_hash = _content_hash(event)
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
        else:
            commitment = redaction_commitments.get(event.id)
            if commitment is None:
                return ChainVerificationResult(
                    intact=False,
                    records_checked=index + 1,
                    violation=ChainViolation(
                        record_id=event.id,
                        violation_type=ChainViolationType.REDACTION_COMMITMENT_MISSING,
                        detail=(
                            f"Record {event.id} is marked redacted (redacted_at is set) but no "
                            f"companion AUDIT_EVENT_REDACTED event with a matching commitment "
                            f"was found in the chain."
                        ),
                    ),
                )
            recomputed_current_hash = _content_hash(event)
            if recomputed_current_hash != commitment:
                return ChainVerificationResult(
                    intact=False,
                    records_checked=index + 1,
                    violation=ChainViolation(
                        record_id=event.id,
                        violation_type=ChainViolationType.REDACTED_CONTENT_MISMATCH,
                        detail=(
                            f"Record {event.id}'s current content hashes to "
                            f"{recomputed_current_hash!r}, which does not match the approved "
                            f"post-redaction commitment {commitment!r} recorded at redaction "
                            f"time - a field outside the authorized redaction was changed."
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
