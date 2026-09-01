import hashlib
import json
from datetime import datetime
from typing import Any

# Placeholder previous_hash for the first record in the chain, chosen as a
# fixed all-zeros value of the same length as a SHA-256 hex digest (64 chars)
# per docs/architecture.md's hash-chain design.
GENESIS_HASH = "0" * 64


def canonicalize(data: dict[str, Any]) -> bytes:
    """Deterministic byte representation of event content for hashing.

    Sorted keys and fixed separators make the same logical event always
    produce the same bytes, regardless of dict insertion order or
    incidental whitespace differences, so the hash is reproducible later
    during chain verification.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_event_hash(
    *,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any],
    timestamp: datetime,
    previous_hash: str,
) -> str:
    content = {
        "eventType": event_type,
        "actorId": actor_id,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "payload": payload,
        "timestamp": timestamp.isoformat(),
        "previousHash": previous_hash,
    }
    return hashlib.sha256(canonicalize(content)).hexdigest()


def hash_field_value(value: Any) -> str:
    """SHA-256 of a single value's canonical JSON representation.

    Reuses canonicalize() rather than a separate algorithm. Used to retain
    a verifiable commitment to a redacted payload field's original value
    (see app/services/redaction_service.py) without storing the value
    itself. Wrapping in {"value": value} lets any JSON-serializable value
    (not just dicts) go through the same canonicalize() function.
    """
    return hashlib.sha256(canonicalize({"value": value})).hexdigest()


def compute_manifest_hash(entries: list[dict[str, Any]]) -> str:
    """SHA-256 over an ordered list of entries, reusing canonicalize().

    Used to give a bundle of records (see app/services/export_service.py)
    a single self-consistency commitment over exactly which records, in
    what order, with what event_hash values, it contains - so a recipient
    can detect a record being added, removed, reordered, or swapped after
    export without needing every individual record's content.
    """
    return hashlib.sha256(canonicalize({"entries": entries})).hexdigest()
