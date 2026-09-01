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
