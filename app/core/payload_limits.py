"""Structural limits on an audit event's `payload` field (see
docs/defensive-limits-design.md). Pure functions, deliberately independent
of Pydantic/FastAPI and of app.core.config - callers (app/schemas/audit_event.py)
supply the configured thresholds explicitly, the same pattern already used
by app/services/hashing.py's functions, so these are trivially unit-testable
without needing a Settings instance or a running app.

Note on ordering: depth and string-length checks walk the payload as
Python objects, which by the time a Pydantic validator runs have already
been fully parsed from JSON - these checks cannot prevent the cost of
that initial parse for a single oversized request. app/core/body_size_limit.py
covers that gap at the transport layer, before parsing, as a coarser,
complementary check.
"""

import json
from typing import Any


def compute_payload_byte_size(payload: dict[str, Any]) -> int:
    """The payload's own serialized size, independent of the surrounding
    request envelope (other fields, headers). Uses compact separators
    (no extra whitespace) - the smallest faithful JSON representation, so
    this is a lower bound on the size a client's raw request body could
    achieve, not an overestimate that would reject borderline-legitimate
    payloads.
    """
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def compute_payload_depth(value: Any) -> int:
    """How many levels of nested dict/list `value` contains. A bare
    scalar contributes no depth of its own - only a dict or list wrapping
    something adds one level - so a flat dict/list of scalars is depth 1,
    and each further level of dict/list nesting adds one: `{"a": 1}` is
    depth 1, `{"a": {"b": 1}}` is depth 2, `{"a": [1, 2]}` is depth 2.
    An empty dict/list, or any non-container scalar, is depth 0.
    """
    if isinstance(value, dict) and value:
        return 1 + max(compute_payload_depth(v) for v in value.values())
    if isinstance(value, list) and value:
        return 1 + max(compute_payload_depth(v) for v in value)
    return 0


def payload_has_overlong_string(value: Any, *, max_length: int) -> bool:
    """Whether `value` contains any string - a scalar value, or (since a
    JSON object's keys are also strings a caller controls) a dict key, at
    any nesting depth - longer than max_length.
    """
    if isinstance(value, str):
        return len(value) > max_length
    if isinstance(value, dict):
        return any(
            payload_has_overlong_string(k, max_length=max_length)
            or payload_has_overlong_string(v, max_length=max_length)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return any(payload_has_overlong_string(v, max_length=max_length) for v in value)
    return False
