"""Tests for the defensive limits on POST /audit/events (see
docs/defensive-limits-design.md): payload byte size, nesting depth,
string length, identity-field length, and the whole-request body size
cap. Each "outside the limit" test is constructed to trip exactly one
limit at a time, so a failure points at a specific check.

Uses the default limits from Settings (no .env.test override needed):
MAX_PAYLOAD_BYTES=16384, MAX_PAYLOAD_DEPTH=10,
MAX_PAYLOAD_STRING_LENGTH=2000, MAX_REQUEST_BODY_BYTES=32768.
"""

from app.core.config import settings
from app.core.payload_limits import (
    compute_payload_byte_size,
    compute_payload_depth,
    payload_has_overlong_string,
)


# --- unit tests for the pure functions themselves -------------------------------


def test_compute_payload_depth_of_a_flat_dict_is_one():
    assert compute_payload_depth({"a": 1, "b": "two"}) == 1


def test_compute_payload_depth_of_an_empty_dict_is_zero():
    assert compute_payload_depth({}) == 0


def test_compute_payload_depth_counts_nested_dicts():
    assert compute_payload_depth({"a": {"b": {"c": 1}}}) == 3


def test_compute_payload_depth_counts_nested_lists():
    assert compute_payload_depth({"a": [1, [2, [3]]]}) == 4


def test_compute_payload_byte_size_matches_compact_json():
    assert compute_payload_byte_size({"a": 1}) == len(b'{"a":1}')


def test_payload_has_overlong_string_detects_a_deeply_nested_value():
    assert payload_has_overlong_string({"a": {"b": ["x" * 10]}}, max_length=5) is True


def test_payload_has_overlong_string_detects_an_overlong_key():
    assert payload_has_overlong_string({"k" * 10: "short"}, max_length=5) is True


def test_payload_has_overlong_string_false_when_everything_fits():
    assert payload_has_overlong_string({"a": {"b": ["short"]}}, max_length=10) is False


# --- end-to-end via the API ------------------------------------------------------


def _body(**overrides):
    body = {
        "eventType": "USER_LOGIN",
        "actorId": "user-1",
        "resourceType": "SESSION",
        "resourceId": "sess-1",
        "payload": {"note": "hello"},
    }
    body.update(overrides)
    return body


def _payload_at_depth(depth: int) -> dict:
    """A payload dict whose compute_payload_depth() is exactly `depth`
    (see app/core/payload_limits.py - a flat dict of scalars is depth 1,
    each further wrapping dict adds one)."""
    value = "leaf"
    for _ in range(depth):
        value = {"level": value}
    return value


# --- within limits: succeeds ----------------------------------------------------


def test_payload_within_all_limits_succeeds(client, writer_headers):
    response = client.post("/audit/events", json=_body(), headers=writer_headers)

    assert response.status_code == 201


def test_payload_at_exactly_the_depth_limit_succeeds(client, writer_headers):
    response = client.post(
        "/audit/events",
        json=_body(payload=_payload_at_depth(settings.max_payload_depth)),
        headers=writer_headers,
    )

    assert response.status_code == 201


def test_payload_at_exactly_the_string_length_limit_succeeds(client, writer_headers):
    response = client.post(
        "/audit/events",
        json=_body(payload={"note": "a" * settings.max_payload_string_length}),
        headers=writer_headers,
    )

    assert response.status_code == 201


def test_identity_fields_at_exactly_their_max_length_succeed(client, writer_headers):
    response = client.post(
        "/audit/events",
        json=_body(actorId="a" * 255, resourceId="r" * 255),
        headers=writer_headers,
    )

    assert response.status_code == 201


# --- payload byte size ------------------------------------------------------


def test_payload_exceeding_byte_size_is_rejected(client, writer_headers):
    """Many short fields (each well under the string-length limit) whose
    combined serialized size exceeds MAX_PAYLOAD_BYTES - isolates the
    byte-size check from the string-length check."""
    big_payload = {f"field_{i}": "x" * 200 for i in range(100)}
    assert len(str(big_payload)) > settings.max_payload_bytes  # sanity check on the test data itself

    response = client.post("/audit/events", json=_body(payload=big_payload), headers=writer_headers)

    assert response.status_code == 422


# --- nesting depth -----------------------------------------------------------


def test_payload_exceeding_depth_is_rejected(client, writer_headers):
    too_deep = _payload_at_depth(settings.max_payload_depth + 1)

    response = client.post("/audit/events", json=_body(payload=too_deep), headers=writer_headers)

    assert response.status_code == 422


def test_payload_exceeding_depth_via_lists_is_rejected(client, writer_headers):
    """Depth is checked through lists too, not just dicts."""
    value = "leaf"
    for _ in range(settings.max_payload_depth):
        value = [value]

    response = client.post("/audit/events", json=_body(payload={"items": value}), headers=writer_headers)

    assert response.status_code == 422


# --- string length -------------------------------------------------------------


def test_payload_string_value_too_long_is_rejected(client, writer_headers):
    response = client.post(
        "/audit/events",
        json=_body(payload={"note": "a" * (settings.max_payload_string_length + 1)}),
        headers=writer_headers,
    )

    assert response.status_code == 422


def test_payload_dict_key_too_long_is_rejected(client, writer_headers):
    overlong_key = "k" * (settings.max_payload_string_length + 1)

    response = client.post(
        "/audit/events", json=_body(payload={overlong_key: "value"}), headers=writer_headers
    )

    assert response.status_code == 422


# --- identity field length -------------------------------------------------------


def test_actor_id_over_max_length_is_rejected(client, writer_headers):
    response = client.post("/audit/events", json=_body(actorId="a" * 256), headers=writer_headers)

    assert response.status_code == 422


def test_event_type_over_max_length_is_rejected(client, writer_headers):
    response = client.post("/audit/events", json=_body(eventType="a" * 101), headers=writer_headers)

    assert response.status_code == 422


# --- whole-request body size cap (413, before parsing) -------------------------


def test_request_body_over_max_size_is_rejected_with_413(client, writer_headers):
    """A request whose raw body exceeds MAX_REQUEST_BODY_BYTES is
    rejected by the body-size middleware before FastAPI even parses it -
    proven by getting 413, not 422 (which is what the payload-level
    checks above would produce once parsing succeeds)."""
    oversized_payload = {"note": "x" * (settings.max_request_body_bytes + 1000)}

    response = client.post("/audit/events", json=_body(payload=oversized_payload), headers=writer_headers)

    assert response.status_code == 413
