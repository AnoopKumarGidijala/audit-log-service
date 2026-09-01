from datetime import datetime, timedelta, timezone

from app.db.models import AuditEvent
from app.db.session import SessionLocal


def _create_event(client, auth_headers, *, actor_id, event_type, resource_type="SESSION", resource_id="sess-1"):
    response = client.post(
        "/audit/events",
        json={
            "eventType": event_type,
            "actorId": actor_id,
            "resourceType": resource_type,
            "resourceId": resource_id,
            "payload": {},
        },
        headers=auth_headers,
    )
    assert response.status_code == 201
    return response.json()


def _set_timestamp(event_id, ts):
    """Directly overwrite a stored event's timestamp (bypassing the API) so
    time-range tests have exact, controlled boundaries instead of depending
    on real wall-clock timing."""
    db = SessionLocal()
    try:
        event = db.get(AuditEvent, event_id)
        event.timestamp = ts
        db.commit()
    finally:
        db.close()


def _seed_events(client, auth_headers):
    # Distinct actorId/eventType combinations so filters can be told apart.
    first = _create_event(client, auth_headers, actor_id="user-1", event_type="USER_LOGIN")
    second = _create_event(client, auth_headers, actor_id="user-1", event_type="RECORD_UPDATED")
    third = _create_event(client, auth_headers, actor_id="user-2", event_type="USER_LOGIN")
    return first, second, third


def test_list_events_requires_auth(client):
    response = client.get("/audit/events")

    assert response.status_code == 401


def test_list_events_without_filters_returns_all(client, auth_headers):
    first, second, third = _seed_events(client, auth_headers)

    response = client.get("/audit/events", headers=auth_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert ids == [first["id"], second["id"], third["id"]]


def test_list_events_filter_by_actor_id(client, auth_headers):
    first, second, _third = _seed_events(client, auth_headers)

    response = client.get("/audit/events", params={"actorId": "user-1"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"], second["id"]]
    assert all(event["actorId"] == "user-1" for event in body)


def test_list_events_filter_by_event_type(client, auth_headers):
    first, _second, third = _seed_events(client, auth_headers)

    response = client.get("/audit/events", params={"eventType": "USER_LOGIN"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"], third["id"]]
    assert all(event["eventType"] == "USER_LOGIN" for event in body)


def test_list_events_combined_filters(client, auth_headers):
    first, _second, _third = _seed_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={"actorId": "user-1", "eventType": "USER_LOGIN"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"]]


def test_list_events_filter_with_no_matches_returns_empty_list(client, auth_headers):
    _seed_events(client, auth_headers)

    response = client.get("/audit/events", params={"actorId": "no-such-user"}, headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == []


def test_list_events_order_is_deterministic_across_requests(client, auth_headers):
    first, second, third = _seed_events(client, auth_headers)
    expected_ids = [first["id"], second["id"], third["id"]]

    response_a = client.get("/audit/events", headers=auth_headers)
    response_b = client.get("/audit/events", headers=auth_headers)

    assert [event["id"] for event in response_a.json()] == expected_ids
    assert [event["id"] for event in response_b.json()] == expected_ids


# --- resourceType / resourceId filters -------------------------------------


def _seed_resource_events(client, auth_headers):
    first = _create_event(
        client, auth_headers, actor_id="user-1", event_type="RECORD_UPDATED",
        resource_type="ACCOUNT", resource_id="acct-1",
    )
    second = _create_event(
        client, auth_headers, actor_id="user-1", event_type="RECORD_UPDATED",
        resource_type="ACCOUNT", resource_id="acct-2",
    )
    third = _create_event(
        client, auth_headers, actor_id="user-1", event_type="RECORD_UPDATED",
        resource_type="SESSION", resource_id="acct-1",
    )
    return first, second, third


def test_list_events_filter_by_resource_type(client, auth_headers):
    first, second, _third = _seed_resource_events(client, auth_headers)

    response = client.get("/audit/events", params={"resourceType": "ACCOUNT"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"], second["id"]]


def test_list_events_filter_by_resource_id(client, auth_headers):
    first, _second, third = _seed_resource_events(client, auth_headers)

    response = client.get("/audit/events", params={"resourceId": "acct-1"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"], third["id"]]


def test_list_events_filter_by_resource_type_and_id_combined(client, auth_headers):
    first, _second, _third = _seed_resource_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={"resourceType": "ACCOUNT", "resourceId": "acct-1"},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert [event["id"] for event in body] == [first["id"]]


# --- from/to time-range filters ---------------------------------------------

_BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _seed_time_events(client, auth_headers):
    first, second, third = _seed_events(client, auth_headers)
    _set_timestamp(first["id"], _BASE_TIME)
    _set_timestamp(second["id"], _BASE_TIME + timedelta(days=1))
    _set_timestamp(third["id"], _BASE_TIME + timedelta(days=2))
    return first, second, third


def test_list_events_filter_by_from_only(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={"from": (_BASE_TIME + timedelta(hours=12)).isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [second["id"], third["id"]]


def test_list_events_filter_by_to_only(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={"to": (_BASE_TIME + timedelta(days=1, hours=12)).isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [first["id"], second["id"]]


def test_list_events_filter_by_from_and_to_range(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={
            "from": (_BASE_TIME + timedelta(hours=12)).isoformat(),
            "to": (_BASE_TIME + timedelta(days=1, hours=12)).isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [second["id"]]


def test_list_events_from_to_boundaries_are_inclusive(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={"from": _BASE_TIME.isoformat(), "to": (_BASE_TIME + timedelta(days=2)).isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [first["id"], second["id"], third["id"]]


def test_list_events_time_filter_accepts_non_utc_offset(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)
    # +05:30 of a moment that is exactly _BASE_TIME + 1 day in UTC.
    local_equivalent = (_BASE_TIME + timedelta(days=1)).astimezone(timezone(timedelta(hours=5, minutes=30)))

    response = client.get(
        "/audit/events",
        params={"from": local_equivalent.isoformat()},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [second["id"], third["id"]]


def test_list_events_naive_from_is_rejected(client, auth_headers):
    _seed_time_events(client, auth_headers)

    response = client.get("/audit/events", params={"from": "2026-01-01T00:00:00"}, headers=auth_headers)

    assert response.status_code == 422


def test_list_events_naive_to_is_rejected(client, auth_headers):
    _seed_time_events(client, auth_headers)

    response = client.get("/audit/events", params={"to": "2026-01-01T00:00:00"}, headers=auth_headers)

    assert response.status_code == 422


def test_list_events_from_after_to_is_rejected(client, auth_headers):
    _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={
            "from": (_BASE_TIME + timedelta(days=2)).isoformat(),
            "to": _BASE_TIME.isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 422


# --- combining a resource/time filter with the existing filters ------------


def test_list_events_combines_actor_and_resource_and_time_filters(client, auth_headers):
    first, second, third = _seed_time_events(client, auth_headers)

    response = client.get(
        "/audit/events",
        params={
            "actorId": "user-1",
            "resourceType": "SESSION",
            "from": _BASE_TIME.isoformat(),
            "to": (_BASE_TIME + timedelta(days=1, hours=12)).isoformat(),
        },
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert [event["id"] for event in response.json()] == [first["id"], second["id"]]


# --- pagination --------------------------------------------------------------


def test_list_events_pagination_returns_pages_in_order(client, auth_headers):
    created = [
        _create_event(client, auth_headers, actor_id="user-1", event_type="USER_LOGIN") for _ in range(5)
    ]
    ids = [event["id"] for event in created]

    page_1 = client.get("/audit/events", params={"limit": 2, "offset": 0}, headers=auth_headers)
    page_2 = client.get("/audit/events", params={"limit": 2, "offset": 2}, headers=auth_headers)
    page_3 = client.get("/audit/events", params={"limit": 2, "offset": 4}, headers=auth_headers)

    assert [event["id"] for event in page_1.json()] == ids[0:2]
    assert [event["id"] for event in page_2.json()] == ids[2:4]
    assert [event["id"] for event in page_3.json()] == ids[4:5]


def test_list_events_pagination_offset_past_end_returns_empty(client, auth_headers):
    _seed_events(client, auth_headers)

    response = client.get("/audit/events", params={"limit": 10, "offset": 100}, headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == []


def test_list_events_limit_zero_is_rejected(client, auth_headers):
    response = client.get("/audit/events", params={"limit": 0}, headers=auth_headers)

    assert response.status_code == 422


def test_list_events_limit_above_max_is_rejected(client, auth_headers):
    response = client.get("/audit/events", params={"limit": 201}, headers=auth_headers)

    assert response.status_code == 422


def test_list_events_negative_offset_is_rejected(client, auth_headers):
    response = client.get("/audit/events", params={"offset": -1}, headers=auth_headers)

    assert response.status_code == 422
