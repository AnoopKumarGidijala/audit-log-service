def _create_event(client, auth_headers, *, actor_id, event_type):
    response = client.post(
        "/audit/events",
        json={
            "eventType": event_type,
            "actorId": actor_id,
            "resourceType": "SESSION",
            "resourceId": "sess-1",
            "payload": {},
        },
        headers=auth_headers,
    )
    assert response.status_code == 201
    return response.json()


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
