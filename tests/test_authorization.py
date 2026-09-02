"""Role-based authorization tests (see docs/authorization-design.md).

Every other test file keeps using the `auth_headers` fixture (admin - a
superset of every permission), so none of the pre-existing hash-chain,
retention, redaction, export, or compliance tests needed to change: this
file is where the new role/tenant behavior itself is exercised.
"""

import pytest

VALID_EVENT = {
    "eventType": "USER_LOGIN",
    "actorId": "user-1",
    "resourceType": "SESSION",
    "resourceId": "sess-1",
    "payload": {},
}


def _create_event(client, headers, **overrides):
    body = {**VALID_EVENT, **overrides}
    response = client.post("/audit/events", json=body, headers=headers)
    assert response.status_code == 201
    return response.json()


# --- missing authentication --------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("get", "/audit/events", {}),
        ("post", "/audit/events", {"json": VALID_EVENT}),
        ("get", "/audit/verify", {}),
        ("get", "/audit/export", {"params": {"actorId": "user-1"}}),
        ("get", "/audit/compliance/account-access", {}),
        ("post", "/audit/retention/apply", {}),
        ("post", "/audit/events/1/redact", {"json": {"fields": ["x"]}}),
    ],
)
def test_missing_authentication_is_rejected(client, method, path, kwargs):
    response = getattr(client, method)(path, **kwargs)

    assert response.status_code == 401


# --- reader: query only -------------------------------------------------------


def test_reader_attempting_writes_is_forbidden(client, reader_headers):
    response = client.post("/audit/events", json=VALID_EVENT, headers=reader_headers)

    assert response.status_code == 403


def test_reader_cannot_verify_chain(client, reader_headers):
    response = client.get("/audit/verify", headers=reader_headers)

    assert response.status_code == 403


def test_reader_cannot_export(client, reader_headers):
    response = client.get("/audit/export", params={"actorId": "user-1"}, headers=reader_headers)

    assert response.status_code == 403


def test_reader_cannot_view_compliance_report(client, reader_headers):
    response = client.get("/audit/compliance/account-access", headers=reader_headers)

    assert response.status_code == 403


def test_reader_cannot_apply_retention(client, reader_headers):
    response = client.post("/audit/retention/apply", headers=reader_headers)

    assert response.status_code == 403


def test_reader_cannot_redact(client, admin_headers, reader_headers):
    event = _create_event(client, admin_headers)

    response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=reader_headers,
    )

    assert response.status_code == 403


# --- writer: create only -------------------------------------------------------


def test_writer_cannot_list_events(client, writer_headers):
    response = client.get("/audit/events", headers=writer_headers)

    assert response.status_code == 403


def test_writer_cannot_verify_chain(client, writer_headers):
    response = client.get("/audit/verify", headers=writer_headers)

    assert response.status_code == 403


def test_writer_cannot_export(client, writer_headers):
    response = client.get("/audit/export", params={"actorId": "user-1"}, headers=writer_headers)

    assert response.status_code == 403


def test_writer_cannot_view_compliance_report(client, writer_headers):
    response = client.get("/audit/compliance/account-access", headers=writer_headers)

    assert response.status_code == 403


def test_writer_attempting_retention_is_forbidden(client, writer_headers):
    response = client.post("/audit/retention/apply", headers=writer_headers)

    assert response.status_code == 403


def test_writer_attempting_redaction_is_forbidden(client, admin_headers, writer_headers):
    event = _create_event(client, admin_headers)

    response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=writer_headers,
    )

    assert response.status_code == 403


# --- auditor: read-only, but every read-side capability ----------------------


def test_auditor_cannot_create_events(client, auditor_headers):
    response = client.post("/audit/events", json=VALID_EVENT, headers=auditor_headers)

    assert response.status_code == 403


def test_auditor_cannot_apply_retention(client, auditor_headers):
    response = client.post("/audit/retention/apply", headers=auditor_headers)

    assert response.status_code == 403


def test_auditor_cannot_redact(client, admin_headers, auditor_headers):
    event = _create_event(client, admin_headers)

    response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=auditor_headers,
    )

    assert response.status_code == 403


def test_auditor_can_list_events_across_tenants(client, writer_headers, writer_headers_b, auditor_headers):
    a = _create_event(client, writer_headers, actorId="tenant-a-user")
    b = _create_event(client, writer_headers_b, actorId="tenant-b-user")

    response = client.get("/audit/events", headers=auditor_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert a["id"] in ids
    assert b["id"] in ids


def test_auditor_can_verify_chain(client, writer_headers, auditor_headers):
    _create_event(client, writer_headers)

    response = client.get("/audit/verify", headers=auditor_headers)

    assert response.status_code == 200
    assert response.json()["intact"] is True


def test_auditor_can_export(client, writer_headers, auditor_headers):
    _create_event(client, writer_headers, actorId="user-1")

    response = client.get("/audit/export", params={"actorId": "user-1"}, headers=auditor_headers)

    assert response.status_code == 200
    assert response.json()["recordCount"] == 1


def test_auditor_can_view_compliance_report(client, writer_headers, auditor_headers):
    _create_event(client, writer_headers, resourceType="ACCOUNT", resourceId="acct-1")

    response = client.get("/audit/compliance/account-access", headers=auditor_headers)

    assert response.status_code == 200
    assert response.json()["recordCount"] == 1


# --- admin: everything ---------------------------------------------------------


def test_admin_can_create_event(client, admin_headers):
    response = client.post("/audit/events", json=VALID_EVENT, headers=admin_headers)

    assert response.status_code == 201


def test_admin_can_list_events_across_tenants(client, writer_headers, writer_headers_b, admin_headers):
    a = _create_event(client, writer_headers, actorId="tenant-a-user")
    b = _create_event(client, writer_headers_b, actorId="tenant-b-user")

    response = client.get("/audit/events", headers=admin_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert a["id"] in ids
    assert b["id"] in ids


def test_admin_can_verify_export_and_view_compliance(client, admin_headers):
    _create_event(client, admin_headers, actorId="user-1", resourceType="ACCOUNT", resourceId="acct-1")

    assert client.get("/audit/verify", headers=admin_headers).status_code == 200
    assert client.get("/audit/export", params={"actorId": "user-1"}, headers=admin_headers).status_code == 200
    assert client.get("/audit/compliance/account-access", headers=admin_headers).status_code == 200


def test_admin_can_apply_retention_and_redact(client, admin_headers):
    event = _create_event(client, admin_headers)

    assert client.post("/audit/retention/apply", headers=admin_headers).status_code == 200
    redact_response = client.post(
        f"/audit/events/{event['id']}/redact",
        json={"fields": ["accountNumber"]},
        headers=admin_headers,
    )
    # accountNumber isn't in this event's payload, so 422 (nothing
    # redactable) - proves admin cleared the role check, not that the
    # field happened to exist.
    assert redact_response.status_code == 422


# --- cross-tenant / resource isolation ----------------------------------------


def test_reader_does_not_see_other_tenants_events_with_no_filter(
    client, writer_headers, writer_headers_b, reader_headers
):
    own = _create_event(client, writer_headers, actorId="tenant-a-user")
    other = _create_event(client, writer_headers_b, actorId="tenant-b-user")

    response = client.get("/audit/events", headers=reader_headers)

    assert response.status_code == 200
    ids = [event["id"] for event in response.json()]
    assert own["id"] in ids
    assert other["id"] not in ids


def test_reader_cannot_reach_other_tenants_event_via_explicit_filter(
    client, writer_headers, writer_headers_b, reader_headers
):
    """Even when a tenant-a reader knows exactly which actor/resource to
    ask for, a match that belongs to another tenant must not come back -
    tenant scoping is ANDed onto every query, not just the default,
    unfiltered case."""
    _create_event(client, writer_headers_b, actorId="tenant-b-only-user", resourceId="tenant-b-resource")

    response = client.get(
        "/audit/events",
        params={"actorId": "tenant-b-only-user", "resourceId": "tenant-b-resource"},
        headers=reader_headers,
    )

    assert response.status_code == 200
    assert response.json() == []


def test_writer_with_no_tenant_configured_cannot_create_events(client, writer_headers_no_tenant):
    response = client.post("/audit/events", json=VALID_EVENT, headers=writer_headers_no_tenant)

    assert response.status_code == 422


def test_reader_with_no_tenant_configured_cannot_query_events(client, reader_headers_no_tenant):
    response = client.get("/audit/events", headers=reader_headers_no_tenant)

    assert response.status_code == 403


def test_two_tenants_readers_each_see_only_their_own_tenant(
    client, writer_headers, writer_headers_b, reader_headers, reader_headers_b
):
    a = _create_event(client, writer_headers, actorId="user-a")
    b = _create_event(client, writer_headers_b, actorId="user-b")

    a_view = client.get("/audit/events", headers=reader_headers).json()
    b_view = client.get("/audit/events", headers=reader_headers_b).json()

    assert [e["id"] for e in a_view] == [a["id"]]
    assert [e["id"] for e in b_view] == [b["id"]]
