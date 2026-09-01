from app.core.config import settings

VALID_EVENT = {
    "eventType": "USER_LOGIN",
    "actorId": "user-1",
    "resourceType": "SESSION",
    "resourceId": "sess-1",
    "payload": {},
}


def test_login_success(client):
    response = client.post(
        "/auth/token",
        data={"username": settings.auth_username, "password": settings.auth_password},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password(client):
    response = client.post(
        "/auth/token",
        data={"username": settings.auth_username, "password": "wrong-password"},
    )

    assert response.status_code == 401


def test_create_event_requires_auth(client):
    response = client.post("/audit/events", json=VALID_EVENT)

    assert response.status_code == 401


def test_create_event_rejects_invalid_token(client):
    response = client.post(
        "/audit/events",
        json=VALID_EVENT,
        headers={"Authorization": "Bearer not-a-real-token"},
    )

    assert response.status_code == 401
