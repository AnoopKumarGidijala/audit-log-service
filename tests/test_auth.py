from app.core.config import settings
from app.core.roles import Role

VALID_EVENT = {
    "eventType": "USER_LOGIN",
    "actorId": "user-1",
    "resourceType": "SESSION",
    "resourceId": "sess-1",
    "payload": {},
}

_ADMIN = next(u for u in settings.auth_users if u.role == Role.ADMIN)
# AUTH_USERS stores only a password hash (see app/core/passwords.py) - the
# raw password every seeded user in .env shares is known out of band.
_ADMIN_PASSWORD = "local_dev_password"


def test_login_success(client):
    response = client.post(
        "/auth/token",
        data={"username": _ADMIN.username, "password": _ADMIN_PASSWORD},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password(client):
    response = client.post(
        "/auth/token",
        data={"username": _ADMIN.username, "password": "wrong-password"},
    )

    assert response.status_code == 401


def test_login_unknown_username(client):
    response = client.post(
        "/auth/token",
        data={"username": "no-such-user", "password": "whatever"},
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
