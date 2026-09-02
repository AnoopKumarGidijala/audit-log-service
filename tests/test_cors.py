"""Tests for the explicit CORS policy (see docs/defensive-limits-design.md
and app/main.py). .env.test configures exactly one allowed origin,
http://allowed-test-origin.example, so both branches - explicitly
allowed, and denied by default - are exercised against real
configuration, not a mocked policy.
"""

_ALLOWED_ORIGIN = "http://allowed-test-origin.example"
_OTHER_ORIGIN = "http://not-on-the-allow-list.example"


def test_request_from_an_unlisted_origin_gets_no_cors_header(client):
    response = client.get("/", headers={"Origin": _OTHER_ORIGIN})

    assert response.status_code == 200  # CORS denies at the browser, not the server
    assert "access-control-allow-origin" not in response.headers


def test_request_from_the_configured_origin_is_allowed(client):
    response = client.get("/", headers={"Origin": _ALLOWED_ORIGIN})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == _ALLOWED_ORIGIN


def test_preflight_for_an_unlisted_origin_is_not_approved(client):
    response = client.options(
        "/audit/events",
        headers={
            "Origin": _OTHER_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_preflight_for_the_configured_origin_is_approved(client):
    response = client.options(
        "/audit/events",
        headers={
            "Origin": _ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.headers.get("access-control-allow-origin") == _ALLOWED_ORIGIN
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_credentials_are_not_allowed_cross_origin(client):
    """allow_credentials=False - this API authenticates via a Bearer
    token, not cookies, so cross-origin credentialed requests aren't
    needed (see docs/defensive-limits-design.md §5). CORSMiddleware only
    ever adds Access-Control-Allow-Credentials when allow_credentials is
    True, so its absence here - even for the one configured, allowed
    origin - confirms the setting."""
    response = client.get("/", headers={"Origin": _ALLOWED_ORIGIN})

    assert "access-control-allow-credentials" not in response.headers
