import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def _clean_audit_events():
    yield
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE audit_events RESTART IDENTITY"))


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/auth/token",
        data={"username": settings.auth_username, "password": settings.auth_password},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
