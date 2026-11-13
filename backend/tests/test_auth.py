from datetime import timedelta

from sqlalchemy import select

from app.db import utcnow
from app.models import Session


def test_authentication_and_security_headers(client, authenticated):
    assert client.get("/api/findings").status_code == 401
    response = client.post(
        "/api/auth/login",
        json={"email": "admin@example.com", "password": "wrong"},
        headers={"Origin": "http://localhost:8080"},
    )
    assert response.status_code == 401
    authenticated()
    assert client.get("/api/auth/session").json()["user"]["role"] == "admin"
    assert client.get("/api/users").headers["X-Content-Type-Options"] == "nosniff"
    assert "password_hash" not in client.get("/api/users").text
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/findings").status_code == 401


def test_origin_csrf_and_permissions(authenticated):
    client = authenticated("viewer")
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/assets", json={"name": "forbidden"}).status_code == 403
    authenticated("analyst")
    assert (
        client.post(
            "/api/users",
            json={
                "email": "new@example.com",
                "name": "New",
                "password": "a-long-password-123",
                "role": "admin",
            },
        ).status_code
        == 403
    )
    client.headers["Origin"] = "https://evil.example"
    assert client.post("/api/assets", json={"name": "bad-origin"}).status_code == 403
    client.headers["Origin"] = "http://localhost:8080"
    client.headers["X-CSRF-Token"] = "wrong"
    assert client.post("/api/assets", json={"name": "bad-token"}).status_code == 403


def test_session_expiry(authenticated, database):
    client = authenticated()
    with database() as db:
        session = db.scalar(select(Session))
        session.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.get("/api/auth/session").status_code == 401


def test_rate_limit(client, monkeypatch):
    # Freeze the fixed rate-limit window so the test cannot straddle a minute boundary.
    monkeypatch.setattr("app.security.time.time", lambda: 1_700_000_010)
    responses = [
        client.post(
            "/api/auth/login",
            json={"email": "missing@example.com", "password": "wrong"},
            headers={"Origin": "http://localhost:8080"},
        )
        for _ in range(11)
    ]
    assert responses[-1].status_code == 429
    assert responses[-1].headers["Retry-After"] == "60"


def test_disable_revokes_sessions(authenticated):
    client = authenticated()
    users = client.get("/api/users").json()
    viewer = next(user for user in users if user["role"] == "viewer")
    assert client.post(f"/api/users/{viewer['id']}/disable").status_code == 204
    assert client.post("/api/users/1/disable").status_code == 409
