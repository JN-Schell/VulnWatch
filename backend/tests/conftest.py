import os

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:////tmp/vulnwatch-test-placeholder.db"
os.environ["ALLOWED_HOSTS"] = '["testserver", "localhost"]'
os.environ["TRUSTED_ORIGINS"] = '["http://localhost:8080"]'

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import api, nvd
from app.db import Base, get_db, make_engine
from app.models import Role, User
from app.security import bootstrap, passwords


@pytest.fixture
def database(tmp_path, monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    if not url.startswith("sqlite") and "vulnwatch_test" not in url:
        raise RuntimeError("TEST_DATABASE_URL must point to a disposable vulnwatch_test database")
    engine = make_engine(url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(api, "SessionLocal", factory)
    monkeypatch.setattr(nvd, "SessionLocal", factory)
    monkeypatch.setattr(nvd, "engine", engine)
    with factory() as db:
        bootstrap(db)
        from sqlalchemy import select

        for role_name in ("admin", "analyst", "viewer"):
            role = db.scalar(select(Role).where(Role.name == role_name))
            db.add(
                User(
                    email=f"{role_name}@example.com",
                    name=role_name.title(),
                    password_hash=passwords.hash("a-long-test-password"),
                    role=role,
                )
            )
        db.commit()
    yield factory
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(database):
    def override():
        with database() as db:
            yield db

    api.app.dependency_overrides[get_db] = override
    with TestClient(api.app) as test_client:
        yield test_client
    api.app.dependency_overrides.clear()


@pytest.fixture
def authenticated(client):
    def authenticate(role="admin"):
        response = client.post(
            "/api/auth/login",
            json={"email": f"{role}@example.com", "password": "a-long-test-password"},
            headers={"Origin": "http://localhost:8080"},
        )
        assert response.status_code == 200
        client.headers.update(
            {"Origin": "http://localhost:8080", "X-CSRF-Token": response.json()["csrf_token"]}
        )
        return client

    return authenticate


@pytest.fixture
def imported(authenticated):
    client = authenticated()
    assert (
        client.post(
            "/api/assets", json={"name": "server-01", "criticality": 5, "exposure": "internet"}
        ).status_code
        == 201
    )
    import json

    payload = {
        "schema_version": "1.0",
        "findings": [
            {"asset": "server-01", "cve_id": "CVE-2021-44228", "title": "Log4Shell", "cvss_score": 10}
        ],
    }
    response = client.post(
        "/api/imports?adapter=generic-json",
        files={"file": ("scan.json", json.dumps(payload), "application/json")},
    )
    assert response.status_code == 201, response.text
    return client, payload
