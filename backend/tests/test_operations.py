import sys
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import cli, worker
from app.db import utcnow
from app.models import Finding, ImportJob, Notification, SyncState, User


def test_cli_seed_is_explicit_and_synthetic(database, monkeypatch):
    monkeypatch.setattr(cli, "SessionLocal", database)
    monkeypatch.setenv("VULNWATCH_ADMIN_PASSWORD", "local-test-only-password")
    monkeypatch.setattr(sys, "argv", ["vulnwatch", "create-admin", "--email", "operator@example.com"])
    cli.main()
    with database() as db:
        assert db.scalar(select(User).where(User.email == "operator@example.com"))
        cli.seed_demo(db)
        assert db.scalar(select(func.count(Finding.id))) == 12
        assert db.scalar(select(ImportJob)).adapter == "demo-fixture"
        with pytest.raises(SystemExit):
            cli.seed_demo(db)
    monkeypatch.setenv("ENVIRONMENT", "production")
    with database() as db, pytest.raises(SystemExit):
        cli.seed_demo(db)


def test_worker_overdue_notification_and_schedule(imported, database, monkeypatch):
    monkeypatch.setattr(worker, "SessionLocal", database)
    calls = []
    monkeypatch.setattr(worker, "synchronize", lambda: calls.append(True))
    with database() as db:
        db.get(SyncState, 1).last_attempt = utcnow()
        db.scalar(select(Finding)).due_at = utcnow() - timedelta(days=1)
        db.commit()
    worker.tick()
    worker.tick()
    with database() as db:
        overdue = list(db.scalars(select(Notification).where(Notification.dedupe_key.like("overdue:%"))))
        assert len(overdue) == 1
        assert not calls
        db.get(SyncState, 1).requested = True
        db.commit()
    worker.tick()
    assert len(calls) == 1


def test_api_body_limit_including_chunked(client):
    response = client.post(
        "/api/auth/login",
        content=b"x" * (2 * 1024 * 1024 + 65537),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    response = client.post(
        "/api/auth/login",
        content=iter([b"x" * (2 * 1024 * 1024 + 65537)]),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_configuration_fails_closed():
    from app.config import Settings

    with pytest.raises(ValueError):
        Settings(environment="production", trusted_origins=["http://insecure.example"])
    with pytest.raises(ValueError):
        Settings(environment="test", nvd_initial_days=121)
    with pytest.raises(ValueError):
        Settings(environment="test", sync_interval_seconds=60)
    with pytest.raises(ValueError):
        Settings(environment="typo")


def test_real_optimistic_concurrency(imported, database):
    from sqlalchemy.orm.exc import StaleDataError

    with database() as first, database() as second:
        left = first.scalar(select(Finding))
        right = second.get(Finding, left.id)
        left.source = "first-editor"
        first.commit()
        right.source = "second-editor"
        with pytest.raises(StaleDataError):
            second.commit()
