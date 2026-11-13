import argparse
import getpass
import json
import os
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from app.db import SessionLocal, utcnow
from app.imports import import_rows
from app.models import Asset, AssetCategory, Finding, FindingHistory, ImportJob, RiskPolicy, Role, User
from app.risk import assess
from app.schemas import ImportRow, UserCreate
from app.security import audit, bootstrap, passwords


def create_admin(db, email, name):
    password = os.environ.get("VULNWATCH_ADMIN_PASSWORD") or getpass.getpass(
        "Administrator password (14+ characters): "
    )
    data = UserCreate(email=email, name=name, password=password, role="admin")
    if db.scalar(select(User).where(User.email == data.email.lower())):
        raise SystemExit("User already exists; use reset-password")
    role = db.scalar(select(Role).where(Role.name == "admin"))
    user = User(
        email=data.email.lower(), name=data.name, password_hash=passwords.hash(data.password), role=role
    )
    db.add(user)
    db.flush()
    audit(db, None, "user.bootstrapped", user.id)
    db.commit()


def seed_demo(db):
    if os.environ.get("ENVIRONMENT") not in {"development", "test"}:
        raise SystemExit("Demo seed is restricted to explicit development/test environments")
    if db.scalar(select(Finding.id).limit(1)):
        raise SystemExit("Demo seed requires an empty findings inventory")
    actor = db.scalar(select(User).where(User.active.is_(True)))
    if not actor:
        raise SystemExit("Create an administrator first")
    category = AssetCategory(name="Demo infrastructure")
    db.add(category)
    db.flush()
    definitions = [
        ("edge-gateway-01", 5, "internet"),
        ("payments-api", 5, "internet"),
        ("identity-service", 4, "internal"),
        ("analytics-db", 4, "internal"),
        ("build-runner-02", 3, "internal"),
        ("employee-portal", 3, "internet"),
    ]
    for name, criticality, exposure in definitions:
        if not db.scalar(select(Asset).where(Asset.name == name)):
            db.add(
                Asset(
                    name=name,
                    criticality=criticality,
                    exposure=exposure,
                    category=category,
                    owner="Demo security team",
                )
            )
    db.flush()
    sample_path = Path(__file__).parents[2] / "samples" / "demo.json"
    if not sample_path.exists():
        sample_path = Path(__file__).parents[1] / "samples" / "demo.json"
    rows = [ImportRow.model_validate(row) for row in json.loads(sample_path.read_text())["findings"]]
    job = ImportJob(
        adapter="demo-fixture",
        filename="demo.json",
        status="processing",
        user_id=actor.id,
        created_count=0,
        duplicate_count=0,
    )
    db.add(job)
    db.flush()
    import_rows(db, rows, job, actor.id)
    now = utcnow()
    for index, finding in enumerate(db.scalars(select(Finding).order_by(Finding.id))):
        finding.first_seen = now - timedelta(days=5 + index * 4)
        finding.last_seen = now - timedelta(hours=index)
        finding.due_at = finding.first_seen + timedelta(days=14)
        if index % 5 == 3:
            finding.status = "verified"
            finding.remediated_at = finding.first_seen + timedelta(days=4)
            db.add(
                FindingHistory(
                    finding_id=finding.id,
                    actor_id=actor.id,
                    from_status="mitigated",
                    to_status="verified",
                    note="DEMO: synthetic verification event",
                )
            )
        elif index % 4 == 1:
            finding.status = "in_progress"
        assess(db, finding, db.get(RiskPolicy, 1))
    audit(db, actor.id, "demo.seeded", "inventory", {"synthetic": True})
    db.commit()


def main():
    parser = argparse.ArgumentParser(description="VulnWatch administration")
    parser.add_argument(
        "command", choices=["bootstrap", "create-admin", "seed-demo", "reset-password", "sync"]
    )
    parser.add_argument("--email", default="admin@example.com")
    parser.add_argument("--name", default="Security Administrator")
    args = parser.parse_args()
    with SessionLocal() as db:
        bootstrap(db)
        if args.command == "create-admin":
            create_admin(db, args.email, args.name)
        elif args.command == "seed-demo":
            seed_demo(db)
        elif args.command == "reset-password":
            from sqlalchemy import delete

            from app.models import Session

            user = db.scalar(select(User).where(User.email == args.email.lower()))
            if not user:
                raise SystemExit("User not found")
            password = getpass.getpass("New password (14+ characters): ")
            UserCreate(email=user.email, name=user.name, password=password, role=user.role.name)
            user.password_hash = passwords.hash(password)
            db.execute(delete(Session).where(Session.user_id == user.id))
            audit(db, None, "user.password_reset", user.id)
            db.commit()
        elif args.command == "sync":
            from app.nvd import synchronize

            if not synchronize():
                raise SystemExit("Synchronization failed or another worker owns the lock; inspect /api/sync")


if __name__ == "__main__":
    main()
