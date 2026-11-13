import pytest
from sqlalchemy.exc import IntegrityError

from app.models import Asset, RiskPolicy


def test_foreign_key_integrity(database):
    with database() as db:
        db.add(Asset(name="orphan", category_id=999, criticality=3, exposure="internal"))
        with pytest.raises(IntegrityError):
            db.commit()


def test_database_constraints(database):
    with database() as db:
        policy = db.get(RiskPolicy, 1)
        policy.high = 10
        with pytest.raises(IntegrityError):
            db.commit()
