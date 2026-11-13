import logging
import time
from datetime import timedelta

from sqlalchemy import delete

from app.config import get_settings
from app.db import SessionLocal, utcnow
from app.models import RateBucket, Session, SyncState
from app.nvd import synchronize
from app.risk import notify_overdue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnwatch.worker")


def tick():
    with SessionLocal() as db:
        state = db.get(SyncState, 1)
        due = not state.last_attempt or utcnow() - state.last_attempt >= timedelta(
            seconds=get_settings().sync_interval_seconds
        )
        requested = state.requested
        db.execute(delete(Session).where(Session.expires_at < utcnow()))
        db.execute(delete(RateBucket).where(RateBucket.window < int(time.time()) // 60 - 1440))
        notify_overdue(db)
        db.commit()
    if due or requested:
        logger.info("NVD synchronization completed: %s", synchronize())


def main():
    while True:
        try:
            tick()
        except Exception:
            logger.exception("Worker iteration failed")
        time.sleep(60)


if __name__ == "__main__":
    main()
