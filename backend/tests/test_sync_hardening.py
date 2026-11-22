from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from app.db import utcnow
from app.models import CVERecord, SyncRun, SyncStagedCVE, SyncState
from app.nvd import PAGE_SIZE, NVDClient, NVDError, sync_window, synchronize
from tests.test_nvd import fixture_cve

WINDOW_DAYS = 119


def window():
    end = utcnow()
    return end - timedelta(days=WINDOW_DAYS), end


def paged_handler(total, page_size=PAGE_SIZE, fail_at=None):
    """Serve ``total`` synthetic CVEs across pages, optionally failing one page."""

    def handler(request):
        index = int(request.url.params["startIndex"])
        if fail_at is not None and index == fail_at:
            return httpx.Response(503)
        take = min(page_size, max(0, total - index))
        entries = [{"cve": fixture_cve(id=f"CVE-2026-{2000 + index + offset}")} for offset in range(take)]
        return httpx.Response(
            200, json={"totalResults": total, "startIndex": index, "vulnerabilities": entries}
        )

    return handler


def client_for(handler):
    return NVDClient(transport=httpx.MockTransport(handler), sleep=lambda _: None)


def test_pages_are_staged_before_the_window_is_applied(database):
    observed = {}

    def checkpoint(stats):
        with database() as db:
            observed["staged"] = db.scalar(select(func.count(SyncStagedCVE.id)))
            observed["applied"] = db.scalar(select(func.count(CVERecord.id)))
            observed["pages"] = stats["pages"]

    client = client_for(paged_handler(3, page_size=1))
    start, end = window()
    with database() as db:
        assert sync_window(db, client, start, end, checkpoint=checkpoint) == "completed"
    client.close()

    # Pages were visible in staging while no CVE had been applied yet.
    assert observed["applied"] == 0
    assert observed["staged"] >= 1
    assert observed["pages"] >= 1
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 3
        assert db.scalar(select(func.count(SyncStagedCVE.id))) == 0
        run = db.scalar(select(SyncRun))
        assert run.status == "completed"
        assert run.pages_fetched == 3
        assert run.last_page_ms is not None


def test_failed_page_leaves_no_partial_window_and_no_watermark(database):
    client = client_for(paged_handler(3, page_size=1, fail_at=2))
    start, end = window()
    with database() as db:
        with pytest.raises(NVDError):
            sync_window(db, client, start, end)
        db.rollback()
    client.close()
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 0
        assert db.get(SyncState, 1).watermark is None


def test_restart_resumes_from_the_recorded_cursor(database):
    start, end = window()
    failing = client_for(paged_handler(3, page_size=1, fail_at=2))
    with database() as db:
        with pytest.raises(NVDError):
            sync_window(db, failing, start, end)
        db.rollback()
    failing.close()
    with database() as db:
        run = db.scalar(select(SyncRun))
        assert run.status == "running"
        assert run.cursor_index == 2
        assert db.scalar(select(func.count(SyncStagedCVE.id))) == 2
        assert db.scalar(select(func.count(CVERecord.id))) == 0

    requested = []

    def resuming(request):
        requested.append(int(request.url.params["startIndex"]))
        return paged_handler(3, page_size=1)(request)

    resumed = client_for(resuming)
    with database() as db:
        assert sync_window(db, resumed, start, end) == "completed"
    resumed.close()

    # The restarted run must not refetch pages already staged.
    assert requested == [2]
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 3
        assert db.scalar(select(func.count(SyncStagedCVE.id))) == 0
        assert db.scalar(select(SyncRun)).status == "completed"


def test_cancellation_discards_staged_pages_and_preserves_cursor(database):
    start, end = window()
    client = client_for(paged_handler(3, page_size=1))

    def cancel_after_first_page(_stats):
        with database() as db:
            db.get(SyncState, 1).cancel_requested = True
            db.commit()

    with database() as db:
        assert sync_window(db, client, start, end, checkpoint=cancel_after_first_page) == "cancelled"
    client.close()
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 0
        assert db.scalar(select(func.count(SyncStagedCVE.id))) == 0
        state = db.get(SyncState, 1)
        assert state.watermark is None
        assert state.cancel_requested is False
        run = db.scalar(select(SyncRun))
        assert run.status == "cancelled"
        assert run.completed_at is not None


def test_duplicate_identifiers_across_pages_are_staged_once(database):
    def handler(request):
        index = int(request.url.params["startIndex"])
        return httpx.Response(
            200,
            json={
                "totalResults": 2,
                "startIndex": index,
                "vulnerabilities": [{"cve": fixture_cve(id="CVE-2026-9999")}],
            },
        )

    client = client_for(handler)
    start, end = window()
    with database() as db:
        assert sync_window(db, client, start, end) == "completed"
    client.close()
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 1


def test_sync_marks_run_failed_and_keeps_watermark(database):
    client = client_for(lambda request: httpx.Response(503))
    assert not synchronize(client)
    client.close()
    with database() as db:
        state = db.get(SyncState, 1)
        assert state.watermark is None
        assert state.last_error is not None
        runs = list(db.scalars(select(SyncRun)))
        assert runs and all(run.status == "failed" for run in runs)


def test_backfill_bounds_are_enforced(monkeypatch):
    from app import cli

    called = []
    monkeypatch.setattr(cli, "bootstrap", lambda db: None)
    monkeypatch.setattr("app.nvd.synchronize", lambda **kwargs: called.append(kwargs) or True)

    def run(argv):
        monkeypatch.setattr("sys.argv", ["vulnwatch", *argv])
        cli.main()

    for invalid in (["backfill"], ["backfill", "--days", "0"], ["backfill", "--days", "121"]):
        with pytest.raises(SystemExit):
            run(invalid)
    assert called == []

    run(["backfill", "--days", "30"])
    assert called == [{"backfill_days": 30}]
    run(["sync"])
    assert called[-1] == {}


def test_crashed_window_is_resumed_by_the_next_synchronize(database):
    """A window left staged by a failed run must be finished, not dropped."""
    end = utcnow()
    start = end - timedelta(days=1)
    with database() as db:
        run = SyncRun(kind="sync", start=start, end=end, status="running")
        db.add(run)
        db.flush()
        for offset in range(2):
            db.add(
                SyncStagedCVE(
                    run_id=run.id,
                    page_index=offset,
                    cve_id=f"CVE-2026-{3000 + offset}",
                    payload=fixture_cve(id=f"CVE-2026-{3000 + offset}"),
                )
            )
        run.cursor_index = 2
        run.pages_fetched = 2
        db.get(SyncState, 1).watermark = end
        db.commit()

    # The range is already covered, so no new pages should be requested.
    requested = []

    def handler(request):
        requested.append(int(request.url.params["startIndex"]))
        return httpx.Response(
            200,
            json={
                "totalResults": 2,
                "startIndex": int(request.url.params["startIndex"]),
                "vulnerabilities": [],
            },
        )

    client = client_for(handler)
    assert synchronize(client)
    client.close()

    # The interrupted window resumes at its recorded cursor instead of refetching
    # pages 0 and 1. The later index-0 read is the separate watermark overlap.
    assert requested[0] == 2
    assert 1 not in requested
    with database() as db:
        assert db.scalar(select(func.count(CVERecord.id))) == 2
        assert db.scalar(select(func.count(SyncStagedCVE.id))) == 0
        assert db.scalar(select(SyncRun).where(SyncRun.pages_fetched > 0)).status == "completed"


def test_sync_status_exposes_run_metrics(authenticated, database):
    client = authenticated()
    with database() as db:
        db.add(
            SyncRun(
                kind="sync",
                start=utcnow() - timedelta(days=1),
                end=utcnow(),
                status="completed",
                pages_fetched=4,
                pages_total=4,
                cursor_index=4000,
                retry_count=2,
                last_page_ms=120,
                completed_at=utcnow(),
            )
        )
        db.commit()
    body = client.get("/api/sync").json()
    assert body["last_run"]["status"] == "completed"
    assert body["last_run"]["pages_fetched"] == 4
    assert body["last_run"]["retry_count"] == 2
    assert body["last_run"]["last_page_ms"] == 120
    assert body["pending_enrichment"] == 0
    assert body["cancel_requested"] is False


def test_cancel_requires_a_running_sync(authenticated):
    assert authenticated().post("/api/sync/cancel").status_code == 409


def test_cancel_sets_the_flag_when_running(authenticated, database):
    client = authenticated()
    with database() as db:
        db.get(SyncState, 1).lease_until = utcnow() + timedelta(minutes=5)
        db.commit()
    assert client.post("/api/sync/cancel").status_code == 202
    with database() as db:
        assert db.get(SyncState, 1).cancel_requested is True
    assert client.get("/api/sync").json()["cancel_requested"] is True


def test_cancel_is_admin_only(authenticated):
    assert authenticated("viewer").post("/api/sync/cancel").status_code == 403


def test_new_run_clears_a_stale_cancel_flag(database):
    with database() as db:
        db.get(SyncState, 1).cancel_requested = True
        db.commit()
    client = client_for(paged_handler(1, page_size=1))
    assert synchronize(client)
    client.close()
    with database() as db:
        assert db.get(SyncState, 1).cancel_requested is False
