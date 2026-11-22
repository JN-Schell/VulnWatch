import math
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, or_, select, text, update

from app.config import get_settings
from app.db import SessionLocal, engine, utcnow
from app.models import CVERecord, Finding, RiskPolicy, SyncRun, SyncStagedCVE, SyncState, Vulnerability
from app.risk import assess
from app.security import audit

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_BACKFILL_DAYS = 120


class NVDError(RuntimeError):
    pass


def parse_date(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def safe_reference(value):
    try:
        parsed = urlsplit(value)
        return parsed.scheme in {"https", "http"} and bool(parsed.hostname) and not parsed.username
    except ValueError:
        return False


def extract_cve(payload):
    import re

    identifier = payload.get("id", "")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", identifier) or len(identifier) > 30:
        raise NVDError("NVD returned an invalid CVE identifier")
    descriptions = payload.get("descriptions", [])
    description = next(
        (entry["value"] for entry in descriptions if entry.get("lang") == "en"),
        "No English description supplied",
    )[:50000]
    selected = None
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = payload.get("metrics", {}).get(metric_name, [])
        if metrics:
            selected = next((entry for entry in metrics if entry.get("type") == "Primary"), metrics[0])
            break
    data = (selected or {}).get("cvssData", {})
    score = data.get("baseScore")
    if score is not None and (
        not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10
    ):
        raise NVDError("NVD returned an invalid CVSS score")
    version = data.get("version")
    if payload.get("vulnStatus") == "Rejected":
        score, version = None, None
    if score is None:
        level = "unknown"
    elif version == "2.0":
        level = "high" if score >= 7 else "medium" if score >= 4 else "low"
    else:
        level = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
            if score > 0
            else "none"
        )
    references = [
        {"url": entry["url"][:2000], "source": entry.get("source", "")[:200], "tags": entry.get("tags", [])}
        for entry in payload.get("references", [])[:100]
        if safe_reference(entry.get("url", ""))
    ]
    products = []

    def walk(node, depth=0):
        if depth > 20:
            raise NVDError("NVD configuration nesting exceeds safety limit")
        for match in node.get("cpeMatch", []):
            if len(products) < 500 and match.get("vulnerable"):
                products.append(
                    {
                        key: match[key]
                        for key in (
                            "criteria",
                            "versionStartIncluding",
                            "versionStartExcluding",
                            "versionEndIncluding",
                            "versionEndExcluding",
                        )
                        if key in match
                    }
                )
        for child in node.get("nodes", []):
            walk(child, depth + 1)

    for configuration in payload.get("configurations", []):
        walk(configuration)
    return dict(
        id=identifier,
        description=description,
        cvss_score=score,
        cvss_version=version,
        cvss_vector=data.get("vectorString"),
        severity=level,
        published_at=parse_date(payload.get("published")),
        modified_at=parse_date(payload.get("lastModified")),
        references=references,
        affected_products=products,
        nvd_status=payload.get("vulnStatus", "Unknown"),
        synced_at=utcnow(),
    )


class NVDClient:
    def __init__(self, api_key=None, transport=None, sleep=time.sleep):
        self.api_key = api_key
        self.sleep = sleep
        self.client = httpx.Client(
            timeout=httpx.Timeout(40, connect=10),
            transport=transport,
            headers={"apiKey": api_key} if api_key else {},
            follow_redirects=False,
        )
        self.last_request = None
        self.retries = 0

    def close(self):
        self.client.close()

    def request(self, params):
        interval = 0.7 if self.api_key else 6.1
        for attempt in range(3):
            if self.last_request is not None:
                self.sleep(max(0, interval - (time.monotonic() - self.last_request)))
            self.last_request = time.monotonic()
            try:
                response = self.client.get(NVD_URL, params=params)
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt == 2:
                        raise NVDError("NVD rate limited or unavailable after three attempts")
                    self.retries += 1
                    retry_after = response.headers.get("retry-after", "")
                    self.sleep(min(120, float(retry_after)) if retry_after.isdigit() else 6 * 2**attempt)
                    continue
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                    raise NVDError("Invalid NVD response schema")
                return payload
            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt == 2:
                    raise NVDError("NVD network failure after three attempts") from None
                self.retries += 1
                self.sleep(6 * 2**attempt)
            except (httpx.HTTPStatusError, ValueError):
                raise NVDError("NVD request rejected or returned malformed JSON") from None
        raise NVDError("NVD request failed")

    def page(self, start, end, index):
        payload = self.request(
            {
                "lastModStartDate": start.isoformat(timespec="milliseconds") + "Z",
                "lastModEndDate": end.isoformat(timespec="milliseconds") + "Z",
                "startIndex": index,
                "resultsPerPage": PAGE_SIZE,
            }
        )
        total = payload.get("totalResults")
        if not isinstance(total, int) or total < 0 or payload.get("startIndex") != index:
            raise NVDError("Invalid NVD pagination metadata")
        entries = payload["vulnerabilities"]
        if not isinstance(entries, list):
            raise NVDError("Invalid NVD response schema")
        pages_total = -(-total // PAGE_SIZE)
        return [entry["cve"] for entry in entries], total, pages_total

    def pages(self, start, end, cursor=0):
        index = cursor
        for _ in range(10000):
            entries, total, pages_total = self.page(start, end, index)
            yield index, entries, total, pages_total
            index += len(entries)
            if index >= total:
                return
            if not entries:
                raise NVDError("NVD pagination made no progress")
        raise NVDError("NVD pagination safety limit exceeded")

    def window(self, start, end):
        for _, entries, _, _ in self.pages(start, end):
            yield from entries


def upsert_cve(db, payload):
    values = extract_cve(payload)
    cve = db.get(CVERecord, values["id"])
    if not cve:
        cve = CVERecord(**values)
        db.add(cve)
    else:
        if cve.modified_at and values["modified_at"] and cve.modified_at > values["modified_at"]:
            return cve
        for key, value in values.items():
            setattr(cve, key, value)
    db.flush()
    vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve.id))
    if not vulnerability:
        vulnerability = Vulnerability(canonical_key=cve.id, cve_id=cve.id, title=cve.id)
        db.add(vulnerability)
    score_changed = vulnerability.cvss_score != cve.cvss_score
    vulnerability.description = cve.description
    vulnerability.cvss_score = cve.cvss_score
    vulnerability.score_source = "nvd"
    if score_changed:
        db.flush()
        for finding in db.scalars(select(Finding).where(Finding.vulnerability_id == vulnerability.id)):
            assess(db, finding, db.get(RiskPolicy, 1))
    return cve


def _open_run(db, kind, start, end):
    run = SyncRun(kind=kind, start=start, end=end, status="running")
    db.add(run)
    db.flush()
    return run


def _resume_run(db, kind, start, end):
    run = db.scalar(
        select(SyncRun)
        .where(SyncRun.kind == kind, SyncRun.status == "running", SyncRun.start == start, SyncRun.end == end)
        .order_by(SyncRun.id.desc())
    )
    if run:
        return run, True
    return _open_run(db, kind, start, end), False


def _stage(db, run, index, entries, seen):
    for entry in entries:
        identifier = entry.get("id")
        if not isinstance(identifier, str):
            raise NVDError("NVD returned an entry without an identifier")
        if identifier in seen:
            continue
        seen.add(identifier)
        db.add(
            SyncStagedCVE(
                run_id=run.id,
                page_index=index,
                cve_id=identifier[:30],
                payload=entry,
            )
        )


def _apply_staged(db, run):
    staged = list(
        db.scalars(select(SyncStagedCVE).where(SyncStagedCVE.run_id == run.id).order_by(SyncStagedCVE.id))
    )
    for row in staged:
        upsert_cve(db, row.payload)
    db.flush()
    return len(staged)


def _discard_staged(db, run):
    db.execute(delete(SyncStagedCVE).where(SyncStagedCVE.run_id == run.id))


def _record(db, run, **values):
    for key, value in values.items():
        setattr(run, key, value)
    run.updated_at = utcnow()
    db.commit()


def _cancelled(db):
    state = db.get(SyncState, 1)
    db.refresh(state)
    return bool(state.cancel_requested)


def sync_window(db, client, start, end, kind="sync", checkpoint=None):
    """Stage every page of one window, then apply it atomically.

    Pages are committed to ``sync_staged_cves`` as they arrive so a crash or
    restart resumes from the recorded cursor instead of refetching. The window's
    CVEs and watermark become visible together only after the final page is
    staged, so a checkpoint can never expose a partially applied window.
    """
    run, resumed = _resume_run(db, kind, start, end)
    db.commit()
    existing = set(db.scalars(select(SyncStagedCVE.cve_id).where(SyncStagedCVE.run_id == run.id)))
    seen = existing
    pages = run.pages_fetched
    cursor = run.cursor_index
    while True:
        page_start = time.monotonic()
        entries, total, pages_total = client.page(start, end, cursor)
        if pages_total != run.pages_total:
            run.pages_total = pages_total
        cursor += len(entries)
        db.flush()
        _stage(db, run, pages, entries, seen)
        run.pages_fetched = pages + 1
        run.cursor_index = cursor
        run.retry_count = client.retries
        _record(db, run, last_page_ms=int((time.monotonic() - page_start) * 1000))
        pages += 1
        if checkpoint:
            checkpoint({"pages": pages, "cursor": cursor, "pages_total": pages_total})
        if _cancelled(db):
            _discard_staged(db, run)
            db.execute(update(SyncState).where(SyncState.id == 1).values(cancel_requested=False))
            _record(db, run, status="cancelled", completed_at=utcnow())
            return "cancelled"
        if cursor >= total or not entries:
            break
    applied = _apply_staged(db, run)
    state = db.get(SyncState, 1)
    state.watermark = end
    state.last_success = utcnow()
    state.last_error = None
    state.lease_until = utcnow() + timedelta(minutes=5)
    _discard_staged(db, run)
    audit(
        db,
        None,
        "nvd.sync" if kind == "sync" else "nvd.backfill",
        "nvd",
        {"start": start.isoformat(), "end": end.isoformat(), "applied": applied, "resumed": resumed},
    )
    _record(db, run, status="completed", completed_at=utcnow())
    return "completed"


def synchronize(client=None, backfill_days=None):
    settings = get_settings()
    now = utcnow()
    lock_connection = None
    if engine.dialect.name == "postgresql":
        lock_connection = engine.connect()
        if not lock_connection.scalar(text("SELECT pg_try_advisory_lock(86174921)")):
            lock_connection.close()
            return False
    with SessionLocal() as db:
        acquired = db.execute(
            update(SyncState)
            .where(SyncState.id == 1, or_(SyncState.lease_until.is_(None), SyncState.lease_until < now))
            .values(
                lease_until=now + timedelta(minutes=5),
                last_attempt=now,
                requested=False,
                cancel_requested=False,
            )
        )
        db.commit()
        if not acquired.rowcount:
            if lock_connection:
                lock_connection.execute(text("SELECT pg_advisory_unlock(86174921)"))
                lock_connection.close()
            return False
    owned_client = client is None
    client = client or NVDClient(settings.nvd_api_key)
    try:
        with SessionLocal() as db:
            pending = list(
                db.scalars(select(CVERecord.id).where(CVERecord.nvd_status == "Pending enrichment").limit(25))
            )
        for identifier in pending:
            payload = client.request({"cveId": identifier})
            with SessionLocal() as db:
                for entry in payload["vulnerabilities"]:
                    upsert_cve(db, entry["cve"])
                db.commit()
        with SessionLocal() as db:
            state = db.get(SyncState, 1)
            if backfill_days:
                start = now - timedelta(days=min(backfill_days, MAX_BACKFILL_DAYS))
            elif state.watermark:
                start = state.watermark - timedelta(minutes=5)
            else:
                start = now - timedelta(days=settings.nvd_initial_days)
        kind = "backfill" if backfill_days else "sync"
        with SessionLocal() as db:
            interrupted = list(
                db.scalars(
                    select(SyncRun)
                    .where(SyncRun.kind == kind, SyncRun.status == "running")
                    .order_by(SyncRun.id)
                )
            )
        for pending in interrupted:
            # A crashed run left staged pages. Finish that exact window before
            # starting new ranges so its work is neither applied early nor lost.
            with SessionLocal() as db:
                outcome = sync_window(db, client, pending.start, pending.end, kind=kind)
            if outcome == "cancelled":
                return False
        while start < now:
            end = min(start + timedelta(days=119), now)
            with SessionLocal() as db:
                outcome = sync_window(db, client, start, end, kind=kind)
            if outcome == "cancelled":
                return False
            start = end
        return True
    except Exception as error:
        with SessionLocal() as db:
            state = db.get(SyncState, 1)
            state.last_error = (
                str(error)[:200]
                if isinstance(error, NVDError)
                else "Synchronization failed; check service logs"
            )
            for run in db.scalars(select(SyncRun).where(SyncRun.status == "running")):
                run.status = "failed"
                run.error = state.last_error
                run.updated_at = utcnow()
                run.completed_at = utcnow()
            db.commit()
        return False
    finally:
        if owned_client:
            client.close()
        with SessionLocal() as db:
            db.execute(update(SyncState).where(SyncState.id == 1).values(lease_until=None))
            db.commit()
        if lock_connection:
            lock_connection.execute(text("SELECT pg_advisory_unlock(86174921)"))
            lock_connection.close()
