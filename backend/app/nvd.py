import math
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_, select, text, update

from app.config import get_settings
from app.db import SessionLocal, engine, utcnow
from app.models import CVERecord, Finding, RiskPolicy, SyncState, Vulnerability
from app.risk import assess
from app.security import audit

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


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
                self.sleep(6 * 2**attempt)
            except (httpx.HTTPStatusError, ValueError):
                raise NVDError("NVD request rejected or returned malformed JSON") from None
        raise NVDError("NVD request failed")

    def window(self, start, end):
        index = 0
        for _ in range(10000):
            payload = self.request(
                {
                    "lastModStartDate": start.isoformat(timespec="milliseconds") + "Z",
                    "lastModEndDate": end.isoformat(timespec="milliseconds") + "Z",
                    "startIndex": index,
                    "resultsPerPage": 2000,
                }
            )
            entries = payload["vulnerabilities"]
            total = payload.get("totalResults")
            if not isinstance(total, int) or total < 0 or payload.get("startIndex") != index:
                raise NVDError("Invalid NVD pagination metadata")
            for entry in entries:
                yield entry["cve"]
            index += len(entries)
            if index >= total:
                return
            if not entries:
                raise NVDError("NVD pagination made no progress")
        raise NVDError("NVD pagination safety limit exceeded")


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


def synchronize(client=None):
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
            .values(lease_until=now + timedelta(minutes=5), last_attempt=now, requested=False)
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
            start = (
                (state.watermark - timedelta(minutes=5))
                if state.watermark
                else now - timedelta(days=settings.nvd_initial_days)
            )
        while start < now:
            end = min(start + timedelta(days=119), now)
            with SessionLocal() as db:
                for payload in client.window(start, end):
                    upsert_cve(db, payload)
                    db.flush()
                state = db.get(SyncState, 1)
                state.watermark = end
                state.last_success = utcnow()
                state.last_error = None
                state.lease_until = utcnow() + timedelta(minutes=5)
                audit(db, None, "nvd.sync", "nvd", {"start": start.isoformat(), "end": end.isoformat()})
                db.commit()
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
