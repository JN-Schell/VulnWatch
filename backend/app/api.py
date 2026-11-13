import csv
import io
import logging
import re
import secrets
from collections import Counter, defaultdict
from datetime import timedelta, timezone

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartParser

from app.adapters import ADAPTERS, MAX_BYTES, ImportError, parse_import
from app.config import get_settings
from app.db import SessionLocal, get_db, utcnow
from app.imports import import_rows
from app.models import (
    Asset,
    AssetCategory,
    AuditEvent,
    CVERecord,
    Finding,
    FindingHistory,
    ImportJob,
    Notification,
    RemediationActivity,
    RemediationAssignment,
    RiskAssessment,
    RiskPolicy,
    Role,
    Session,
    SyncState,
    User,
    Vulnerability,
)
from app.risk import ACTIVE_STATUSES, assess, severity
from app.schemas import AssetInput, FindingUpdate, Login, PolicyInput, UserCreate
from app.security import (
    DUMMY_HASH,
    audit,
    check_origin,
    consume_rate,
    current_user,
    digest,
    passwords,
    require,
)

settings = get_settings()
MultiPartParser.spool_max_size = MAX_BYTES + 65536


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        received = 0

        async def bounded_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > MAX_BYTES + 65536:
                raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, bounded_receive, send)


app = FastAPI(title="VulnWatch API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(BodyLimitMiddleware)
logger = logging.getLogger("vulnwatch")


def rate_boundary(request):
    with SessionLocal() as db:
        token = request.cookies.get("vw_session", "")
        session = db.get(Session, digest(token)) if token and len(token) <= 100 else None
        identity = (
            f"user:{session.user_id}"
            if session and session.expires_at > utcnow()
            else f"ip:{request.client.host if request.client else 'unknown'}"
        )
        consume_rate(db, f"api:{identity}", 300)


@app.middleware("http")
async def boundary(request: Request, call_next):
    request_id = secrets.token_hex(8)
    try:
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > MAX_BYTES + 65536):
            response = JSONResponse({"detail": "Request body too large"}, status_code=413)
        else:
            await run_in_threadpool(rate_boundary, request)
            response = await call_next(request)
    except HTTPException as error:
        response = JSONResponse(
            {"detail": error.detail}, status_code=error.status_code, headers=error.headers
        )
    except Exception:
        logger.exception("Unhandled error request_id=%s", request_id)
        response = JSONResponse(
            {"detail": "Internal service error", "request_id": request_id}, status_code=500
        )
    response.headers.update(
        {
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        }
    )
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    return JSONResponse(
        {
            "detail": "Input validation failed",
            "fields": [".".join(map(str, item["loc"])) for item in error.errors()],
        },
        status_code=422,
    )


@app.exception_handler(IntegrityError)
async def integrity_error(request, error):
    return JSONResponse({"detail": "Conflicting record or invalid relationship"}, status_code=409)


@app.exception_handler(StaleDataError)
async def stale_error(request, error):
    return JSONResponse({"detail": "Record changed; refresh and retry"}, status_code=409)


def public_user(user):
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role.name,
        "active": user.active,
    }


def policy_data(policy):
    return {field: getattr(policy, field) for field in PolicyInput.model_fields} | {"version": policy.version}


def asset_data(asset):
    return {
        "id": asset.id,
        "name": asset.name,
        "category": asset.category.name,
        "criticality": asset.criticality,
        "exposure": asset.exposure,
        "owner": asset.owner,
    }


def finding_data(finding, policy):
    vulnerability = finding.vulnerability
    return {
        "id": finding.id,
        "title": vulnerability.title,
        "description": vulnerability.description,
        "cve_id": vulnerability.cve_id,
        "cvss_score": vulnerability.cvss_score,
        "score_source": vulnerability.score_source,
        "severity": severity(vulnerability.cvss_score, policy),
        "asset": asset_data(finding.asset),
        "status": finding.status,
        "risk_score": finding.risk_score,
        "locator": finding.locator,
        "source": finding.source,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "occurrences": finding.occurrences,
        "due_at": finding.due_at,
        "remediated_at": finding.remediated_at,
        "revision": finding.revision,
        "assignee_id": finding.assignment.user_id if finding.assignment else None,
        "overdue": finding.status in ACTIVE_STATUSES
        and finding.due_at is not None
        and finding.due_at < utcnow(),
    }


def get_finding(db, finding_id):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


@app.get("/api/health")
def health(db=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.get("/api/openapi.json")
def openapi(user=Depends(require("read"))):
    return app.openapi()


@app.post("/api/auth/login")
def login(data: Login, request: Request, response: Response, db=Depends(get_db)):
    check_origin(request)
    ip = request.client.host if request.client else "unknown"
    consume_rate(db, f"login-ip:{ip}", 10)
    consume_rate(db, f"login-account:{data.email.lower()}", 10)
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    valid = passwords.verify(data.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid or not user.active:
        audit(db, None, "auth.failed", "login")
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    previous = request.cookies.get("vw_session")
    if previous:
        db.execute(delete(Session).where(Session.token_hash == digest(previous)))
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(
        Session(
            token_hash=digest(token),
            user_id=user.id,
            csrf_token=csrf,
            expires_at=utcnow() + timedelta(hours=settings.session_hours),
        )
    )
    audit(db, user.id, "auth.login", user.id)
    db.commit()
    response.set_cookie(
        "vw_session",
        token,
        httponly=True,
        secure=settings.environment == "production",
        samesite="strict",
        max_age=settings.session_hours * 3600,
        path="/api",
    )
    return {"user": public_user(user), "csrf_token": csrf}


@app.get("/api/auth/session")
def session(request: Request, user=Depends(current_user)):
    return {"user": public_user(user), "csrf_token": request.state.auth_session.csrf_token}


@app.post("/api/auth/logout", status_code=204)
def logout(request: Request, response: Response, user=Depends(current_user), db=Depends(get_db)):
    db.execute(delete(Session).where(Session.token_hash == request.state.auth_session.token_hash))
    audit(db, user.id, "auth.logout", user.id)
    db.commit()
    response.delete_cookie("vw_session", path="/api")


@app.get("/api/users")
def users(user=Depends(require("read")), db=Depends(get_db)):
    return [public_user(entry) for entry in db.scalars(select(User).order_by(User.name))]


@app.post("/api/users", status_code=201)
def create_user(data: UserCreate, user=Depends(require("admin")), db=Depends(get_db)):
    role = db.scalar(select(Role).where(Role.name == data.role))
    created = User(
        email=data.email.lower(), name=data.name, password_hash=passwords.hash(data.password), role=role
    )
    db.add(created)
    db.flush()
    audit(db, user.id, "user.created", created.id, {"role": data.role})
    db.commit()
    return public_user(created)


@app.post("/api/users/{user_id}/disable", status_code=204)
def disable_user(user_id: int, user=Depends(require("admin")), db=Depends(get_db)):
    if user_id == user.id:
        raise HTTPException(409, "Cannot disable your own administrator account")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    target.active = False
    db.execute(delete(Session).where(Session.user_id == user_id))
    audit(db, user.id, "user.disabled", user_id)
    db.commit()


@app.get("/api/assets")
def assets(user=Depends(require("read")), db=Depends(get_db)):
    return [asset_data(asset) for asset in db.scalars(select(Asset).order_by(Asset.name))]


def save_asset(db, data, asset=None):
    category = db.scalar(select(AssetCategory).where(AssetCategory.name == data.category))
    if not category:
        category = AssetCategory(name=data.category)
        db.add(category)
        db.flush()
    asset = asset or Asset()
    for field in ("name", "criticality", "exposure", "owner"):
        setattr(asset, field, getattr(data, field))
    asset.category = category
    db.add(asset)
    db.flush()
    return asset


@app.post("/api/assets", status_code=201)
def create_asset(data: AssetInput, user=Depends(require("write")), db=Depends(get_db)):
    asset = save_asset(db, data)
    audit(db, user.id, "asset.created", asset.id)
    db.commit()
    return asset_data(asset)


@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: int, data: AssetInput, user=Depends(require("write")), db=Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    if asset.name != data.name:
        raise HTTPException(409, "Asset identity is immutable; create a new asset instead")
    save_asset(db, data, asset)
    for finding in db.scalars(select(Finding).where(Finding.asset_id == asset_id)):
        assess(db, finding, db.get(RiskPolicy, 1))
    audit(db, user.id, "asset.updated", asset.id)
    db.commit()
    return asset_data(asset)


@app.get("/api/imports/adapters")
def adapters(user=Depends(require("read"))):
    return [
        {"id": key, "extension": adapter.extension, "schema_version": "1.0"}
        for key, adapter in ADAPTERS.items()
    ]


@app.get("/api/imports")
def imports(user=Depends(require("read")), db=Depends(get_db)):
    return [
        {
            "id": job.id,
            "adapter": job.adapter,
            "filename": job.filename,
            "status": job.status,
            "created_count": job.created_count,
            "duplicate_count": job.duplicate_count,
            "error": job.error,
            "created_at": job.created_at,
        }
        for job in db.scalars(select(ImportJob).order_by(ImportJob.id.desc()).limit(100))
    ]


@app.post("/api/imports", status_code=201)
def upload(
    adapter: str = Query(max_length=50, pattern=r"^[a-z][a-z0-9-]*$"),
    file: UploadFile = File(...),
    user=Depends(require("write")),
    db=Depends(get_db),
):
    filename = (file.filename or "upload").replace("\\", "/").split("/")[-1][:200]
    filename = re.sub(r"[\x00-\x1f\x7f]", "_", filename)
    job = ImportJob(
        adapter=adapter[:50],
        filename=filename,
        user_id=user.id,
        status="processing",
        created_count=0,
        duplicate_count=0,
    )
    try:
        content = file.file.read(MAX_BYTES + 1)
        rows = parse_import(adapter, content, filename)
        db.add(job)
        db.flush()
        import_rows(db, rows, job, user.id)
        db.commit()
        return {
            "id": job.id,
            "status": job.status,
            "created": job.created_count,
            "duplicates": job.duplicate_count,
        }
    except (ImportError, ValueError, IntegrityError, StaleDataError) as error:
        db.rollback()
        message = (
            str(error)
            if isinstance(error, (ImportError, ValueError))
            else "Concurrent import conflict; retry the entire batch"
        )
        failed = ImportJob(
            adapter=adapter[:50], filename=filename, user_id=user.id, status="failed", error=message[:300]
        )
        db.add(failed)
        db.flush()
        audit(db, user.id, "import.failed", failed.id, {"reason": message[:300]})
        db.commit()
        raise HTTPException(422, message[:300]) from None
    finally:
        file.file.close()


@app.get("/api/findings")
def findings(
    q: str = Query(default="", max_length=200),
    status: str | None = None,
    asset_id: int | None = None,
    assignee_id: int | None = None,
    severity_level: str | None = None,
    overdue: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    user=Depends(require("read")),
    db=Depends(get_db),
):
    query = select(Finding).join(Vulnerability).join(Asset)
    if q:
        query = query.where(
            (Vulnerability.title.icontains(q, autoescape=True))
            | (Vulnerability.canonical_key.icontains(q, autoescape=True))
            | (Asset.name.icontains(q, autoescape=True))
        )
    if status:
        query = query.where(Finding.status == status)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if assignee_id:
        query = query.join(RemediationAssignment).where(RemediationAssignment.user_id == assignee_id)
    if overdue:
        query = query.where(Finding.status.in_(ACTIVE_STATUSES), Finding.due_at < utcnow())
    policy = db.get(RiskPolicy, 1)
    if severity_level:
        if severity_level == "unknown":
            query = query.where(Vulnerability.cvss_score.is_(None))
        elif severity_level in {"none", "low", "medium", "high", "critical"}:
            bounds = {
                "none": (0, policy.low),
                "low": (policy.low, policy.medium),
                "medium": (policy.medium, policy.high),
                "high": (policy.high, policy.critical),
                "critical": (policy.critical, 11),
            }
            lower, upper = bounds[severity_level]
            query = query.where(Vulnerability.cvss_score >= lower, Vulnerability.cvss_score < upper)
        else:
            raise HTTPException(422, "Unknown severity filter")
    count = db.scalar(select(func.count()).select_from(query.subquery()))
    entries = db.scalars(
        query.order_by(Finding.risk_score.desc(), Finding.id).offset((page - 1) * page_size).limit(page_size)
    ).unique()
    return {
        "items": [finding_data(entry, policy) for entry in entries],
        "total": count,
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: int, user=Depends(require("read")), db=Depends(get_db)):
    finding = get_finding(db, finding_id)
    result = finding_data(finding, db.get(RiskPolicy, 1))
    result["history"] = [
        {
            "from_status": entry.from_status,
            "to_status": entry.to_status,
            "note": entry.note,
            "created_at": entry.created_at,
            "actor_id": entry.actor_id,
        }
        for entry in db.scalars(
            select(FindingHistory)
            .where(FindingHistory.finding_id == finding_id)
            .order_by(FindingHistory.id.desc())
        )
    ]
    result["activities"] = [
        {"kind": entry.kind, "note": entry.note, "created_at": entry.created_at, "user_id": entry.user_id}
        for entry in db.scalars(
            select(RemediationActivity)
            .where(RemediationActivity.finding_id == finding_id)
            .order_by(RemediationActivity.id.desc())
        )
    ]
    result["risk_history"] = [
        {"score": entry.score, "inputs": entry.inputs, "created_at": entry.created_at}
        for entry in db.scalars(
            select(RiskAssessment)
            .where(RiskAssessment.finding_id == finding_id)
            .order_by(RiskAssessment.id.desc())
            .limit(100)
        )
    ]
    return result


TRANSITIONS = {
    "open": {"in_progress", "accepted"},
    "in_progress": {"open", "mitigated", "accepted"},
    "mitigated": {"in_progress", "verified", "accepted"},
    "verified": {"open"},
    "accepted": {"open"},
}


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, data: FindingUpdate, user=Depends(require("write")), db=Depends(get_db)):
    finding = get_finding(db, finding_id)
    if data.revision != finding.revision:
        raise HTTPException(409, "Record changed; refresh and retry")
    previous = finding.status
    if data.status and data.status != previous:
        if data.status not in TRANSITIONS[previous]:
            raise HTTPException(409, "Invalid remediation state transition")
        if data.status == "accepted" and user.role.name != "admin":
            raise HTTPException(403, "Only administrators may accept risk")
        if data.status == "verified" and data.kind != "verification":
            raise HTTPException(422, "Verification evidence is required")
        if data.status == "mitigated" and data.kind != "mitigation":
            raise HTTPException(422, "Mitigation evidence is required")
        finding.status = data.status
        finding.remediated_at = utcnow() if data.status == "verified" else None
        db.add(
            FindingHistory(
                finding_id=finding_id,
                actor_id=user.id,
                from_status=previous,
                to_status=data.status,
                note=data.note,
            )
        )
    if "due_at" in data.model_fields_set:
        finding.due_at = data.due_at.astimezone(timezone.utc).replace(tzinfo=None) if data.due_at else None
    if "assignee_id" in data.model_fields_set:
        if data.assignee_id is None:
            if finding.assignment:
                db.delete(finding.assignment)
                finding.assignment = None
        else:
            assignee = db.get(User, data.assignee_id)
            if not assignee or not assignee.active or assignee.role.name == "viewer":
                raise HTTPException(422, "Assignee must be an active analyst or administrator")
            if finding.assignment:
                finding.assignment.user_id = assignee.id
                finding.assignment.assigned_by = user.id
                finding.assignment.assigned_at = utcnow()
            else:
                finding.assignment = RemediationAssignment(user_id=assignee.id, assigned_by=user.id)
            db.add(
                Notification(
                    dedupe_key=f"assigned:{finding_id}:{secrets.token_hex(8)}",
                    finding_id=finding_id,
                    message=f"{assignee.name} assigned to {finding.vulnerability.title}"[:300],
                )
            )
    db.add(RemediationActivity(finding_id=finding_id, user_id=user.id, kind=data.kind, note=data.note))
    finding.revision += 1
    assess(db, finding, db.get(RiskPolicy, 1))
    audit(
        db,
        user.id,
        "finding.updated",
        finding_id,
        {"from": previous, "to": finding.status, "kind": data.kind},
    )
    db.commit()
    return finding_data(finding, db.get(RiskPolicy, 1))


@app.get("/api/cves")
def cves(
    q: str = Query(default="", max_length=200),
    page: int = Query(default=1, ge=1),
    user=Depends(require("read")),
    db=Depends(get_db),
):
    query = select(CVERecord).where(
        CVERecord.id.icontains(q, autoescape=True) | CVERecord.description.icontains(q, autoescape=True)
    )
    return {
        "total": db.scalar(select(func.count()).select_from(query.subquery())),
        "items": [
            {
                "id": entry.id,
                "description": entry.description,
                "cvss_score": entry.cvss_score,
                "cvss_version": entry.cvss_version,
                "severity": entry.severity,
                "nvd_status": entry.nvd_status,
                "published_at": entry.published_at,
                "modified_at": entry.modified_at,
            }
            for entry in db.scalars(
                query.order_by(CVERecord.modified_at.desc()).offset((page - 1) * 50).limit(50)
            )
        ],
    }


@app.get("/api/cves/{cve_id}")
def cve_detail(cve_id: str, user=Depends(require("read")), db=Depends(get_db)):
    cve = db.get(CVERecord, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return {column.name: getattr(cve, column.name) for column in CVERecord.__table__.columns}


@app.get("/api/policy")
def policy(user=Depends(require("read")), db=Depends(get_db)):
    return policy_data(db.get(RiskPolicy, 1))


@app.put("/api/policy")
def update_policy(data: PolicyInput, user=Depends(require("admin")), db=Depends(get_db)):
    policy = db.get(RiskPolicy, 1)
    for field, value in data.model_dump().items():
        setattr(policy, field, value)
    policy.version += 1
    for finding in db.scalars(select(Finding)):
        assess(db, finding, policy)
    audit(db, user.id, "policy.updated", policy.version, data.model_dump())
    db.commit()
    return policy_data(policy)


@app.get("/api/sync")
def sync_status(user=Depends(require("read")), db=Depends(get_db)):
    state = db.get(SyncState, 1)
    return {
        "watermark": state.watermark,
        "last_attempt": state.last_attempt,
        "last_success": state.last_success,
        "last_error": state.last_error,
        "requested": state.requested,
        "running": bool(state.lease_until and state.lease_until > utcnow()),
        "api_key_configured": bool(settings.nvd_api_key),
    }


@app.post("/api/sync", status_code=202)
def request_sync(user=Depends(require("admin")), db=Depends(get_db)):
    state = db.get(SyncState, 1)
    if state.last_attempt and utcnow() - state.last_attempt < timedelta(hours=2):
        raise HTTPException(429, "NVD synchronization is limited to once every two hours")
    state.requested = True
    audit(db, user.id, "nvd.requested", "nvd")
    db.commit()
    return {"status": "queued", "message": "The worker must be running to process this request"}


def report_data(db, asset_id=None):
    policy = db.get(RiskPolicy, 1)
    query = select(Finding)
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)
    findings = list(db.scalars(query))
    now = utcnow()
    counts = Counter(entry.status for entry in findings)
    levels = Counter(severity(entry.vulnerability.cvss_score, policy) for entry in findings)
    active = [entry for entry in findings if entry.status in ACTIVE_STATUSES]
    ages = Counter(
        "0–7 days"
        if (now - entry.first_seen).days <= 7
        else "8–30 days"
        if (now - entry.first_seen).days <= 30
        else "31–90 days"
        if (now - entry.first_seen).days <= 90
        else "90+ days"
        for entry in active
    )
    times = [
        (entry.remediated_at - entry.first_seen).total_seconds() / 86400
        for entry in findings
        if entry.remediated_at
    ]
    distribution = Counter(entry.asset.name for entry in active)
    snapshots = defaultdict(dict)
    assessment_query = select(RiskAssessment).order_by(RiskAssessment.created_at, RiskAssessment.id)
    if asset_id is not None:
        assessment_query = assessment_query.join(Finding).where(Finding.asset_id == asset_id)
    latest = {}
    for assessment in db.scalars(assessment_query):
        latest[assessment.finding_id] = (
            assessment.score if assessment.inputs.get("status", "open") in ACTIVE_STATUSES else 0
        )
        snapshots[assessment.created_at.date().isoformat()] = {
            "date": assessment.created_at.date().isoformat(),
            "risk": round(sum(latest.values()), 1),
        }
    performance = []
    for member in db.scalars(select(User).where(User.active.is_(True))):
        assigned = [entry for entry in findings if entry.assignment and entry.assignment.user_id == member.id]
        if assigned:
            performance.append(
                {
                    "name": member.name,
                    "assigned": len(assigned),
                    "verified": sum(entry.status == "verified" for entry in assigned),
                    "overdue": sum(
                        entry.status in ACTIVE_STATUSES and entry.due_at is not None and entry.due_at < now
                        for entry in assigned
                    ),
                }
            )
    return {
        "total": len(findings),
        "unique_vulnerabilities": len({entry.vulnerability_id for entry in findings}),
        "active": len(active),
        "verified": counts["verified"],
        "accepted": counts["accepted"],
        "severity": dict(levels),
        "statuses": dict(counts),
        "overdue": sum(entry.due_at is not None and entry.due_at < now for entry in active),
        "average_remediation_days": round(sum(times) / len(times), 1) if times else None,
        "risk_total": round(sum(entry.risk_score for entry in active), 1),
        "aging": dict(ages),
        "asset_distribution": [{"asset": name, "count": count} for name, count in distribution.most_common()],
        "trend": list(snapshots.values())[-30:],
        "performance": performance,
    }


@app.get("/api/dashboard")
def dashboard(user=Depends(require("read")), db=Depends(get_db)):
    return report_data(db)


@app.get("/api/assets/{asset_id}/report")
def asset_report(asset_id: int, user=Depends(require("read")), db=Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return {"asset": asset_data(asset), **report_data(db, asset_id)}


def csv_safe(value):
    value = str(value if value is not None else "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


@app.get("/api/reports/export")
def export(asset_id: int | None = None, user=Depends(require("read")), db=Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "finding_id",
            "asset",
            "title",
            "cve",
            "cvss",
            "custom_priority",
            "status",
            "due_at",
            "first_seen",
            "last_seen",
        ]
    )
    query = select(Finding).order_by(Finding.id)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    for finding in db.scalars(query):
        writer.writerow(
            [
                csv_safe(value)
                for value in [
                    finding.id,
                    finding.asset.name,
                    finding.vulnerability.title,
                    finding.vulnerability.cve_id,
                    finding.vulnerability.cvss_score,
                    finding.risk_score,
                    finding.status,
                    finding.due_at,
                    finding.first_seen,
                    finding.last_seen,
                ]
            ]
        )
    audit(db, user.id, "report.exported", asset_id or "all")
    db.commit()
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vulnwatch-findings.csv"'},
    )


@app.get("/api/notifications")
def notifications(user=Depends(require("read")), db=Depends(get_db)):
    return [
        {
            "id": entry.id,
            "message": entry.message,
            "finding_id": entry.finding_id,
            "created_at": entry.created_at,
        }
        for entry in db.scalars(select(Notification).order_by(Notification.id.desc()).limit(50))
    ]


@app.get("/api/audit")
def audit_events(page: int = Query(default=1, ge=1), user=Depends(require("audit")), db=Depends(get_db)):
    return [
        {
            "id": entry.id,
            "actor_id": entry.actor_id,
            "action": entry.action,
            "target": entry.target,
            "details": entry.details,
            "created_at": entry.created_at,
        }
        for entry in db.scalars(
            select(AuditEvent).order_by(AuditEvent.id.desc()).offset((page - 1) * 100).limit(100)
        )
    ]
