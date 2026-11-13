from datetime import datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base, utcnow


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), primary_key=True)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(30), unique=True)
    permissions: Mapped[list[Permission]] = relationship(secondary="role_permissions", lazy="selectin")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    role: Mapped[Role] = relationship(lazy="joined")
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(100))
    expires_at: Mapped[datetime] = mapped_column(index=True)


class AssetCategory(Base):
    __tablename__ = "asset_categories"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("criticality BETWEEN 1 AND 5"),
        CheckConstraint("exposure IN ('internal','internet')"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    category_id: Mapped[int] = mapped_column(ForeignKey("asset_categories.id"))
    category: Mapped[AssetCategory] = relationship(lazy="joined")
    criticality: Mapped[int] = mapped_column(default=3)
    exposure: Mapped[str] = mapped_column(String(20), default="internal")
    owner: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class CVERecord(Base):
    __tablename__ = "cve_records"
    __table_args__ = (CheckConstraint("cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10"),)
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(10))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="unknown")
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    affected_products: Mapped[list] = mapped_column(JSON, default=list)
    nvd_status: Mapped[str] = mapped_column(String(50), default="")
    synced_at: Mapped[datetime] = mapped_column(default=utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (CheckConstraint("cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(200), unique=True)
    cve_id: Mapped[str | None] = mapped_column(ForeignKey("cve_records.id"), unique=True)
    cve: Mapped[CVERecord | None] = relationship(lazy="joined")
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    score_source: Mapped[str] = mapped_column(String(20), default="unknown")


class ImportJob(Base):
    __tablename__ = "import_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    adapter: Mapped[str] = mapped_column(String(50))
    filename: Mapped[str] = mapped_column(String(200))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20))
    created_count: Mapped[int] = mapped_column(default=0)
    duplicate_count: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("status IN ('open','in_progress','mitigated','verified','accepted')"),
        Index("ix_findings_status_due", "status", "due_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    asset: Mapped[Asset] = relationship(lazy="joined")
    vulnerability: Mapped[Vulnerability] = relationship(lazy="joined")
    import_job_id: Mapped[int | None] = mapped_column(ForeignKey("import_jobs.id"))
    locator: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    occurrences: Mapped[int] = mapped_column(default=1)
    due_at: Mapped[datetime | None] = mapped_column(DateTime)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    revision: Mapped[int] = mapped_column(default=1)
    __mapper_args__ = {"version_id_col": revision}
    assignment: Mapped["RemediationAssignment | None"] = relationship(lazy="joined")


class FindingHistory(Base):
    __tablename__ = "finding_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    from_status: Mapped[str | None] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class RemediationAssignment(Base):
    __tablename__ = "remediation_assignments"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    assigned_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    assigned_at: Mapped[datetime] = mapped_column(default=utcnow)


class RemediationActivity(Base):
    __tablename__ = "remediation_activities"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(String(30))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class RiskPolicy(Base):
    __tablename__ = "risk_policies"
    __table_args__ = (
        CheckConstraint("id = 1"),
        CheckConstraint("0 < low AND low < medium AND medium < high AND high < critical AND critical <= 10"),
    )
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    low: Mapped[float] = mapped_column(Float, default=0.1)
    medium: Mapped[float] = mapped_column(Float, default=4)
    high: Mapped[float] = mapped_column(Float, default=7)
    critical: Mapped[float] = mapped_column(Float, default=9)
    internet_multiplier: Mapped[float] = mapped_column(Float, default=1.25)
    unknown_baseline: Mapped[float] = mapped_column(Float, default=5)
    version: Mapped[int] = mapped_column(default=1)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("risk_policies.id"))
    score: Mapped[float] = mapped_column(Float)
    inputs: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(60), index=True)
    target: Mapped[str] = mapped_column(String(200))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(200), unique=True)
    message: Mapped[str] = mapped_column(String(300))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class SyncState(Base):
    __tablename__ = "sync_state"
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    watermark: Mapped[datetime | None] = mapped_column(DateTime)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime)
    last_success: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(String(200))
    requested: Mapped[bool] = mapped_column(default=False)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    __table_args__ = (UniqueConstraint("key", "window"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64))
    window: Mapped[int] = mapped_column(Integer, index=True)
    count: Mapped[int] = mapped_column(default=1)
