from datetime import timedelta

from app.db import utcnow
from app.models import Notification, RiskAssessment

ACTIVE_STATUSES = {"open", "in_progress", "mitigated"}


def severity(score, policy):
    if score is None:
        return "unknown"
    for level in ("critical", "high", "medium", "low"):
        if score >= getattr(policy, level):
            return level
    return "none"


def calculate_risk(cvss, criticality, exposure, policy):
    base = policy.unknown_baseline if cvss is None else cvss
    multiplier = policy.internet_multiplier if exposure == "internet" else 1
    return round(min(100, base * 10 * (0.6 + criticality * 0.08) * multiplier), 1)


def assess(db, finding, policy, deadline_start=None):
    score = finding.vulnerability.cvss_score
    finding.risk_score = calculate_risk(score, finding.asset.criticality, finding.asset.exposure, policy)
    db.add(
        RiskAssessment(
            finding_id=finding.id,
            policy_id=policy.id,
            score=finding.risk_score,
            inputs={
                "cvss": score,
                "criticality": finding.asset.criticality,
                "exposure": finding.asset.exposure,
                "unknown_baseline": policy.unknown_baseline,
                "internet_multiplier": policy.internet_multiplier,
                "policy_version": policy.version,
                "status": finding.status,
            },
        )
    )
    if finding.due_at is None:
        days = {"critical": 7, "high": 14, "medium": 30, "low": 90, "none": 90, "unknown": 14}
        finding.due_at = (deadline_start or finding.first_seen) + timedelta(
            days=days[severity(score, policy)]
        )
    if finding.risk_score >= 90 and finding.status in ACTIVE_STATUSES:
        from sqlalchemy import select

        key = f"priority:{finding.id}"
        if not db.scalar(select(Notification).where(Notification.dedupe_key == key)):
            db.add(
                Notification(
                    dedupe_key=key,
                    finding_id=finding.id,
                    message=f"High priority finding on {finding.asset.name}: {finding.vulnerability.title}"[
                        :300
                    ],
                )
            )
    return finding.risk_score


def notify_overdue(db):
    from sqlalchemy import select

    from app.models import Finding

    for finding in db.scalars(
        select(Finding).where(Finding.status.in_(ACTIVE_STATUSES), Finding.due_at < utcnow())
    ):
        key = f"overdue:{finding.id}:{finding.due_at.date()}"
        if not db.scalar(select(Notification).where(Notification.dedupe_key == key)):
            db.add(
                Notification(
                    dedupe_key=key,
                    finding_id=finding.id,
                    message=f"Remediation overdue: {finding.vulnerability.title} on {finding.asset.name}"[
                        :300
                    ],
                )
            )
