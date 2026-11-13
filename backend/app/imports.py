import hashlib
import json

from sqlalchemy import select

from app.db import utcnow
from app.models import Asset, CVERecord, Finding, FindingHistory, RiskPolicy, Vulnerability
from app.risk import assess
from app.security import audit


def import_rows(db, rows, job, actor_id):
    policy = db.get(RiskPolicy, 1)
    for row in rows:
        asset = db.scalar(select(Asset).where(Asset.name == row.asset))
        if not asset:
            raise ValueError("Every imported asset must already exist; create it before import")
        key = row.cve_id or row.external_id
        vulnerability = db.scalar(select(Vulnerability).where(Vulnerability.canonical_key == key))
        if not vulnerability:
            cve = db.get(CVERecord, row.cve_id) if row.cve_id else None
            if row.cve_id and not cve:
                cve = CVERecord(
                    id=row.cve_id, description="Awaiting NVD enrichment", nvd_status="Pending enrichment"
                )
                db.add(cve)
                db.flush()
            authoritative = cve is not None and cve.nvd_status != "Pending enrichment"
            vulnerability = Vulnerability(
                canonical_key=key,
                cve_id=row.cve_id,
                title=row.title,
                description=cve.description if authoritative else row.description,
                cvss_score=cve.cvss_score if authoritative else row.cvss_score,
                score_source="nvd"
                if authoritative
                else ("import" if row.cvss_score is not None else "unknown"),
            )
            db.add(vulnerability)
            db.flush()
        fingerprint = hashlib.sha256(
            json.dumps([asset.name, key, row.locator], separators=(",", ":")).encode()
        ).hexdigest()
        finding = db.scalar(
            select(Finding).where(Finding.fingerprint == fingerprint).with_for_update(of=Finding)
        )
        if finding:
            finding.last_seen = utcnow()
            finding.occurrences += 1
            if finding.status == "verified":
                finding.status = "open"
                finding.remediated_at = None
                finding.due_at = None
                db.add(
                    FindingHistory(
                        finding_id=finding.id,
                        actor_id=actor_id,
                        from_status="verified",
                        to_status="open",
                        note="Reopened after scan re-observation",
                    )
                )
                assess(db, finding, policy, deadline_start=finding.last_seen)
            job.duplicate_count += 1
        else:
            finding = Finding(
                asset=asset,
                vulnerability=vulnerability,
                fingerprint=fingerprint,
                import_job_id=job.id,
                locator=row.locator,
                source=row.source,
            )
            db.add(finding)
            db.flush()
            db.add(
                FindingHistory(
                    finding_id=finding.id, actor_id=actor_id, to_status="open", note="Imported finding"
                )
            )
            assess(db, finding, policy)
            job.created_count += 1
    audit(
        db,
        actor_id,
        "import.completed",
        job.id,
        {"created": job.created_count, "duplicates": job.duplicate_count},
    )
    job.status = "completed"
