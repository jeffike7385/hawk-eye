"""Celery Beat helper functions for scheduled maintenance tasks."""

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from hawk_scan.web.db import ScanRecord

STALE_THRESHOLD_HOURS = 2


def cleanup_expired_scans(engine):
    """Delete all ScanRecords whose expires_at is in the past."""
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        expired = session.query(ScanRecord).filter(ScanRecord.expires_at < now).all()
        for scan in expired:
            session.delete(scan)
        session.commit()


def recover_stale_scans(engine):
    """Mark long-running scans as failed if they exceed STALE_THRESHOLD_HOURS."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_THRESHOLD_HOURS)
    with Session(engine) as session:
        stale = session.query(ScanRecord).filter(
            ScanRecord.status.in_(["scanning", "enumerating"]),
            ScanRecord.started_at < cutoff,
        ).all()
        for scan in stale:
            scan.status = "failed"
            scan.error_message = f"Scan timed out after {STALE_THRESHOLD_HOURS} hours"
            scan.completed_at = datetime.now(timezone.utc)
        session.commit()
