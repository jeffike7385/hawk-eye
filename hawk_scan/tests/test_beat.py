import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord
from hawk_scan.web.beat import cleanup_expired_scans, recover_stale_scans


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def test_cleanup_deletes_expired(db_engine):
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        ))
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-02", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        ))
        session.commit()

    cleanup_expired_scans(db_engine)

    with Session(db_engine) as session:
        remaining = session.query(ScanRecord).all()
        assert len(remaining) == 1
        assert remaining[0].target_host == "WKS-02"


def test_recover_stale_scans(db_engine):
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="scanning",
            paths=[], exclude_patterns=[], redacted=False,
            started_at=datetime.now(timezone.utc) - timedelta(hours=3),
        ))
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-02", scan_user="admin",
            entra_user="jeff@example.com", status="scanning",
            paths=[], exclude_patterns=[], redacted=False,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        ))
        session.commit()

    recover_stale_scans(db_engine)

    with Session(db_engine) as session:
        scans = session.query(ScanRecord).all()
        stale = [s for s in scans if s.target_host == "WKS-01"][0]
        fresh = [s for s in scans if s.target_host == "WKS-02"][0]
        assert stale.status == "failed"
        assert "timed out" in stale.error_message.lower()
        assert fresh.status == "scanning"
