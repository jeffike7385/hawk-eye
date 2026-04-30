import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_tables_created(db_session):
    inspector = inspect(db_session.bind)
    tables = inspector.get_table_names()
    assert "scans" in tables
    assert "findings" in tables
    assert "skipped_files" in tables


def test_create_scan(db_session):
    scan = ScanRecord(
        id=uuid.uuid4(),
        target_host="WKS-01",
        scan_user="DOMAIN\\admin",
        entra_user="jeff@example.com",
        status="queued",
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=True,
    )
    db_session.add(scan)
    db_session.commit()
    assert scan.created_at is not None
    assert scan.expires_at is not None


def test_finding_cascade_delete(db_session):
    scan_id = uuid.uuid4()
    scan = ScanRecord(
        id=scan_id,
        target_host="WKS-01",
        scan_user="admin",
        entra_user="jeff@example.com",
        status="completed",
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=False,
    )
    finding = FindingRecord(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="\\\\WKS-01\\C$\\file.txt",
        pattern_name="SSN",
        category="pii",
        severity="high",
        matches=["123-45-6789"],
        match_count=1,
        sample_text="SSN: 123-45-...",
    )
    db_session.add(scan)
    db_session.add(finding)
    db_session.commit()
    db_session.delete(scan)
    db_session.commit()
    assert db_session.query(FindingRecord).count() == 0


def test_skipped_file_cascade_delete(db_session):
    scan_id = uuid.uuid4()
    scan = ScanRecord(
        id=scan_id,
        target_host="WKS-01",
        scan_user="admin",
        entra_user="jeff@example.com",
        status="completed",
        paths=[],
        exclude_patterns=[],
        redacted=False,
    )
    skipped = SkippedFileRecord(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="\\\\WKS-01\\C$\\big.zip",
        reason="Too large",
    )
    db_session.add(scan)
    db_session.add(skipped)
    db_session.commit()
    db_session.delete(scan)
    db_session.commit()
    assert db_session.query(SkippedFileRecord).count() == 0
