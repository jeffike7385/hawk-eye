"""Tests for hawk_scan.web.tasks — _execute_scan without Celery/Redis."""

import uuid
import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock, ANY
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.web.crypto import encrypt_credentials
from hawk_scan.web.tasks import _execute_scan
from hawk_scan.models import Finding, SkippedFile, FileMetadata


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def scan_id(db_engine):
    sid = uuid.uuid4()
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=sid,
            target_host="WKS-01",
            scan_user="admin",
            entra_user="jeff@example.com",
            status="queued",
            paths=["C:\\Users"],
            exclude_patterns=[],
            redacted=False,
        ))
        session.commit()
    return sid


@pytest.fixture
def mock_settings(tmp_path):
    """Return a mock Settings object with a writable reports_dir."""
    settings = MagicMock()
    settings.reports_dir = str(tmp_path / "reports")
    settings.redis_url = "redis://localhost:6379/0"
    return settings


def test_execute_scan_success(db_engine, scan_id, mock_settings):
    """Full successful scan: enumerate, scan, write findings, generate report."""
    secret = "test-key"
    encrypted = encrypt_credentials("admin", "P@ss", secret)

    # Mock transport
    mock_transport = MagicMock()
    mock_transport.name = "smb"

    # Mock file list returned by enumerate
    mock_file = FileMetadata(
        remote_path="\\\\WKS-01\\C$\\Users\\doc.txt",
        size_bytes=100,
        extension=".txt",
        owner="DOMAIN\\admin",
        modified_time="2026-04-29T10:00:00",
    )

    # Mock finding returned by orchestrator.scan()
    mock_finding = Finding(
        file_path="\\\\WKS-01\\C$\\Users\\doc.txt",
        pattern_name="SSN",
        category="pii",
        severity="high",
        matches=["123-45-6789"],
        match_count=1,
        sample_text="SSN: 123-45-6789",
        file_owner="DOMAIN\\admin",
        file_modified="2026-04-29T10:00:00",
    )

    # Mock orchestrator instance
    mock_orch_instance = MagicMock()
    mock_orch_instance.enumerate.return_value = [mock_file]
    mock_orch_instance.scan.return_value = ([mock_finding], [])

    with (
        patch("hawk_scan.web.tasks._get_engine", return_value=db_engine),
        patch("hawk_scan.web.tasks._get_secret", return_value=secret),
        patch("hawk_scan.web.tasks._publish_progress"),
        patch("hawk_scan.web.tasks.get_settings", return_value=mock_settings),
        patch("hawk_scan.web.tasks.negotiate_transport", return_value=mock_transport),
        patch("hawk_scan.web.tasks.load_fingerprints", return_value={"SSN": {"pattern": "\\d{3}-\\d{2}-\\d{4}"}}),
        patch("hawk_scan.web.tasks.ScanEngine") as mock_engine_cls,
        patch("hawk_scan.web.tasks.ScanOrchestrator", return_value=mock_orch_instance),
        patch("hawk_scan.web.tasks.generate_html_report") as mock_report,
    ):
        _execute_scan(
            scan_id=str(scan_id),
            target_host="WKS-01",
            encrypted_creds=encrypted,
            paths=["C:\\Users"],
            exclude_patterns=[],
            max_file_size_mb=50,
            redact=False,
            transport_type=None,
        )

    # Verify DB state
    with Session(db_engine) as session:
        scan = session.query(ScanRecord).filter(ScanRecord.id == scan_id).one()
        assert scan.status == "completed"
        assert scan.files_found == 1
        assert scan.files_scanned == 1
        assert scan.files_skipped == 0
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.error_message is None
        assert scan.report_path is not None

        findings = session.query(FindingRecord).filter(FindingRecord.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].pattern_name == "SSN"
        assert findings[0].severity == "high"
        assert findings[0].category == "pii"
        assert findings[0].match_count == 1

    # Verify report was generated
    mock_report.assert_called_once()


def test_execute_scan_failure(db_engine, scan_id):
    """Transport negotiation fails -- scan status should be 'failed'."""
    secret = "test-key"
    encrypted = encrypt_credentials("admin", "P@ss", secret)

    with (
        patch("hawk_scan.web.tasks._get_engine", return_value=db_engine),
        patch("hawk_scan.web.tasks._get_secret", return_value=secret),
        patch("hawk_scan.web.tasks._publish_progress"),
        patch(
            "hawk_scan.web.tasks.negotiate_transport",
            side_effect=ConnectionError("unreachable"),
        ),
    ):
        _execute_scan(
            scan_id=str(scan_id),
            target_host="WKS-01",
            encrypted_creds=encrypted,
            paths=["C:\\Users"],
            exclude_patterns=[],
            max_file_size_mb=50,
            redact=False,
            transport_type=None,
        )

    # Verify DB state
    with Session(db_engine) as session:
        scan = session.query(ScanRecord).filter(ScanRecord.id == scan_id).one()
        assert scan.status == "failed"
        assert "unreachable" in scan.error_message
