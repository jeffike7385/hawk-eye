"""Scan execution task — runs inside Celery worker or directly for testing."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from hawk_scan.remote.transport import Credentials, negotiate_transport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.orchestrator import ScanOrchestrator
from hawk_scan.config import load_fingerprints
from hawk_scan.report.generator import generate_html_report
from hawk_scan.models import ScanReport, ScanResult
from hawk_scan.web.db import ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.web.crypto import decrypt_credentials
from hawk_scan.web.config import get_settings


def _get_engine():
    """Return a sync SQLAlchemy engine from settings."""
    settings = get_settings()
    url = settings.database_url.replace("+asyncpg", "")
    return create_engine(url)


def _get_secret() -> str:
    """Return the secret key from settings."""
    return get_settings().secret_key


def _publish_progress(scan_id: str, data: dict) -> None:
    """Publish progress JSON to Redis pub/sub channel scan:{id}:progress."""
    try:
        import redis
        settings = get_settings()
        r = redis.from_url(settings.redis_url)
        channel = f"scan:{scan_id}:progress"
        r.publish(channel, json.dumps(data))
    except Exception:
        pass  # Progress publishing is best-effort


def _execute_scan(
    scan_id: str,
    target_host: str,
    encrypted_creds: str,
    paths: list[str],
    exclude_patterns: list[str],
    max_file_size_mb: int,
    redact: bool,
    transport_type: str | None,
) -> None:
    """Main scan logic — decrypts creds, connects, scans, writes results to DB."""

    engine = _get_engine()
    secret = _get_secret()
    sid = uuid.UUID(scan_id)

    def _update_scan(**kwargs):
        with Session(engine) as session:
            scan = session.query(ScanRecord).filter(ScanRecord.id == sid).one()
            for key, value in kwargs.items():
                setattr(scan, key, value)
            session.commit()

    try:
        # 1. Decrypt credentials
        username, password = decrypt_credentials(encrypted_creds, secret)
        creds = Credentials(username=username, password=password)

        # 2. Update status to enumerating
        _update_scan(status="enumerating", started_at=datetime.now(timezone.utc))
        _publish_progress(scan_id, {"phase": "enumerating"})

        # 3. Connect to target via negotiate_transport
        transport = negotiate_transport(
            target_host=target_host,
            credentials=creds,
            timeout=30,
            force_transport=transport_type,
        )

        # 4. Update transport name in DB
        _update_scan(transport=transport.name)

        # 5. Load fingerprints
        fp_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "fingerprints",
            "default.yml",
        )
        fingerprints = load_fingerprints(fp_path)

        # 6. Create ScanEngine and ScanOrchestrator
        scan_engine = ScanEngine(fingerprints, redact=redact)
        orchestrator = ScanOrchestrator(transport, scan_engine, max_file_size_mb=max_file_size_mb)

        # 7. Enumerate files with progress callback
        def enum_progress(path):
            _publish_progress(scan_id, {"phase": "enumerating", "current_path": path})

        file_list = orchestrator.enumerate(paths, exclude_patterns, progress_callback=enum_progress)

        # 8. Update status to scanning, set files_found
        _update_scan(status="scanning", files_found=len(file_list))
        _publish_progress(scan_id, {"phase": "scanning", "files_found": len(file_list)})

        # 9. Scan files with progress callback
        with tempfile.TemporaryDirectory() as temp_dir:
            def scan_progress(path):
                _publish_progress(scan_id, {"phase": "scanning", "current_file": path})

            findings, skipped = orchestrator.scan(file_list, temp_dir, progress_callback=scan_progress)

        # 10. Write findings and skipped files to DB
        with Session(engine) as session:
            for finding in findings:
                session.add(FindingRecord(
                    id=uuid.uuid4(),
                    scan_id=sid,
                    file_path=finding.file_path,
                    pattern_name=finding.pattern_name,
                    category=finding.category,
                    severity=finding.severity,
                    matches=finding.matches,
                    match_count=finding.match_count,
                    sample_text=finding.sample_text,
                    file_owner=finding.file_owner,
                    file_modified=finding.file_modified,
                ))
            for skip in skipped:
                session.add(SkippedFileRecord(
                    id=uuid.uuid4(),
                    scan_id=sid,
                    file_path=skip.file_path,
                    reason=skip.reason,
                ))
            session.commit()

        # 11. Generate HTML report
        settings = get_settings()
        scan_result = ScanResult(
            target_host=target_host,
            transport_method=transport.name,
            scan_user=username,
            start_time=datetime.now(timezone.utc).isoformat(),
            end_time=datetime.now(timezone.utc).isoformat(),
            duration_seconds=0.0,
            total_files_scanned=len(file_list) - len(skipped),
            total_files_skipped=len(skipped),
            findings=findings,
            skipped_files=skipped,
        )
        report = ScanReport(result=scan_result)
        report_filename = f"hawk_scan_{target_host}_{scan_id}.html"
        report_path = os.path.join(settings.reports_dir, report_filename)
        os.makedirs(settings.reports_dir, exist_ok=True)
        generate_html_report(report, report_path)

        # 12. Update status to completed
        _update_scan(
            status="completed",
            completed_at=datetime.now(timezone.utc),
            files_scanned=len(file_list) - len(skipped),
            files_skipped=len(skipped),
            report_path=report_path,
        )
        _publish_progress(scan_id, {"phase": "completed"})

    except Exception as exc:
        _update_scan(
            status="failed",
            completed_at=datetime.now(timezone.utc),
            error_message=str(exc),
        )
        _publish_progress(scan_id, {"phase": "failed", "error": str(exc)})


# Register as Celery task if Celery/Redis are available
try:
    from hawk_scan.web.celery_app import celery

    @celery.task(name="hawk_scan.run_scan")
    def run_scan_task(
        scan_id: str,
        target_host: str,
        encrypted_creds: str,
        paths: list[str],
        exclude_patterns: list[str],
        max_file_size_mb: int,
        redact: bool,
        transport_type: str | None,
    ):
        _execute_scan(
            scan_id=scan_id,
            target_host=target_host,
            encrypted_creds=encrypted_creds,
            paths=paths,
            exclude_patterns=exclude_patterns,
            max_file_size_mb=max_file_size_mb,
            redact=redact,
            transport_type=transport_type,
        )
except Exception:
    run_scan_task = None
