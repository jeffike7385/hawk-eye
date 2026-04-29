# hawk_scan/tests/test_models.py
from hawk_scan.models import FileMetadata, Finding, ScanResult, SkippedFile, ScanReport


def test_file_metadata_creation():
    meta = FileMetadata(
        remote_path="C:\\Users\\jsmith\\doc.pdf",
        size_bytes=1024,
        extension=".pdf",
    )
    assert meta.remote_path == "C:\\Users\\jsmith\\doc.pdf"
    assert meta.size_bytes == 1024
    assert meta.extension == ".pdf"
    assert meta.owner is None
    assert meta.modified_time is None


def test_finding_creation():
    finding = Finding(
        file_path="C:\\Users\\jsmith\\doc.pdf",
        pattern_name="SSN",
        category="pii",
        severity="high",
        matches=["123-45-6789"],
        match_count=1,
        sample_text="SSN: 123-45-6789",
        file_owner="DOMAIN\\jsmith",
        file_modified="2026-01-15 10:30:00",
    )
    assert finding.severity == "high"
    assert finding.match_count == 1


def test_finding_with_redaction():
    finding = Finding(
        file_path="C:\\test.txt",
        pattern_name="Email",
        category="pii",
        severity="low",
        matches=["j***@example.com"],
        match_count=1,
        sample_text="contact j***@example.com",
    )
    assert "***" in finding.matches[0]


def test_skipped_file():
    skipped = SkippedFile(
        file_path="C:\\Users\\jsmith\\locked.docx",
        reason="File is locked by another process",
    )
    assert skipped.reason == "File is locked by another process"


def test_scan_result_creation():
    result = ScanResult(
        target_host="WORKSTATION-01",
        transport_method="winrm",
        scan_user="DOMAIN\\admin",
        start_time="2026-04-29 10:00:00",
        end_time="2026-04-29 10:05:00",
        duration_seconds=300.0,
        total_files_scanned=150,
        total_files_skipped=3,
        findings=[],
        skipped_files=[],
    )
    assert result.target_host == "WORKSTATION-01"
    assert result.total_files_scanned == 150


def test_scan_report_severity_summary():
    findings = [
        Finding(file_path="a.txt", pattern_name="SSN", category="pii",
                severity="high", matches=["x"], match_count=1, sample_text="x"),
        Finding(file_path="b.txt", pattern_name="SSN", category="pii",
                severity="high", matches=["y"], match_count=1, sample_text="y"),
        Finding(file_path="c.txt", pattern_name="Email", category="pii",
                severity="low", matches=["z"], match_count=1, sample_text="z"),
    ]
    result = ScanResult(
        target_host="WS-01", transport_method="smb", scan_user="admin",
        start_time="", end_time="", duration_seconds=0,
        total_files_scanned=3, total_files_skipped=0,
        findings=findings, skipped_files=[],
    )
    report = ScanReport(result=result)
    summary = report.severity_summary()
    assert summary["high"] == 2
    assert summary["low"] == 1
    assert summary.get("medium", 0) == 0


def test_scan_report_category_summary():
    findings = [
        Finding(file_path="a.txt", pattern_name="SSN", category="pii",
                severity="high", matches=["x"], match_count=1, sample_text="x"),
        Finding(file_path="b.txt", pattern_name="Azure Key", category="secret",
                severity="high", matches=["y"], match_count=1, sample_text="y"),
    ]
    result = ScanResult(
        target_host="WS-01", transport_method="smb", scan_user="admin",
        start_time="", end_time="", duration_seconds=0,
        total_files_scanned=2, total_files_skipped=0,
        findings=findings, skipped_files=[],
    )
    report = ScanReport(result=result)
    summary = report.category_summary()
    assert summary["pii"] == 1
    assert summary["secret"] == 1
