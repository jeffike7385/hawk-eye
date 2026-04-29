import os
import json
import shutil
import pytest
from unittest.mock import MagicMock
from hawk_scan.models import FileMetadata, ScanResult, ScanReport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.orchestrator import ScanOrchestrator
from hawk_scan.report.generator import generate_html_report, generate_json_report


@pytest.fixture
def mock_transport_with_files(tmp_scan_dir):
    transport = MagicMock()
    transport.name = "smb"

    source_dir = os.path.join(tmp_scan_dir, "source")
    os.makedirs(source_dir, exist_ok=True)

    txt_path = os.path.join(source_dir, "employee_data.txt")
    with open(txt_path, "w") as f:
        f.write("Employee: John Smith\n")
        f.write("SSN: 123-45-6789\n")
        f.write("Email: john.smith@company.com\n")
        f.write("Password: MyS3cretP@ss!\n")

    clean_path = os.path.join(source_dir, "readme.txt")
    with open(clean_path, "w") as f:
        f.write("This is a clean file with no PII.\n")

    transport.enumerate.return_value = [
        FileMetadata(remote_path="C:\\Users\\jsmith\\employee_data.txt", size_bytes=200, extension=".txt"),
        FileMetadata(remote_path="C:\\Users\\jsmith\\readme.txt", size_bytes=50, extension=".txt"),
    ]

    def retrieve(remote_path, local_dir):
        # Use ntpath to handle Windows-style paths on any OS
        import ntpath
        name = ntpath.basename(remote_path)
        src = os.path.join(source_dir, name)
        dst = os.path.join(local_dir, name)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            return dst
        return None

    transport.retrieve.side_effect = retrieve
    return transport


def test_full_scan_pipeline(mock_transport_with_files, tmp_scan_dir, simple_fingerprints):
    engine = ScanEngine(simple_fingerprints, redact=False)
    orchestrator = ScanOrchestrator(
        transport=mock_transport_with_files, engine=engine, max_file_size_mb=50,
    )

    scan_dir = os.path.join(tmp_scan_dir, "scan_temp")
    os.makedirs(scan_dir, exist_ok=True)
    findings, skipped = orchestrator.run(
        paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=scan_dir,
    )

    assert len(findings) >= 2
    pattern_names = {f.pattern_name for f in findings}
    assert "SSN" in pattern_names
    assert "Email" in pattern_names
    assert all(f.file_path.startswith("C:\\") for f in findings)

    result = ScanResult(
        target_host="WORKSTATION-01", transport_method="smb", scan_user="DOMAIN\\admin",
        start_time="2026-04-29 10:00:00", end_time="2026-04-29 10:01:00",
        duration_seconds=60.0, total_files_scanned=2, total_files_skipped=len(skipped),
        findings=findings, skipped_files=skipped,
    )
    report = ScanReport(result=result)

    html_path = os.path.join(tmp_scan_dir, "report.html")
    generate_html_report(report, html_path)
    assert os.path.exists(html_path)
    with open(html_path) as f:
        html = f.read()
    assert "SSN" in html
    assert "WORKSTATION-01" in html

    json_path = os.path.join(tmp_scan_dir, "report.json")
    generate_json_report(report, json_path)
    with open(json_path) as f:
        data = json.load(f)
    assert data["target_host"] == "WORKSTATION-01"
    assert len(data["findings"]) >= 2
    assert data["severity_summary"]["high"] >= 1


def test_full_scan_with_redaction(mock_transport_with_files, tmp_scan_dir, simple_fingerprints):
    engine = ScanEngine(simple_fingerprints, redact=True)
    orchestrator = ScanOrchestrator(
        transport=mock_transport_with_files, engine=engine, max_file_size_mb=50,
    )

    scan_dir = os.path.join(tmp_scan_dir, "scan_temp")
    os.makedirs(scan_dir, exist_ok=True)
    findings, _ = orchestrator.run(
        paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=scan_dir,
    )

    ssn_findings = [f for f in findings if f.pattern_name == "SSN"]
    assert len(ssn_findings) >= 1
    for f in ssn_findings:
        for match in f.matches:
            assert "*" in match
            assert match != "123-45-6789"
