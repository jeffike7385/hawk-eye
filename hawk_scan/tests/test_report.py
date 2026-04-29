import os
import json
import pytest
from hawk_scan.models import Finding, SkippedFile, ScanResult, ScanReport
from hawk_scan.report.generator import generate_html_report, generate_json_report


@pytest.fixture
def sample_result():
    findings = [
        Finding(file_path="C:\\Users\\jsmith\\data.txt", pattern_name="SSN", category="pii",
                severity="high", matches=["123-45-6789"], match_count=1,
                sample_text="SSN: 123-45-6789", file_owner="DOMAIN\\jsmith",
                file_modified="2026-01-15 10:30:00"),
        Finding(file_path="C:\\Users\\jsmith\\contacts.csv", pattern_name="Email", category="pii",
                severity="low", matches=["jane@example.com", "bob@example.com"], match_count=2,
                sample_text="jane@example.com,bob@example.com"),
    ]
    skipped = [SkippedFile(file_path="C:\\Users\\jsmith\\locked.docx", reason="File is locked by another process")]
    return ScanResult(
        target_host="WORKSTATION-01", transport_method="winrm", scan_user="DOMAIN\\admin",
        start_time="2026-04-29 10:00:00", end_time="2026-04-29 10:05:00", duration_seconds=300.0,
        total_files_scanned=150, total_files_skipped=1, findings=findings, skipped_files=skipped,
    )


def test_generate_html_report(sample_result, tmp_scan_dir):
    output_path = os.path.join(tmp_scan_dir, "report.html")
    generate_html_report(ScanReport(result=sample_result), output_path)
    assert os.path.exists(output_path)
    with open(output_path, "r") as f:
        html = f.read()
    assert "WORKSTATION-01" in html
    assert "SSN" in html
    assert "123-45-6789" in html
    assert "locked.docx" in html
    assert "<html" in html.lower()


def test_generate_html_report_contains_severity_summary(sample_result, tmp_scan_dir):
    output_path = os.path.join(tmp_scan_dir, "report.html")
    generate_html_report(ScanReport(result=sample_result), output_path)
    with open(output_path, "r") as f:
        html = f.read()
    assert "high" in html.lower()
    assert "low" in html.lower()


def test_generate_json_report(sample_result, tmp_scan_dir):
    output_path = os.path.join(tmp_scan_dir, "report.json")
    generate_json_report(ScanReport(result=sample_result), output_path)
    assert os.path.exists(output_path)
    with open(output_path, "r") as f:
        data = json.load(f)
    assert data["target_host"] == "WORKSTATION-01"
    assert len(data["findings"]) == 2
    assert len(data["skipped_files"]) == 1


def test_generate_json_report_structure(sample_result, tmp_scan_dir):
    output_path = os.path.join(tmp_scan_dir, "report.json")
    generate_json_report(ScanReport(result=sample_result), output_path)
    with open(output_path, "r") as f:
        data = json.load(f)
    assert "severity_summary" in data
    assert "category_summary" in data
    assert data["severity_summary"]["high"] == 1
    assert data["category_summary"]["pii"] == 2


def test_html_report_is_self_contained(sample_result, tmp_scan_dir):
    output_path = os.path.join(tmp_scan_dir, "report.html")
    generate_html_report(ScanReport(result=sample_result), output_path)
    with open(output_path, "r") as f:
        html = f.read()
    assert "<style" in html


def test_generate_html_empty_findings(tmp_scan_dir):
    result = ScanResult(
        target_host="WS-01", transport_method="smb", scan_user="admin",
        start_time="", end_time="", duration_seconds=0,
        total_files_scanned=100, total_files_skipped=0,
        findings=[], skipped_files=[],
    )
    output_path = os.path.join(tmp_scan_dir, "report.html")
    generate_html_report(ScanReport(result=result), output_path)
    with open(output_path, "r") as f:
        html = f.read()
    assert "0" in html or "No findings" in html
