import os
import pytest
from unittest.mock import MagicMock
from hawk_scan.scanner.orchestrator import ScanOrchestrator
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.models import FileMetadata


@pytest.fixture
def mock_transport():
    transport = MagicMock()
    transport.name = "smb"
    return transport


@pytest.fixture
def engine(simple_fingerprints):
    return ScanEngine(simple_fingerprints, redact=False)


@pytest.fixture
def orchestrator(mock_transport, engine):
    return ScanOrchestrator(transport=mock_transport, engine=engine, max_file_size_mb=50, debug=False)


def test_orchestrator_scans_text_file(orchestrator, mock_transport, tmp_scan_dir):
    meta = FileMetadata(remote_path="C:\\Users\\jsmith\\data.txt", size_bytes=100, extension=".txt")
    mock_transport.enumerate.return_value = [meta]
    local_file = os.path.join(tmp_scan_dir, "data.txt")
    with open(local_file, "w") as f:
        f.write("SSN: 123-45-6789\n")
    mock_transport.retrieve.return_value = local_file
    findings, skipped = orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert len(findings) == 1
    assert findings[0].pattern_name == "SSN"
    assert findings[0].file_path == "C:\\Users\\jsmith\\data.txt"
    assert len(skipped) == 0


def test_orchestrator_skips_large_files(orchestrator, mock_transport, tmp_scan_dir):
    meta = FileMetadata(remote_path="C:\\Users\\jsmith\\huge.pdf", size_bytes=60_000_000, extension=".pdf")
    mock_transport.enumerate.return_value = [meta]
    findings, skipped = orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert len(findings) == 0
    assert len(skipped) == 1
    assert "size" in skipped[0].reason.lower()


def test_orchestrator_handles_retrieve_failure(orchestrator, mock_transport, tmp_scan_dir):
    meta = FileMetadata(remote_path="C:\\Users\\jsmith\\locked.docx", size_bytes=1024, extension=".docx")
    mock_transport.enumerate.return_value = [meta]
    mock_transport.retrieve.return_value = None
    findings, skipped = orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert len(findings) == 0
    assert len(skipped) == 1


def test_orchestrator_handles_reader_error(orchestrator, mock_transport, tmp_scan_dir):
    meta = FileMetadata(remote_path="C:\\Users\\jsmith\\corrupt.pdf", size_bytes=1024, extension=".pdf")
    mock_transport.enumerate.return_value = [meta]
    local_file = os.path.join(tmp_scan_dir, "corrupt.pdf")
    with open(local_file, "wb") as f:
        f.write(b"not a real pdf")
    mock_transport.retrieve.return_value = local_file
    findings, skipped = orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert len(skipped) <= 1


def test_orchestrator_cleans_temp_files(orchestrator, mock_transport, tmp_scan_dir):
    meta = FileMetadata(remote_path="C:\\Users\\jsmith\\data.txt", size_bytes=100, extension=".txt")
    mock_transport.enumerate.return_value = [meta]
    local_file = os.path.join(tmp_scan_dir, "data.txt")
    with open(local_file, "w") as f:
        f.write("nothing")
    mock_transport.retrieve.return_value = local_file
    orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert not os.path.exists(local_file)


def test_orchestrator_multiple_findings(orchestrator, mock_transport, tmp_scan_dir):
    files = [FileMetadata(remote_path=f"C:\\Users\\jsmith\\file{i}.txt", size_bytes=100, extension=".txt") for i in range(3)]
    mock_transport.enumerate.return_value = files

    def make_file(remote_path, local_dir):
        name = os.path.basename(remote_path)
        path = os.path.join(local_dir, name)
        with open(path, "w") as f:
            f.write("john@example.com\n")
        return path

    mock_transport.retrieve.side_effect = make_file
    findings, skipped = orchestrator.run(paths=["C:\\Users\\jsmith"], exclude_patterns=[], temp_dir=tmp_scan_dir)
    assert len(findings) == 3
    assert all(f.pattern_name == "Email" for f in findings)
