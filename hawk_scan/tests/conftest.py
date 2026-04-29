# hawk_scan/tests/conftest.py
import pytest
import tempfile
import os


@pytest.fixture
def tmp_scan_dir():
    with tempfile.TemporaryDirectory(prefix="hawk_scan_test_") as d:
        yield d


@pytest.fixture
def sample_text_file(tmp_scan_dir):
    path = os.path.join(tmp_scan_dir, "sample.txt")
    with open(path, "w") as f:
        f.write("Contact John at john@example.com or SSN 123-45-6789\n")
    return path


@pytest.fixture
def simple_fingerprints():
    return {
        "Email": {
            "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
            "severity": "low",
            "category": "pii",
        },
        "SSN": {
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "severity": "high",
            "category": "pii",
        },
    }
