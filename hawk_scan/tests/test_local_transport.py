import os
import tempfile
import pytest
from hawk_scan.remote.local_transport import LocalTransport


@pytest.fixture
def transport():
    return LocalTransport(debug=False)


@pytest.fixture
def sample_tree(tmp_path):
    (tmp_path / "doc.txt").write_text("hello world")
    (tmp_path / "data.csv").write_text("a,b,c")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")
    (tmp_path / "code.py").write_text("print('hi')")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "report.docx").write_bytes(b"fake")
    (tmp_path / "SkipMe").mkdir()
    (tmp_path / "SkipMe" / "secret.txt").write_text("hidden")
    return tmp_path


def test_name(transport):
    assert transport.name == "local"


def test_copies_files(transport):
    assert transport.copies_files is False


def test_is_available(transport):
    assert transport.is_available() is True


def test_enumerate_filters_extensions(transport, sample_tree):
    results = transport.enumerate([str(sample_tree)], [])
    extensions = {r.extension for r in results}
    assert ".txt" in extensions
    assert ".csv" in extensions
    assert ".png" in extensions
    assert ".docx" in extensions
    assert ".py" not in extensions


def test_enumerate_exclude_patterns(transport, sample_tree):
    subdir = sample_tree / "Excluded"
    subdir.mkdir()
    (subdir / "hidden.txt").write_text("hidden")
    results = transport.enumerate([str(sample_tree)], ["Excluded"])
    paths = [r.remote_path for r in results]
    assert not any("Excluded" in p for p in paths)
    assert len(results) > 0


def test_enumerate_exclude_glob(transport, sample_tree):
    results = transport.enumerate([str(sample_tree)], ["*.csv"])
    extensions = {r.extension for r in results}
    assert ".csv" not in extensions
    assert ".txt" in extensions


def test_enumerate_records_size(transport, sample_tree):
    results = transport.enumerate([str(sample_tree)], [])
    txt_files = [r for r in results if r.extension == ".txt"]
    assert len(txt_files) >= 1
    assert txt_files[0].size_bytes > 0


def test_retrieve_returns_original_path(transport, sample_tree):
    target = str(sample_tree / "doc.txt")
    result = transport.retrieve(target, tempfile.gettempdir())
    assert result == target
    assert os.path.exists(result)


def test_retrieve_missing_file_raises(transport):
    with pytest.raises(OSError, match="File not found"):
        transport.retrieve("/nonexistent/file.txt", tempfile.gettempdir())


def test_detect_volumes(transport):
    volumes = transport.detect_volumes()
    assert "C:\\" in volumes


def test_enumerate_progress_callback(transport, sample_tree):
    calls = []
    transport.enumerate([str(sample_tree)], [], progress_callback=lambda count, name: calls.append((count, name)))
    assert len(calls) > 0
    assert all(isinstance(c[0], int) and isinstance(c[1], str) for c in calls)
