import os
import pytest
from hawk_scan.scanner.readers import (
    read_text, read_pdf, read_docx, read_xlsx, read_pptx,
    read_image_ocr, read_file,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_read_text():
    content = read_text(os.path.join(FIXTURES, "sample.txt"))
    assert "123-45-6789" in content
    assert "test@example.com" in content


def test_read_text_nonexistent_raises():
    with pytest.raises(FileNotFoundError):
        read_text("/nonexistent/file.txt")


def test_read_pdf():
    content = read_pdf(os.path.join(FIXTURES, "sample.pdf"))
    assert "678-90-1234" in content or "finance@company.com" in content


def test_read_docx():
    content = read_docx(os.path.join(FIXTURES, "sample.docx"))
    assert "234-56-7890" in content
    assert "hr@company.com" in content


def test_read_xlsx():
    content = read_xlsx(os.path.join(FIXTURES, "sample.xlsx"))
    assert "345-67-8901" in content
    assert "Jane Doe" in content


def test_read_pptx():
    content = read_pptx(os.path.join(FIXTURES, "sample.pptx"))
    assert "456-78-9012" in content
    assert "user@corp.com" in content


def test_read_image_ocr():
    content = read_image_ocr(os.path.join(FIXTURES, "sample.png"))
    # OCR output may vary; just check it returned a non-empty string
    assert isinstance(content, str)
    assert len(content.strip()) > 0


def test_read_file_dispatches_text(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")
    content = read_file(str(f))
    assert content == "hello world"


def test_read_file_dispatches_pdf():
    content = read_file(os.path.join(FIXTURES, "sample.pdf"))
    assert len(content) > 0


def test_read_file_dispatches_docx():
    content = read_file(os.path.join(FIXTURES, "sample.docx"))
    assert "234-56-7890" in content


def test_read_file_dispatches_xlsx():
    content = read_file(os.path.join(FIXTURES, "sample.xlsx"))
    assert "345-67-8901" in content


def test_read_file_dispatches_pptx():
    content = read_file(os.path.join(FIXTURES, "sample.pptx"))
    assert "456-78-9012" in content


def test_read_file_unsupported_extension(tmp_path):
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x00\x01\x02")
    content = read_file(str(f))
    assert isinstance(content, str)
