import pytest
from pydantic import ValidationError
from hawk_scan.web.schemas import ScanCreate, ScanResponse, ScanListParams


def test_scan_create_valid():
    sc = ScanCreate(
        target_host="WKS-01",
        username="DOMAIN\\admin",
        password="secret",
    )
    assert sc.target_host == "WKS-01"
    assert sc.paths == ["C:\\Users"]
    assert sc.max_file_size_mb == 50
    assert sc.redact is True


def test_scan_create_rejects_invalid_hostname():
    with pytest.raises(ValidationError):
        ScanCreate(
            target_host="host; rm -rf /",
            username="admin",
            password="pass",
        )


def test_scan_create_custom_paths():
    sc = ScanCreate(
        target_host="WKS-01",
        username="admin",
        password="pass",
        paths=["D:\\Data", "E:\\Shared"],
    )
    assert sc.paths == ["D:\\Data", "E:\\Shared"]


def test_scan_create_transport_validation():
    sc = ScanCreate(
        target_host="WKS-01",
        username="admin",
        password="pass",
        transport="smb",
    )
    assert sc.transport == "smb"
    with pytest.raises(ValidationError):
        ScanCreate(
            target_host="WKS-01",
            username="admin",
            password="pass",
            transport="ftp",
        )


def test_scan_list_params_defaults():
    params = ScanListParams()
    assert params.page == 1
    assert params.per_page == 20
    assert params.status is None
    assert params.target is None
