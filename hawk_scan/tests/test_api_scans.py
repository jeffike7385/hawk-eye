import uuid
from unittest.mock import MagicMock, patch

import pytest
import httpx
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.web.app import create_app

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Enable foreign-key enforcement in SQLite.
    @event.listens_for(eng, "connect")
    def _set_fk(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return eng


@pytest.fixture
def app(engine):
    application = create_app(testing=True, db_engine=engine)
    yield application
    engine.dispose()


@pytest.fixture
def client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def db_session(app):
    """Get a DB session using the same engine as the app."""
    session_factory = app.state.session_factory
    session = session_factory()
    yield session
    session.close()


def _make_scan(
    target_host="WKS-01",
    status="completed",
    scan_user="DOMAIN\\admin",
    entra_user="jeff@example.com",
) -> ScanRecord:
    return ScanRecord(
        id=uuid.uuid4(),
        target_host=target_host,
        scan_user=scan_user,
        entra_user=entra_user,
        status=status,
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=True,
    )


def _make_finding(scan_id: uuid.UUID, severity="high") -> FindingRecord:
    return FindingRecord(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="\\\\WKS-01\\C$\\file.txt",
        pattern_name="SSN",
        category="pii",
        severity=severity,
        matches=["123-45-6789"],
        match_count=1,
        sample_text="SSN: 123-45-...",
    )


async def test_list_scans_empty(client):
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1
    assert data["per_page"] == 20


async def test_list_scans_with_data(client, db_session):
    scan1 = _make_scan(target_host="WKS-01")
    scan2 = _make_scan(target_host="WKS-02")
    db_session.add_all([scan1, scan2])
    db_session.commit()

    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    hosts = {item["target_host"] for item in data["items"]}
    assert hosts == {"WKS-01", "WKS-02"}


async def test_get_scan_not_found(client):
    random_id = str(uuid.uuid4())
    resp = await client.get(f"/api/scans/{random_id}")
    assert resp.status_code == 404


async def test_get_scan_detail(client, db_session):
    scan = _make_scan()
    finding = _make_finding(scan.id, severity="high")
    skipped = SkippedFileRecord(
        id=uuid.uuid4(),
        scan_id=scan.id,
        file_path="\\\\WKS-01\\C$\\big.zip",
        reason="Too large",
    )
    db_session.add(scan)
    db_session.add(finding)
    db_session.add(skipped)
    db_session.commit()

    resp = await client.get(f"/api/scans/{scan.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == str(scan.id)
    assert data["target_host"] == "WKS-01"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "high"
    assert len(data["skipped_files"]) == 1
    assert data["skipped_files"][0]["reason"] == "Too large"


async def test_delete_scan(client, db_session):
    scan = _make_scan()
    db_session.add(scan)
    db_session.commit()

    resp = await client.delete(f"/api/scans/{scan.id}")
    assert resp.status_code == 204

    resp2 = await client.get(f"/api/scans/{scan.id}")
    assert resp2.status_code == 404


async def test_create_scan_queues_task(client):
    mock_task = MagicMock()
    mock_task.delay = MagicMock()

    with patch("hawk_scan.web.routes.scans.run_scan_task", mock_task):
        resp = await client.post(
            "/api/scans",
            json={
                "target_host": "WKS-01",
                "username": "DOMAIN\\admin",
                "password": "secret123",
            },
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "queued"
    assert data["target_host"] == "WKS-01"
    assert data["scan_user"] == "DOMAIN\\admin"
    assert data["entra_user"] == "anonymous"
    assert "id" in data
    mock_task.delay.assert_called_once_with(data["id"])
