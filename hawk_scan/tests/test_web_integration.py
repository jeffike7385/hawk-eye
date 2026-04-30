"""Integration smoke test: end-to-end scan lifecycle through the API."""

import uuid
import pytest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def app(db_engine):
    return create_app(testing=True, db_engine=db_engine)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.anyio
async def test_full_scan_lifecycle(client, db_engine):
    # 1. Create a scan
    with patch("hawk_scan.web.routes.scans._send_scan_task"):
        resp = await client.post("/api/scans", json={
            "target_host": "WKS-TEST",
            "username": "DOMAIN\\admin",
            "password": "test",
        })
    assert resp.status_code == 201
    scan_id = resp.json()["id"]

    # 2. Simulate scan completion (worker would do this)
    with Session(db_engine) as session:
        scan = session.get(ScanRecord, uuid.UUID(scan_id))
        scan.status = "completed"
        scan.files_scanned = 10
        scan.files_skipped = 2
        session.add(FindingRecord(
            id=uuid.uuid4(), scan_id=uuid.UUID(scan_id),
            file_path="\\\\WKS-TEST\\C$\\data.xlsx",
            pattern_name="SSN", category="pii", severity="high",
            matches=["***-**-****"], match_count=5, sample_text="...",
        ))
        session.commit()

    # 3. Verify scan detail
    resp = await client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert len(data["findings"]) == 1

    # 4. List scans
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    # 5. Delete scan
    resp = await client.delete(f"/api/scans/{scan_id}")
    assert resp.status_code == 204

    # 6. Verify deletion
    resp = await client.get("/api/scans")
    assert resp.json()["total"] == 0
