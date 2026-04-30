import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
async def test_report_not_found(client):
    resp = await client.get(f"/api/scans/{uuid.uuid4()}/report")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_report_no_file(client, db_engine):
    scan_id = uuid.uuid4()
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=scan_id, target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            report_path=None,
        ))
        session.commit()
    resp = await client.get(f"/api/scans/{scan_id}/report")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_report_download(client, db_engine, tmp_path):
    report_file = tmp_path / "test.html"
    report_file.write_text("<html><body>Report</body></html>")

    scan_id = uuid.uuid4()
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=scan_id, target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            report_path=str(report_file),
        ))
        session.commit()
    resp = await client.get(f"/api/scans/{scan_id}/report")
    assert resp.status_code == 200
    assert "Report" in resp.text
