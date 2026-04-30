import uuid
import pytest
from starlette.testclient import TestClient
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
def scan_id(db_engine):
    sid = uuid.uuid4()
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=sid, target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
        ))
        session.commit()
    return sid


def test_websocket_completed_scan(app, scan_id):
    client = TestClient(app)
    with client.websocket_connect(f"/api/scans/{scan_id}/progress") as ws:
        data = ws.receive_json()
        assert data["phase"] == "completed"


def test_websocket_scan_not_found(app):
    client = TestClient(app)
    fake_id = uuid.uuid4()
    with pytest.raises(Exception):
        with client.websocket_connect(f"/api/scans/{fake_id}/progress"):
            pass
