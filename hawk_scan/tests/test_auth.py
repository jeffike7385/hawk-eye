import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from hawk_scan.web.db import Base
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
async def test_me_unauthenticated(client):
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_login_redirects(client):
    resp = await client.get("/api/auth/login", follow_redirects=False)
    assert resp.status_code in (302, 307)


@pytest.mark.anyio
async def test_logout(client):
    resp = await client.post("/api/auth/logout")
    assert resp.status_code == 200
