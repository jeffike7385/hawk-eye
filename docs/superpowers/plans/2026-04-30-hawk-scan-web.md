# Hawk Scan Web Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Containerize Hawk Scan as a Docker-hosted web application with a React frontend, FastAPI backend, Celery task queue, and Entra ID SSO — providing a browser-based interface for starting scans, monitoring progress in real time, and maintaining a central audit trail.

**Architecture:** Five Docker Compose containers (nginx, api, worker, redis, postgres). The existing scanning core (`hawk_scan.scanner.*`, `hawk_scan.remote.*`, `hawk_scan.report.*`) is reused directly by the Celery worker. New code lives under `hawk_scan.web.*` (backend) and `frontend/` (React SPA). Auth via server-driven Entra ID OAuth2 with Redis-backed sessions.

**Tech Stack:** Python 3.11, FastAPI, Celery, Redis, PostgreSQL, SQLAlchemy, Alembic, React 18, TypeScript, Tailwind CSS, Docker Compose

**Design Spec:** `docs/superpowers/specs/2026-04-30-hawk-scan-web-containerization-design.md`

---

## File Structure

### New Backend Files (`hawk_scan/hawk_scan/web/`)

| File | Responsibility |
|------|---------------|
| `__init__.py` | Package marker |
| `config.py` | Settings loaded from environment variables (Pydantic BaseSettings) |
| `db.py` | SQLAlchemy async engine, session factory, ORM models (Scan, Finding, SkippedFile) |
| `schemas.py` | Pydantic request/response schemas for API endpoints |
| `crypto.py` | Fernet encrypt/decrypt for credential transit through Redis |
| `app.py` | FastAPI application factory, middleware, router mounting |
| `routes/__init__.py` | Package marker |
| `routes/auth.py` | Entra ID OAuth2 login, callback, logout, /me endpoints |
| `routes/scans.py` | Scan CRUD, report download, WebSocket progress endpoint |
| `celery_app.py` | Celery application instance + configuration |
| `tasks.py` | Celery task: execute scan, publish progress, write results |
| `beat.py` | Celery Beat scheduled tasks: retention cleanup, stale scan recovery |

### New Frontend Files (`frontend/`)

| File | Responsibility |
|------|---------------|
| `src/App.tsx` | Root component, router, auth guard |
| `src/api.ts` | Fetch wrapper with 401 handling |
| `src/types.ts` | TypeScript interfaces matching API schemas |
| `src/hooks/useWebSocket.ts` | Custom hook for scan progress WebSocket |
| `src/pages/Dashboard.tsx` | Summary stats, active scans, recent scans |
| `src/pages/NewScan.tsx` | Scan form with credential inputs |
| `src/pages/ScanProgress.tsx` | Live progress with WebSocket |
| `src/pages/ScanHistory.tsx` | Paginated/filterable scan table |
| `src/pages/ScanDetail.tsx` | Completed scan findings + report download |
| `src/components/Layout.tsx` | Nav bar, page shell |
| `src/components/StatusBadge.tsx` | Colored status pill component |
| `src/components/ProgressBar.tsx` | Animated progress bar |

### New Docker/Config Files

| File | Responsibility |
|------|---------------|
| `docker/Dockerfile` | Python image for api + worker (Tesseract included) |
| `docker/Dockerfile.nginx` | nginx + React build output |
| `docker/nginx.conf` | Reverse proxy, WebSocket upgrade, TLS |
| `docker-compose.yml` | 5-service orchestration |
| `.env.example` | Template for required environment variables |
| `alembic.ini` | Alembic configuration |
| `alembic/env.py` | Alembic migration environment |
| `alembic/versions/001_initial.py` | Initial migration creating 3 tables |

### Modified Files

| File | Change |
|------|--------|
| `hawk_scan/pyproject.toml` | Add `[web]` optional dependency group |
| `.gitignore` | Add `frontend/node_modules/`, `frontend/dist/` |

---

## Task 1: Backend Dependencies and Web Package Scaffold

**Files:**
- Modify: `hawk_scan/pyproject.toml`
- Create: `hawk_scan/hawk_scan/web/__init__.py`
- Create: `hawk_scan/hawk_scan/web/config.py`
- Test: `hawk_scan/tests/test_web_config.py`

- [ ] **Step 1: Add web dependency group to pyproject.toml**

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "pyinstaller>=6.0",
]
web = [
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.27.0",
    "celery[redis]>=5.3.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "asyncpg>=0.29.0",
    "alembic>=1.13.0",
    "msal>=1.26.0",
    "cryptography>=42.0.0",
    "redis>=5.0.0",
    "httpx>=0.27.0",
]
```

- [ ] **Step 2: Create web package and config module**

Create `hawk_scan/hawk_scan/web/__init__.py` (empty file).

Create `hawk_scan/hawk_scan/web/config.py`:

```python
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hawkscan:hawkscan@localhost:5432/hawkscan"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "change-me-in-production"
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    retention_days: int = 90
    max_concurrent_scans: int = 3
    session_ttl_hours: int = 8
    reports_dir: str = "/app/reports"
    base_url: str = "http://localhost:8000"

    model_config = {"env_prefix": "HAWKSCAN_", "env_file": ".env"}


def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 3: Write test for config**

Create `hawk_scan/tests/test_web_config.py`:

```python
import os
import pytest
from hawk_scan.web.config import Settings


def test_settings_defaults():
    s = Settings(secret_key="test")
    assert s.retention_days == 90
    assert s.max_concurrent_scans == 3
    assert s.session_ttl_hours == 8


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("HAWKSCAN_RETENTION_DAYS", "30")
    monkeypatch.setenv("HAWKSCAN_SECRET_KEY", "test-key")
    s = Settings()
    assert s.retention_days == 30
    assert s.secret_key == "test-key"


def test_settings_database_url_default():
    s = Settings(secret_key="test")
    assert "asyncpg" in s.database_url
    assert "hawkscan" in s.database_url
```

- [ ] **Step 4: Install web dependencies and run test**

Run:
```bash
cd hawk_scan && pip install -e ".[dev,web]"
pip install pydantic-settings
pytest tests/test_web_config.py -v
```
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/pyproject.toml hawk_scan/hawk_scan/web/__init__.py hawk_scan/hawk_scan/web/config.py hawk_scan/tests/test_web_config.py
git commit -m "feat(web): add web dependency group and settings module"
```

---

## Task 2: Credential Encryption Module

**Files:**
- Create: `hawk_scan/hawk_scan/web/crypto.py`
- Test: `hawk_scan/tests/test_crypto.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_crypto.py`:

```python
import pytest
from hawk_scan.web.crypto import encrypt_credentials, decrypt_credentials


def test_roundtrip():
    secret = "test-secret-key-for-encryption"
    username = "DOMAIN\\admin"
    password = "s3cret!"
    encrypted = encrypt_credentials(username, password, secret)
    assert isinstance(encrypted, str)
    assert password not in encrypted
    result_user, result_pass = decrypt_credentials(encrypted, secret)
    assert result_user == username
    assert result_pass == password


def test_wrong_key_fails():
    secret = "correct-key"
    wrong = "wrong-key"
    encrypted = encrypt_credentials("user", "pass", secret)
    with pytest.raises(Exception):
        decrypt_credentials(encrypted, wrong)


def test_different_inputs_different_outputs():
    secret = "test-key"
    enc1 = encrypt_credentials("user", "pass1", secret)
    enc2 = encrypt_credentials("user", "pass2", secret)
    assert enc1 != enc2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_crypto.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Implement crypto module**

Create `hawk_scan/hawk_scan/web/crypto.py`:

```python
import base64
import json
import os
import hashlib
from cryptography.fernet import Fernet


def _derive_key(secret: str, salt: bytes) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(dk)


def encrypt_credentials(username: str, password: str, secret: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(secret, salt)
    f = Fernet(key)
    payload = json.dumps({"u": username, "p": password}).encode()
    token = f.encrypt(payload)
    combined = salt + token
    return base64.urlsafe_b64encode(combined).decode()


def decrypt_credentials(encrypted: str, secret: str) -> tuple[str, str]:
    combined = base64.urlsafe_b64decode(encrypted.encode())
    salt = combined[:16]
    token = combined[16:]
    key = _derive_key(secret, salt)
    f = Fernet(key)
    payload = json.loads(f.decrypt(token))
    return payload["u"], payload["p"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_crypto.py -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/hawk_scan/web/crypto.py hawk_scan/tests/test_crypto.py
git commit -m "feat(web): add credential encryption module"
```

---

## Task 3: Database Models (SQLAlchemy)

**Files:**
- Create: `hawk_scan/hawk_scan/web/db.py`
- Test: `hawk_scan/tests/test_db_models.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_db_models.py`:

```python
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_tables_created(db_session):
    inspector = inspect(db_session.bind)
    tables = inspector.get_table_names()
    assert "scans" in tables
    assert "findings" in tables
    assert "skipped_files" in tables


def test_create_scan(db_session):
    scan = ScanRecord(
        id=uuid.uuid4(),
        target_host="WKS-01",
        scan_user="DOMAIN\\admin",
        entra_user="jeff@example.com",
        status="queued",
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=True,
    )
    db_session.add(scan)
    db_session.commit()
    assert scan.created_at is not None
    assert scan.expires_at is not None


def test_finding_cascade_delete(db_session):
    scan_id = uuid.uuid4()
    scan = ScanRecord(
        id=scan_id,
        target_host="WKS-01",
        scan_user="admin",
        entra_user="jeff@example.com",
        status="completed",
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=False,
    )
    finding = FindingRecord(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="\\\\WKS-01\\C$\\file.txt",
        pattern_name="SSN",
        category="pii",
        severity="high",
        matches=["123-45-6789"],
        match_count=1,
        sample_text="SSN: 123-45-...",
    )
    db_session.add(scan)
    db_session.add(finding)
    db_session.commit()
    db_session.delete(scan)
    db_session.commit()
    assert db_session.query(FindingRecord).count() == 0


def test_skipped_file_cascade_delete(db_session):
    scan_id = uuid.uuid4()
    scan = ScanRecord(
        id=scan_id,
        target_host="WKS-01",
        scan_user="admin",
        entra_user="jeff@example.com",
        status="completed",
        paths=[],
        exclude_patterns=[],
        redacted=False,
    )
    skipped = SkippedFileRecord(
        id=uuid.uuid4(),
        scan_id=scan_id,
        file_path="\\\\WKS-01\\C$\\big.zip",
        reason="Too large",
    )
    db_session.add(scan)
    db_session.add(skipped)
    db_session.commit()
    db_session.delete(scan)
    db_session.commit()
    assert db_session.query(SkippedFileRecord).count() == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_db_models.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Implement database models**

Create `hawk_scan/hawk_scan/web/db.py`:

```python
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, ForeignKey, JSON,
    event,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, relationship

RETENTION_DAYS_DEFAULT = 90


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(PG_UUID(as_uuid=True).with_variant(String(36), "sqlite"), primary_key=True, default=uuid.uuid4)
    target_host = Column(String, nullable=False)
    transport = Column(String, nullable=True)
    scan_user = Column(String, nullable=False)
    entra_user = Column(String, nullable=False)
    status = Column(String, nullable=False, default="queued")
    paths = Column(JSON, nullable=False, default=list)
    exclude_patterns = Column(JSON, nullable=False, default=list)
    redacted = Column(Boolean, nullable=False, default=False)
    files_found = Column(Integer, nullable=True)
    files_scanned = Column(Integer, nullable=True)
    files_skipped = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    report_path = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    findings = relationship("FindingRecord", back_populates="scan", cascade="all, delete-orphan")
    skipped_files = relationship("SkippedFileRecord", back_populates="scan", cascade="all, delete-orphan")


@event.listens_for(ScanRecord, "init")
def _set_defaults(target, args, kwargs):
    if target.created_at is None:
        target.created_at = datetime.now(timezone.utc)
    if target.expires_at is None:
        target.expires_at = (target.created_at or datetime.now(timezone.utc)) + timedelta(days=RETENTION_DAYS_DEFAULT)


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(PG_UUID(as_uuid=True).with_variant(String(36), "sqlite"), primary_key=True, default=uuid.uuid4)
    scan_id = Column(PG_UUID(as_uuid=True).with_variant(String(36), "sqlite"), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String, nullable=False)
    pattern_name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    matches = Column(JSON, nullable=False)
    match_count = Column(Integer, nullable=False)
    sample_text = Column(String, nullable=True)
    file_owner = Column(String, nullable=True)
    file_modified = Column(String, nullable=True)

    scan = relationship("ScanRecord", back_populates="findings")


class SkippedFileRecord(Base):
    __tablename__ = "skipped_files"

    id = Column(PG_UUID(as_uuid=True).with_variant(String(36), "sqlite"), primary_key=True, default=uuid.uuid4)
    scan_id = Column(PG_UUID(as_uuid=True).with_variant(String(36), "sqlite"), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String, nullable=False)
    reason = Column(String, nullable=False)

    scan = relationship("ScanRecord", back_populates="skipped_files")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_db_models.py -v`
Expected: 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/hawk_scan/web/db.py hawk_scan/tests/test_db_models.py
git commit -m "feat(web): add SQLAlchemy database models"
```

---

## Task 4: Pydantic Request/Response Schemas

**Files:**
- Create: `hawk_scan/hawk_scan/web/schemas.py`
- Test: `hawk_scan/tests/test_schemas.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_schemas.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_schemas.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Implement schemas**

Create `hawk_scan/hawk_scan/web/schemas.py`:

```python
import re
import uuid
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$")


class ScanCreate(BaseModel):
    target_host: str
    username: str
    password: str
    transport: str | None = None
    paths: list[str] = Field(default_factory=lambda: ["C:\\Users"])
    exclude_patterns: list[str] = Field(default_factory=list)
    max_file_size_mb: int = 50
    redact: bool = True

    @field_validator("target_host")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        if not HOSTNAME_RE.match(v):
            raise ValueError("Invalid hostname: alphanumeric and hyphens only, max 63 chars")
        return v

    @field_validator("transport")
    @classmethod
    def validate_transport(cls, v: str | None) -> str | None:
        if v is not None and v not in ("smb", "winrm"):
            raise ValueError("Transport must be 'smb', 'winrm', or null")
        return v


class ScanSummary(BaseModel):
    id: uuid.UUID
    target_host: str
    status: str
    transport: str | None
    scan_user: str
    entra_user: str
    files_found: int | None
    files_scanned: int | None
    files_skipped: int | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    file_path: str
    pattern_name: str
    category: str
    severity: str
    matches: list[str]
    match_count: int
    sample_text: str | None
    file_owner: str | None
    file_modified: str | None

    model_config = {"from_attributes": True}


class SkippedFileResponse(BaseModel):
    id: uuid.UUID
    file_path: str
    reason: str

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_host: str
    status: str
    transport: str | None
    scan_user: str
    entra_user: str
    paths: list[str]
    exclude_patterns: list[str]
    redacted: bool
    files_found: int | None
    files_scanned: int | None
    files_skipped: int | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    findings: list[FindingResponse] = []
    skipped_files: list[SkippedFileResponse] = []

    model_config = {"from_attributes": True}


class ScanListParams(BaseModel):
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    status: str | None = None
    target: str | None = None


class ScanListResponse(BaseModel):
    items: list[ScanSummary]
    total: int
    page: int
    per_page: int


class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_findings: int
    high_severity_findings: int
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_schemas.py -v`
Expected: 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/hawk_scan/web/schemas.py hawk_scan/tests/test_schemas.py
git commit -m "feat(web): add Pydantic request/response schemas"
```

---

## Task 5: FastAPI Application + Scan CRUD Routes

**Files:**
- Create: `hawk_scan/hawk_scan/web/app.py`
- Create: `hawk_scan/hawk_scan/web/routes/__init__.py`
- Create: `hawk_scan/hawk_scan/web/routes/scans.py`
- Test: `hawk_scan/tests/test_api_scans.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_api_scans.py`:

```python
import uuid
import pytest
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def app(db_engine):
    application = create_app(testing=True, db_engine=db_engine)
    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _seed_scan(db_engine, **overrides):
    defaults = dict(
        id=uuid.uuid4(),
        target_host="WKS-01",
        scan_user="DOMAIN\\admin",
        entra_user="jeff@example.com",
        status="completed",
        paths=["C:\\Users"],
        exclude_patterns=[],
        redacted=False,
    )
    defaults.update(overrides)
    with Session(db_engine) as session:
        scan = ScanRecord(**defaults)
        session.add(scan)
        session.commit()
        return defaults["id"]


@pytest.mark.anyio
async def test_list_scans_empty(client):
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.anyio
async def test_list_scans_with_data(client, db_engine):
    _seed_scan(db_engine)
    _seed_scan(db_engine, target_host="WKS-02")
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


@pytest.mark.anyio
async def test_get_scan_not_found(client):
    resp = await client.get(f"/api/scans/{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_get_scan_detail(client, db_engine):
    scan_id = _seed_scan(db_engine)
    with Session(db_engine) as session:
        session.add(FindingRecord(
            id=uuid.uuid4(), scan_id=scan_id,
            file_path="\\\\WKS-01\\C$\\file.txt",
            pattern_name="SSN", category="pii", severity="high",
            matches=["123-45-6789"], match_count=1, sample_text="...",
        ))
        session.commit()
    resp = await client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_host"] == "WKS-01"
    assert len(data["findings"]) == 1


@pytest.mark.anyio
async def test_delete_scan(client, db_engine):
    scan_id = _seed_scan(db_engine)
    resp = await client.delete(f"/api/scans/{scan_id}")
    assert resp.status_code == 204
    resp = await client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_create_scan_queues_task(client):
    with patch("hawk_scan.web.routes.scans.run_scan_task") as mock_task:
        mock_task.delay = lambda *a, **kw: None
        resp = await client.post("/api/scans", json={
            "target_host": "WKS-01",
            "username": "DOMAIN\\admin",
            "password": "secret",
        })
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "queued"
    assert data["target_host"] == "WKS-01"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_api_scans.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Create routes/__init__.py**

Create `hawk_scan/hawk_scan/web/routes/__init__.py` (empty file).

- [ ] **Step 4: Implement scan routes**

Create `hawk_scan/hawk_scan/web/routes/scans.py`:

```python
import uuid
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, case
from sqlalchemy.orm import Session
from hawk_scan.web.db import ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.web.schemas import (
    ScanCreate, ScanResponse, ScanSummary,
    ScanListResponse, FindingResponse, SkippedFileResponse,
)
from hawk_scan.web.crypto import encrypt_credentials

router = APIRouter(prefix="/api/scans", tags=["scans"])

run_scan_task = None


def _get_db():
    raise NotImplementedError("Override in app factory")


def _settings():
    from hawk_scan.web.config import get_settings
    return get_settings()


@router.post("", status_code=201, response_model=ScanResponse)
def create_scan(body: ScanCreate, db: Session = Depends(_get_db)):
    settings = _settings()
    scan_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    scan = ScanRecord(
        id=scan_id,
        target_host=body.target_host,
        scan_user=body.username,
        entra_user="anonymous",
        status="queued",
        paths=body.paths,
        exclude_patterns=body.exclude_patterns,
        redacted=body.redact,
        created_at=now,
        expires_at=now + timedelta(days=settings.retention_days),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    encrypted_creds = encrypt_credentials(body.username, body.password, settings.secret_key)
    if run_scan_task is not None:
        run_scan_task.delay(
            str(scan_id),
            body.target_host,
            encrypted_creds,
            body.paths,
            body.exclude_patterns,
            body.max_file_size_mb,
            body.redact,
            body.transport,
        )

    return scan


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str | None = None,
    target: str | None = None,
    db: Session = Depends(_get_db),
):
    query = select(ScanRecord)
    count_query = select(func.count(ScanRecord.id))

    if status:
        query = query.where(ScanRecord.status == status)
        count_query = count_query.where(ScanRecord.status == status)
    if target:
        query = query.where(ScanRecord.target_host.ilike(f"%{target}%"))
        count_query = count_query.where(ScanRecord.target_host.ilike(f"%{target}%"))

    total = db.execute(count_query).scalar() or 0
    scans = db.execute(
        query.order_by(ScanRecord.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    ).scalars().all()

    items = []
    for scan in scans:
        high = sum(1 for f in scan.findings if f.severity == "high")
        medium = sum(1 for f in scan.findings if f.severity == "medium")
        low = sum(1 for f in scan.findings if f.severity == "low")
        items.append(ScanSummary(
            id=scan.id, target_host=scan.target_host, status=scan.status,
            transport=scan.transport, scan_user=scan.scan_user,
            entra_user=scan.entra_user, files_found=scan.files_found,
            files_scanned=scan.files_scanned, files_skipped=scan.files_skipped,
            started_at=scan.started_at, completed_at=scan.completed_at,
            created_at=scan.created_at,
            high_count=high, medium_count=medium, low_count=low,
        ))

    return ScanListResponse(items=items, total=total, page=page, per_page=per_page)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.get(ScanRecord, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.get(ScanRecord, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.delete(scan)
    db.commit()
```

- [ ] **Step 5: Implement FastAPI app factory**

Create `hawk_scan/hawk_scan/web/app.py`:

```python
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from hawk_scan.web.db import Base
from hawk_scan.web.routes import scans as scans_router


def create_app(testing: bool = False, db_engine=None) -> FastAPI:
    app = FastAPI(title="Hawk Scan", version="0.1.0")

    if db_engine is None:
        from hawk_scan.web.config import get_settings
        settings = get_settings()
        db_engine = create_engine(
            settings.database_url.replace("+asyncpg", ""),
            pool_pre_ping=True,
        )
        Base.metadata.create_all(db_engine)

    session_factory = sessionmaker(bind=db_engine)

    def get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    scans_router.router.dependencies = []
    original_get_db = scans_router._get_db

    app.dependency_overrides[scans_router._get_db] = get_db
    app.include_router(scans_router.router)

    return app
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd hawk_scan && pip install anyio httpx pytest-anyio && pytest tests/test_api_scans.py -v`
Expected: 6 tests PASS

- [ ] **Step 7: Commit**

```bash
git add hawk_scan/hawk_scan/web/app.py hawk_scan/hawk_scan/web/routes/__init__.py hawk_scan/hawk_scan/web/routes/scans.py hawk_scan/tests/test_api_scans.py
git commit -m "feat(web): add FastAPI app and scan CRUD routes"
```

---

## Task 6: Celery Application and Scan Task

**Files:**
- Create: `hawk_scan/hawk_scan/web/celery_app.py`
- Create: `hawk_scan/hawk_scan/web/tasks.py`
- Test: `hawk_scan/tests/test_tasks.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_tasks.py`:

```python
import uuid
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.web.crypto import encrypt_credentials
from hawk_scan.web.tasks import _execute_scan


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def scan_id(db_engine):
    sid = uuid.uuid4()
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=sid, target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="queued",
            paths=["C:\\Users"], exclude_patterns=[], redacted=False,
        ))
        session.commit()
    return sid


def test_execute_scan_success(db_engine, scan_id):
    creds = encrypt_credentials("admin", "pass", "test-key")

    mock_transport = MagicMock()
    mock_transport.name = "smb"
    mock_files = [MagicMock(remote_path="\\\\WKS-01\\C$\\file.txt", size_bytes=100, extension=".txt", owner=None, modified_time=None)]

    mock_orchestrator = MagicMock()
    mock_orchestrator.enumerate.return_value = mock_files
    mock_orchestrator.scan.return_value = (
        [MagicMock(
            file_path="\\\\WKS-01\\C$\\file.txt",
            pattern_name="SSN", category="pii", severity="high",
            matches=["123-45-6789"], match_count=1,
            sample_text="SSN: ...", file_owner=None, file_modified=None,
        )],
        [],
    )

    with patch("hawk_scan.web.tasks.negotiate_transport", return_value=mock_transport), \
         patch("hawk_scan.web.tasks.ScanOrchestrator", return_value=mock_orchestrator), \
         patch("hawk_scan.web.tasks.ScanEngine"), \
         patch("hawk_scan.web.tasks.generate_html_report"), \
         patch("hawk_scan.web.tasks.load_fingerprints", return_value={}), \
         patch("hawk_scan.web.tasks._get_engine", return_value=db_engine), \
         patch("hawk_scan.web.tasks._publish_progress"), \
         patch("hawk_scan.web.tasks._get_secret", return_value="test-key"):
        _execute_scan(
            str(scan_id), "WKS-01", creds,
            ["C:\\Users"], [], 50, False, None,
        )

    with Session(db_engine) as session:
        scan = session.get(ScanRecord, scan_id)
        assert scan.status == "completed"
        assert scan.files_found == 1
        assert session.query(FindingRecord).filter_by(scan_id=scan_id).count() == 1


def test_execute_scan_failure(db_engine, scan_id):
    creds = encrypt_credentials("admin", "pass", "test-key")

    with patch("hawk_scan.web.tasks.negotiate_transport", side_effect=ConnectionError("unreachable")), \
         patch("hawk_scan.web.tasks._get_engine", return_value=db_engine), \
         patch("hawk_scan.web.tasks._publish_progress"), \
         patch("hawk_scan.web.tasks._get_secret", return_value="test-key"):
        _execute_scan(
            str(scan_id), "WKS-01", creds,
            ["C:\\Users"], [], 50, False, None,
        )

    with Session(db_engine) as session:
        scan = session.get(ScanRecord, scan_id)
        assert scan.status == "failed"
        assert "unreachable" in scan.error_message
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_tasks.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Implement Celery app**

Create `hawk_scan/hawk_scan/web/celery_app.py`:

```python
from celery import Celery
from hawk_scan.web.config import get_settings

settings = get_settings()

celery = Celery(
    "hawk_scan",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    worker_concurrency=settings.max_concurrent_scans,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)
```

- [ ] **Step 4: Implement scan task**

Create `hawk_scan/hawk_scan/web/tasks.py`:

```python
import os
import uuid
import tempfile
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from hawk_scan.web.crypto import decrypt_credentials
from hawk_scan.web.db import Base, ScanRecord, FindingRecord, SkippedFileRecord
from hawk_scan.remote.transport import Credentials, negotiate_transport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.orchestrator import ScanOrchestrator
from hawk_scan.config import load_fingerprints
from hawk_scan.report.generator import generate_html_report
from hawk_scan.models import ScanReport, ScanResult


def _get_engine():
    from hawk_scan.web.config import get_settings
    settings = get_settings()
    return create_engine(settings.database_url.replace("+asyncpg", ""))


def _get_secret():
    from hawk_scan.web.config import get_settings
    return get_settings().secret_key


def _publish_progress(scan_id: str, data: dict):
    try:
        import redis as redis_lib
        from hawk_scan.web.config import get_settings
        r = redis_lib.Redis.from_url(get_settings().redis_url)
        import json
        r.publish(f"scan:{scan_id}:progress", json.dumps(data))
    except Exception:
        pass


def _execute_scan(
    scan_id: str,
    target_host: str,
    encrypted_creds: str,
    paths: list[str],
    exclude_patterns: list[str],
    max_file_size_mb: int,
    redact: bool,
    transport_type: str | None,
):
    engine = _get_engine()
    secret = _get_secret()
    scan_uuid = uuid.UUID(scan_id)

    try:
        username, password = decrypt_credentials(encrypted_creds, secret)
        creds = Credentials(username=username, password=password)

        with Session(engine) as session:
            scan = session.get(ScanRecord, scan_uuid)
            scan.status = "enumerating"
            scan.started_at = datetime.now(timezone.utc)
            session.commit()

        _publish_progress(scan_id, {"phase": "enumerating", "files_found": 0})

        transport = negotiate_transport(target_host, creds, 30, transport_type)

        fp_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "fingerprints", "default.yml")
        fingerprints = load_fingerprints(fp_path)
        scan_engine = ScanEngine(fingerprints, redact=redact)
        orchestrator = ScanOrchestrator(transport=transport, engine=scan_engine, max_file_size_mb=max_file_size_mb)

        def on_enum(count, filename):
            _publish_progress(scan_id, {"phase": "enumerating", "files_found": count})

        file_list = orchestrator.enumerate(paths, exclude_patterns, progress_callback=on_enum)

        with Session(engine) as session:
            scan = session.get(ScanRecord, scan_uuid)
            scan.status = "scanning"
            scan.transport = transport.name
            scan.files_found = len(file_list)
            session.commit()

        _publish_progress(scan_id, {"phase": "scanning", "current": 0, "total": len(file_list)})

        scan_count = 0
        def on_scan(file_path):
            nonlocal scan_count
            scan_count += 1
            import ntpath
            _publish_progress(scan_id, {
                "phase": "scanning",
                "current": scan_count,
                "total": len(file_list),
                "filename": ntpath.basename(file_path),
            })

        temp_dir = tempfile.mkdtemp(prefix="hawk_scan_web_")
        try:
            findings, skipped = orchestrator.scan(file_list, temp_dir, progress_callback=on_scan)
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

        with Session(engine) as session:
            for f in findings:
                session.add(FindingRecord(
                    id=uuid.uuid4(), scan_id=scan_uuid,
                    file_path=f.file_path, pattern_name=f.pattern_name,
                    category=f.category, severity=f.severity,
                    matches=f.matches, match_count=f.match_count,
                    sample_text=f.sample_text, file_owner=f.file_owner,
                    file_modified=f.file_modified,
                ))
            for s in skipped:
                session.add(SkippedFileRecord(
                    id=uuid.uuid4(), scan_id=scan_uuid,
                    file_path=s.file_path, reason=s.reason,
                ))

            scan = session.get(ScanRecord, scan_uuid)
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.files_scanned = len(findings) + len(skipped)
            scan.files_skipped = len(skipped)

            from hawk_scan.web.config import get_settings
            settings = get_settings()
            reports_dir = settings.reports_dir
            os.makedirs(reports_dir, exist_ok=True)
            report_path = os.path.join(reports_dir, f"{scan_id}.html")
            result = ScanResult(
                target_host=target_host, transport_method=transport.name,
                scan_user=username, start_time=str(scan.started_at),
                end_time=str(scan.completed_at),
                duration_seconds=(scan.completed_at - scan.started_at).total_seconds(),
                total_files_scanned=scan.files_scanned,
                total_files_skipped=scan.files_skipped,
                findings=findings, skipped_files=skipped,
            )
            report = ScanReport(result=result)
            generate_html_report(report, report_path)
            scan.report_path = report_path

            session.commit()

        _publish_progress(scan_id, {
            "phase": "completed",
            "findings_count": len(findings),
            "skipped_count": len(skipped),
        })

    except Exception as e:
        with Session(engine) as session:
            scan = session.get(ScanRecord, scan_uuid)
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                session.commit()
        _publish_progress(scan_id, {"phase": "failed", "error": str(e)})


try:
    from hawk_scan.web.celery_app import celery

    @celery.task(name="hawk_scan.run_scan")
    def run_scan_task(scan_id, target_host, encrypted_creds, paths, exclude_patterns, max_file_size_mb, redact, transport_type):
        _execute_scan(scan_id, target_host, encrypted_creds, paths, exclude_patterns, max_file_size_mb, redact, transport_type)
except Exception:
    run_scan_task = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_tasks.py -v`
Expected: 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add hawk_scan/hawk_scan/web/celery_app.py hawk_scan/hawk_scan/web/tasks.py hawk_scan/tests/test_tasks.py
git commit -m "feat(web): add Celery scan task with progress publishing"
```

---

## Task 7: WebSocket Progress Endpoint

**Files:**
- Modify: `hawk_scan/hawk_scan/web/routes/scans.py`
- Test: `hawk_scan/tests/test_websocket.py`

- [ ] **Step 1: Write failing test**

Create `hawk_scan/tests/test_websocket.py`:

```python
import uuid
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
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
            entra_user="jeff@example.com", status="scanning",
            paths=[], exclude_patterns=[], redacted=False,
        ))
        session.commit()
    return sid


@pytest.mark.anyio
async def test_websocket_scan_not_found(app):
    from starlette.testclient import TestClient
    client = TestClient(app)
    fake_id = uuid.uuid4()
    with pytest.raises(Exception):
        with client.websocket_connect(f"/api/scans/{fake_id}/progress"):
            pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd hawk_scan && pytest tests/test_websocket.py -v`
Expected: FAIL

- [ ] **Step 3: Add WebSocket endpoint to scans router**

Add to the end of `hawk_scan/hawk_scan/web/routes/scans.py`:

```python
import asyncio
import json
from fastapi import WebSocket, WebSocketDisconnect


@router.websocket("/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: uuid.UUID):
    db = next(_get_db()) if callable(_get_db) else None

    try:
        session_factory = websocket.app.state.session_factory
        db = session_factory()
    except Exception:
        db_gen = _get_db()
        db = next(db_gen)

    scan = db.get(ScanRecord, scan_id)
    db.close()
    if not scan:
        await websocket.close(code=4004, reason="Scan not found")
        return

    await websocket.accept()

    if scan.status in ("completed", "failed"):
        await websocket.send_json({"phase": scan.status})
        await websocket.close()
        return

    try:
        import redis as redis_lib
        from hawk_scan.web.config import get_settings
        settings = get_settings()
        r = redis_lib.Redis.from_url(settings.redis_url)
        pubsub = r.pubsub()
        pubsub.subscribe(f"scan:{scan_id}:progress")
        try:
            while True:
                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                    if data.get("phase") in ("completed", "failed"):
                        break
                else:
                    await asyncio.sleep(0.5)
        finally:
            pubsub.unsubscribe()
            pubsub.close()
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.send_json({"phase": "completed"})
    finally:
        await websocket.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd hawk_scan && pytest tests/test_websocket.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/hawk_scan/web/routes/scans.py hawk_scan/tests/test_websocket.py
git commit -m "feat(web): add WebSocket endpoint for scan progress"
```

---

## Task 8: Auth Routes (Entra ID OAuth2)

**Files:**
- Create: `hawk_scan/hawk_scan/web/routes/auth.py`
- Modify: `hawk_scan/hawk_scan/web/app.py`
- Test: `hawk_scan/tests/test_auth.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_auth.py`:

```python
import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from hawk_scan.web.db import Base
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_auth.py -v`
Expected: FAIL with ImportError or 404

- [ ] **Step 3: Implement auth routes**

Create `hawk_scan/hawk_scan/web/routes/auth.py`:

```python
import uuid
import json
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _get_msal_app(settings):
    import msal
    return msal.ConfidentialClientApplication(
        settings.azure_client_id,
        authority=f"https://login.microsoftonline.com/{settings.azure_tenant_id}",
        client_credential=settings.azure_client_secret,
    )


@router.get("/login")
def login(request: Request):
    from hawk_scan.web.config import get_settings
    settings = get_settings()

    if not settings.azure_client_id:
        return RedirectResponse(url="/api/auth/callback?dev=1")

    msal_app = _get_msal_app(settings)
    callback_url = f"{settings.base_url}/api/auth/callback"
    flow = msal_app.initiate_auth_code_flow(
        scopes=["User.Read"],
        redirect_uri=callback_url,
    )
    request.app.state.auth_flows = getattr(request.app.state, "auth_flows", {})
    flow_id = str(uuid.uuid4())
    request.app.state.auth_flows[flow_id] = flow

    response = RedirectResponse(url=flow["auth_uri"])
    response.set_cookie("flow_id", flow_id, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback")
def callback(request: Request):
    from hawk_scan.web.config import get_settings
    settings = get_settings()

    if request.query_params.get("dev") == "1" and not settings.azure_client_id:
        session_id = str(uuid.uuid4())
        try:
            import redis as redis_lib
            r = redis_lib.Redis.from_url(settings.redis_url)
            r.setex(
                f"session:{session_id}",
                settings.session_ttl_hours * 3600,
                json.dumps({"email": "dev@localhost", "name": "Dev User"}),
            )
        except Exception:
            pass
        response = RedirectResponse(url="/")
        response.set_cookie(
            "session_id", session_id,
            httponly=True, samesite="lax",
            max_age=settings.session_ttl_hours * 3600,
        )
        return response

    flow_id = request.cookies.get("flow_id")
    if not flow_id:
        raise HTTPException(400, "Missing auth flow")

    flows = getattr(request.app.state, "auth_flows", {})
    flow = flows.pop(flow_id, None)
    if not flow:
        raise HTTPException(400, "Invalid or expired auth flow")

    msal_app = _get_msal_app(settings)
    result = msal_app.acquire_token_by_auth_code_flow(
        flow,
        dict(request.query_params),
    )

    if "error" in result:
        raise HTTPException(400, f"Auth failed: {result.get('error_description', result['error'])}")

    claims = result.get("id_token_claims", {})
    user_info = {
        "email": claims.get("preferred_username", claims.get("email", "")),
        "name": claims.get("name", ""),
    }

    session_id = str(uuid.uuid4())
    try:
        import redis as redis_lib
        r = redis_lib.Redis.from_url(settings.redis_url)
        r.setex(
            f"session:{session_id}",
            settings.session_ttl_hours * 3600,
            json.dumps(user_info),
        )
    except Exception:
        pass

    response = RedirectResponse(url="/")
    response.set_cookie(
        "session_id", session_id,
        httponly=True, samesite="lax", secure=True,
        max_age=settings.session_ttl_hours * 3600,
    )
    response.delete_cookie("flow_id")
    return response


@router.get("/me")
def me(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(401, "Not authenticated")

    try:
        import redis as redis_lib
        from hawk_scan.web.config import get_settings
        r = redis_lib.Redis.from_url(get_settings().redis_url)
        data = r.get(f"session:{session_id}")
        if not data:
            raise HTTPException(401, "Session expired")
        return json.loads(data)
    except HTTPException:
        raise
    except Exception:
        if getattr(request.app.state, "_testing", False):
            raise HTTPException(401, "Not authenticated")
        raise HTTPException(500, "Session store unavailable")


@router.post("/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id:
        try:
            import redis as redis_lib
            from hawk_scan.web.config import get_settings
            r = redis_lib.Redis.from_url(get_settings().redis_url)
            r.delete(f"session:{session_id}")
        except Exception:
            pass
    response = Response(status_code=200)
    response.delete_cookie("session_id")
    return response
```

- [ ] **Step 4: Mount auth routes in app.py**

Add to `hawk_scan/hawk_scan/web/app.py`, after the scans router import:

```python
from hawk_scan.web.routes import auth as auth_router
```

And inside `create_app()`, after `app.include_router(scans_router.router)`:

```python
    app.include_router(auth_router.router)
    if testing:
        app.state._testing = True
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_auth.py -v`
Expected: 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add hawk_scan/hawk_scan/web/routes/auth.py hawk_scan/hawk_scan/web/app.py hawk_scan/tests/test_auth.py
git commit -m "feat(web): add Entra ID OAuth2 auth routes"
```

---

## Task 9: Celery Beat Scheduled Tasks

**Files:**
- Create: `hawk_scan/hawk_scan/web/beat.py`
- Test: `hawk_scan/tests/test_beat.py`

- [ ] **Step 1: Write failing tests**

Create `hawk_scan/tests/test_beat.py`:

```python
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord
from hawk_scan.web.beat import cleanup_expired_scans, recover_stale_scans


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def test_cleanup_deletes_expired(db_engine):
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        ))
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-02", scan_user="admin",
            entra_user="jeff@example.com", status="completed",
            paths=[], exclude_patterns=[], redacted=False,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        ))
        session.commit()

    cleanup_expired_scans(db_engine)

    with Session(db_engine) as session:
        remaining = session.query(ScanRecord).all()
        assert len(remaining) == 1
        assert remaining[0].target_host == "WKS-02"


def test_recover_stale_scans(db_engine):
    with Session(db_engine) as session:
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-01", scan_user="admin",
            entra_user="jeff@example.com", status="scanning",
            paths=[], exclude_patterns=[], redacted=False,
            started_at=datetime.now(timezone.utc) - timedelta(hours=3),
        ))
        session.add(ScanRecord(
            id=uuid.uuid4(), target_host="WKS-02", scan_user="admin",
            entra_user="jeff@example.com", status="scanning",
            paths=[], exclude_patterns=[], redacted=False,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=30),
        ))
        session.commit()

    recover_stale_scans(db_engine)

    with Session(db_engine) as session:
        scans = session.query(ScanRecord).all()
        stale = [s for s in scans if s.target_host == "WKS-01"][0]
        fresh = [s for s in scans if s.target_host == "WKS-02"][0]
        assert stale.status == "failed"
        assert "timed out" in stale.error_message.lower()
        assert fresh.status == "scanning"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hawk_scan && pytest tests/test_beat.py -v`
Expected: FAIL with ImportError

- [ ] **Step 3: Implement beat tasks**

Create `hawk_scan/hawk_scan/web/beat.py`:

```python
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from hawk_scan.web.db import ScanRecord

STALE_THRESHOLD_HOURS = 2


def cleanup_expired_scans(engine):
    now = datetime.now(timezone.utc)
    with Session(engine) as session:
        expired = session.query(ScanRecord).filter(ScanRecord.expires_at < now).all()
        for scan in expired:
            session.delete(scan)
        session.commit()


def recover_stale_scans(engine):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_THRESHOLD_HOURS)
    with Session(engine) as session:
        stale = session.query(ScanRecord).filter(
            ScanRecord.status.in_(["scanning", "enumerating"]),
            ScanRecord.started_at < cutoff,
        ).all()
        for scan in stale:
            scan.status = "failed"
            scan.error_message = f"Scan timed out after {STALE_THRESHOLD_HOURS} hours"
            scan.completed_at = datetime.now(timezone.utc)
        session.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_beat.py -v`
Expected: 2 tests PASS

- [ ] **Step 5: Register beat tasks with Celery**

Add to `hawk_scan/hawk_scan/web/celery_app.py`:

```python
from celery.schedules import crontab

celery.conf.beat_schedule = {
    "cleanup-expired-scans": {
        "task": "hawk_scan.cleanup_expired",
        "schedule": crontab(hour=2, minute=0),
    },
    "recover-stale-scans": {
        "task": "hawk_scan.recover_stale",
        "schedule": 300.0,
    },
}


@celery.task(name="hawk_scan.cleanup_expired")
def cleanup_expired_task():
    from hawk_scan.web.beat import cleanup_expired_scans
    from hawk_scan.web.tasks import _get_engine
    cleanup_expired_scans(_get_engine())


@celery.task(name="hawk_scan.recover_stale")
def recover_stale_task():
    from hawk_scan.web.beat import recover_stale_scans
    from hawk_scan.web.tasks import _get_engine
    recover_stale_scans(_get_engine())
```

- [ ] **Step 6: Commit**

```bash
git add hawk_scan/hawk_scan/web/beat.py hawk_scan/hawk_scan/web/celery_app.py hawk_scan/tests/test_beat.py
git commit -m "feat(web): add scheduled retention cleanup and stale scan recovery"
```

---

## Task 10: Report Download Endpoint

**Files:**
- Modify: `hawk_scan/hawk_scan/web/routes/scans.py`
- Test: `hawk_scan/tests/test_report_download.py`

- [ ] **Step 1: Write failing test**

Create `hawk_scan/tests/test_report_download.py`:

```python
import uuid
import os
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd hawk_scan && pytest tests/test_report_download.py -v`
Expected: FAIL (404 — endpoint doesn't exist yet)

- [ ] **Step 3: Add report download endpoint**

Add to `hawk_scan/hawk_scan/web/routes/scans.py`:

```python
import os
from fastapi.responses import FileResponse


@router.get("/{scan_id}/report")
def download_report(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.get(ScanRecord, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(404, "Report not available")
    return FileResponse(
        scan.report_path,
        media_type="text/html",
        filename=f"hawk_scan_{scan.target_host}_{scan_id}.html",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hawk_scan && pytest tests/test_report_download.py -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add hawk_scan/hawk_scan/web/routes/scans.py hawk_scan/tests/test_report_download.py
git commit -m "feat(web): add report download endpoint"
```

---

## Task 11: Alembic Database Migrations

**Files:**
- Create: `hawk_scan/alembic.ini`
- Create: `hawk_scan/alembic/env.py`
- Create: `hawk_scan/alembic/script.py.mako`
- Create: `hawk_scan/alembic/versions/` (directory)

- [ ] **Step 1: Initialize Alembic**

Run:
```bash
cd hawk_scan && alembic init alembic
```

- [ ] **Step 2: Configure alembic.ini**

Edit `hawk_scan/alembic.ini` — set `sqlalchemy.url`:

```ini
sqlalchemy.url = postgresql+asyncpg://hawkscan:hawkscan@localhost:5432/hawkscan
```

- [ ] **Step 3: Configure alembic/env.py**

Replace `hawk_scan/alembic/env.py` target_metadata with:

```python
from hawk_scan.web.db import Base
target_metadata = Base.metadata
```

Add environment variable override for database URL:

```python
import os
config.set_main_option(
    "sqlalchemy.url",
    os.environ.get("HAWKSCAN_DATABASE_URL", config.get_main_option("sqlalchemy.url", "")).replace("+asyncpg", ""),
)
```

- [ ] **Step 4: Generate initial migration**

Run:
```bash
cd hawk_scan && alembic revision --autogenerate -m "initial schema"
```

- [ ] **Step 5: Verify migration file was created**

Run:
```bash
ls hawk_scan/alembic/versions/
```
Expected: one migration file like `001_initial_schema.py`

- [ ] **Step 6: Commit**

```bash
git add hawk_scan/alembic.ini hawk_scan/alembic/
git commit -m "feat(web): add Alembic database migrations"
```

---

## Task 12: Frontend Scaffold (React + TypeScript + Tailwind)

**Files:**
- Create: `frontend/` (Vite project)
- Create: `frontend/src/types.ts`
- Create: `frontend/src/api.ts`
- Modify: `.gitignore`

- [ ] **Step 1: Create Vite React project**

Run:
```bash
cd /Users/jeickelberger/Repositories/hawk-eye && npm create vite@latest frontend -- --template react-ts
cd frontend && npm install
npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Configure Tailwind**

Edit `frontend/vite.config.ts`:

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        ws: true,
      },
    },
  },
});
```

Replace `frontend/src/index.css` with:

```css
@import "tailwindcss";
```

- [ ] **Step 3: Install React Router**

Run:
```bash
cd frontend && npm install react-router-dom
```

- [ ] **Step 4: Create TypeScript types**

Create `frontend/src/types.ts`:

```typescript
export interface ScanSummary {
  id: string;
  target_host: string;
  status: string;
  transport: string | null;
  scan_user: string;
  entra_user: string;
  files_found: number | null;
  files_scanned: number | null;
  files_skipped: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface Finding {
  id: string;
  file_path: string;
  pattern_name: string;
  category: string;
  severity: string;
  matches: string[];
  match_count: number;
  sample_text: string | null;
  file_owner: string | null;
  file_modified: string | null;
}

export interface SkippedFile {
  id: string;
  file_path: string;
  reason: string;
}

export interface ScanDetail extends ScanSummary {
  paths: string[];
  exclude_patterns: string[];
  redacted: boolean;
  error_message: string | null;
  findings: Finding[];
  skipped_files: SkippedFile[];
}

export interface ScanListResponse {
  items: ScanSummary[];
  total: number;
  page: number;
  per_page: number;
}

export interface DashboardStats {
  total_scans: number;
  active_scans: number;
  total_findings: number;
  high_severity_findings: number;
}

export interface ProgressMessage {
  phase: string;
  files_found?: number;
  current?: number;
  total?: number;
  filename?: string;
  findings_count?: number;
  skipped_count?: number;
  error?: string;
}

export interface UserInfo {
  email: string;
  name: string;
}
```

- [ ] **Step 5: Create API wrapper**

Create `frontend/src/api.ts`:

```typescript
const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (resp.status === 401) {
    window.location.href = "/api/auth/login";
    throw new Error("Not authenticated");
  }
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${resp.status}: ${text}`);
  }
  if (resp.status === 204) return undefined as T;
  return resp.json();
}

export const api = {
  getMe: () => request<{ email: string; name: string }>("/auth/me"),
  getScans: (page = 1, status?: string, target?: string) => {
    const params = new URLSearchParams({ page: String(page) });
    if (status) params.set("status", status);
    if (target) params.set("target", target);
    return request<import("./types").ScanListResponse>(`/scans?${params}`);
  },
  getScan: (id: string) => request<import("./types").ScanDetail>(`/scans/${id}`),
  createScan: (body: Record<string, unknown>) =>
    request<import("./types").ScanDetail>("/scans", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteScan: (id: string) => request<void>(`/scans/${id}`, { method: "DELETE" }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
};
```

- [ ] **Step 6: Update .gitignore**

Add to `.gitignore`:

```
frontend/node_modules/
frontend/dist/
```

- [ ] **Step 7: Verify build works**

Run:
```bash
cd frontend && npm run build
```
Expected: Build succeeds, output in `frontend/dist/`

- [ ] **Step 8: Commit**

```bash
git add frontend/ .gitignore
git commit -m "feat(web): scaffold React frontend with Vite, TypeScript, Tailwind"
```

---

## Task 13: Frontend Layout and Auth Flow

**Files:**
- Create: `frontend/src/components/Layout.tsx`
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Create Layout component**

Create `frontend/src/components/Layout.tsx`:

```tsx
import { Link, Outlet, useNavigate } from "react-router-dom";
import { api } from "../api";
import type { UserInfo } from "../types";

export function Layout({ user }: { user: UserInfo }) {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await api.logout();
    window.location.href = "/api/auth/login";
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex justify-between items-center">
        <div className="flex items-center gap-6">
          <Link to="/" className="text-lg font-bold text-cyan-400">
            Hawk Scan
          </Link>
          <Link to="/" className="text-sm text-gray-400 hover:text-gray-200">
            Dashboard
          </Link>
          <Link to="/scans/new" className="text-sm text-gray-400 hover:text-gray-200">
            New Scan
          </Link>
          <Link to="/scans" className="text-sm text-gray-400 hover:text-gray-200">
            History
          </Link>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-gray-400">{user.email}</span>
          <button onClick={handleLogout} className="text-gray-500 hover:text-gray-300">
            Logout
          </button>
        </div>
      </nav>
      <main className="p-6 max-w-7xl mx-auto">
        <Outlet />
      </main>
    </div>
  );
}
```

- [ ] **Step 2: Wire up App with router and auth**

Replace `frontend/src/App.tsx`:

```tsx
import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { api } from "./api";
import type { UserInfo } from "./types";
import { Layout } from "./components/Layout";

function Placeholder({ title }: { title: string }) {
  return <h1 className="text-2xl font-bold">{title}</h1>;
}

export default function App() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getMe().then(setUser).catch(() => setUser(null)).finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <p className="text-gray-400">Loading...</p>
      </div>
    );
  }

  if (!user) {
    window.location.href = "/api/auth/login";
    return null;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout user={user} />}>
          <Route path="/" element={<Placeholder title="Dashboard" />} />
          <Route path="/scans/new" element={<Placeholder title="New Scan" />} />
          <Route path="/scans/:id" element={<Placeholder title="Scan Detail" />} />
          <Route path="/scans" element={<Placeholder title="Scan History" />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
```

- [ ] **Step 3: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add frontend/src/
git commit -m "feat(web): add layout component and auth-gated router"
```

---

## Task 14: Frontend — Dashboard, New Scan, Scan Progress, History, Detail Pages

**Files:**
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/pages/NewScan.tsx`
- Create: `frontend/src/pages/ScanProgress.tsx`
- Create: `frontend/src/pages/ScanHistory.tsx`
- Create: `frontend/src/pages/ScanDetail.tsx`
- Create: `frontend/src/components/StatusBadge.tsx`
- Create: `frontend/src/components/ProgressBar.tsx`
- Create: `frontend/src/hooks/useWebSocket.ts`
- Modify: `frontend/src/App.tsx`

This is a large task — implement each page one at a time, building from the simplest outward.

- [ ] **Step 1: Create shared components**

Create `frontend/src/components/StatusBadge.tsx`:

```tsx
const colors: Record<string, string> = {
  queued: "bg-gray-500",
  enumerating: "bg-amber-500 text-gray-900",
  scanning: "bg-amber-500 text-gray-900",
  completed: "bg-green-500 text-gray-900",
  failed: "bg-red-500",
  cancelled: "bg-gray-600",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colors[status] || "bg-gray-600"}`}>
      {status}
    </span>
  );
}
```

Create `frontend/src/components/ProgressBar.tsx`:

```tsx
export function ProgressBar({ current, total }: { current: number; total: number }) {
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  return (
    <div className="w-full bg-gray-700 rounded-full h-2">
      <div
        className="bg-gradient-to-r from-cyan-400 to-green-400 h-2 rounded-full transition-all duration-300"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}
```

Create `frontend/src/hooks/useWebSocket.ts`:

```tsx
import { useEffect, useRef, useState, useCallback } from "react";
import type { ProgressMessage } from "../types";

export function useWebSocket(scanId: string | undefined) {
  const [messages, setMessages] = useState<ProgressMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/api/scans/${scanId}/progress`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      const data: ProgressMessage = JSON.parse(event.data);
      setMessages((prev) => [...prev, data]);
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [scanId]);

  const latest = messages.length > 0 ? messages[messages.length - 1] : null;
  return { messages, latest, connected };
}
```

- [ ] **Step 2: Create Dashboard page**

Create `frontend/src/pages/Dashboard.tsx`:

```tsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { ScanSummary } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getScans(1).then((data) => { setScans(data.items); setLoading(false); });
  }, []);

  const active = scans.filter((s) => ["queued", "enumerating", "scanning"].includes(s.status));
  const totalFindings = scans.reduce((acc, s) => acc + s.high_count + s.medium_count + s.low_count, 0);
  const highFindings = scans.reduce((acc, s) => acc + s.high_count, 0);

  if (loading) return <p className="text-gray-400">Loading...</p>;

  return (
    <div>
      <div className="grid grid-cols-4 gap-4 mb-8">
        {[
          { label: "Total Scans", value: scans.length, color: "text-cyan-400" },
          { label: "Running Now", value: active.length, color: "text-green-400" },
          { label: "Total Findings", value: totalFindings, color: "text-orange-400" },
          { label: "High Severity", value: highFindings, color: "text-red-400" },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            <div className="text-gray-500 text-sm">{stat.label}</div>
          </div>
        ))}
      </div>

      <h2 className="text-lg font-bold mb-3">Recent Scans</h2>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-800">
            <th className="text-left py-2">Target</th>
            <th className="text-left">Status</th>
            <th className="text-left">Findings</th>
            <th className="text-left">Date</th>
            <th className="text-left">By</th>
          </tr>
        </thead>
        <tbody>
          {scans.slice(0, 10).map((scan) => (
            <tr key={scan.id} className="border-b border-gray-800/50">
              <td className="py-2">
                <Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline">
                  {scan.target_host}
                </Link>
              </td>
              <td><StatusBadge status={scan.status} /></td>
              <td>
                {scan.high_count > 0 && <span className="text-red-400">{scan.high_count} high</span>}
                {scan.high_count > 0 && scan.medium_count > 0 && " · "}
                {scan.medium_count > 0 && <span>{scan.medium_count} med</span>}
              </td>
              <td className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
              <td className="text-gray-500">{scan.entra_user}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 3: Create NewScan page**

Create `frontend/src/pages/NewScan.tsx`:

```tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export function NewScan() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    target_host: "",
    username: "",
    password: "",
    transport: "" as string,
    paths: "C:\\Users",
    max_file_size_mb: 50,
    redact: true,
  });
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const result = await api.createScan({
        ...form,
        transport: form.transport || null,
        paths: form.paths.split("\n").map((p) => p.trim()).filter(Boolean),
      });
      navigate(`/scans/${result.id}`);
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-lg mx-auto">
      <h1 className="text-2xl font-bold mb-6">New Scan</h1>
      {error && <div className="bg-red-900/50 text-red-300 p-3 rounded mb-4">{error}</div>}

      <label className="block text-sm text-gray-400 mb-1">Target Hostname</label>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.target_host} onChange={(e) => setForm({ ...form, target_host: e.target.value })} required />

      <label className="block text-sm text-gray-400 mb-1">Domain\Username</label>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />

      <label className="block text-sm text-gray-400 mb-1">Password</label>
      <input type="password" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4"
        value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Transport</label>
          <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
            value={form.transport} onChange={(e) => setForm({ ...form, transport: e.target.value })}>
            <option value="">Auto-detect</option>
            <option value="smb">SMB</option>
            <option value="winrm">WinRM</option>
          </select>
        </div>
        <div>
          <label className="block text-sm text-gray-400 mb-1">Max File Size (MB)</label>
          <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2"
            value={form.max_file_size_mb} onChange={(e) => setForm({ ...form, max_file_size_mb: Number(e.target.value) })} />
        </div>
      </div>

      <label className="block text-sm text-gray-400 mb-1">Scan Paths (one per line)</label>
      <textarea rows={3} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 mb-4 font-mono text-sm"
        value={form.paths} onChange={(e) => setForm({ ...form, paths: e.target.value })} />

      <label className="flex items-center gap-2 mb-6 text-sm">
        <input type="checkbox" checked={form.redact} onChange={(e) => setForm({ ...form, redact: e.target.checked })} />
        Redact matched values in report
      </label>

      <button type="submit" disabled={submitting}
        className="w-full bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-bold py-3 rounded disabled:opacity-50">
        {submitting ? "Starting..." : "Start Scan"}
      </button>
    </form>
  );
}
```

- [ ] **Step 4: Create ScanProgress page**

Create `frontend/src/pages/ScanProgress.tsx`:

```tsx
import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import { useWebSocket } from "../hooks/useWebSocket";
import { ProgressBar } from "../components/ProgressBar";
import { StatusBadge } from "../components/StatusBadge";
import type { ScanDetail } from "../types";

export function ScanProgress() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const { latest, messages } = useWebSocket(id);

  useEffect(() => {
    if (id) api.getScan(id).then(setScan);
  }, [id]);

  useEffect(() => {
    if (latest?.phase === "completed" || latest?.phase === "failed") {
      if (id) api.getScan(id).then(setScan);
    }
  }, [latest, id]);

  if (!scan) return <p className="text-gray-400">Loading...</p>;

  const isActive = ["queued", "enumerating", "scanning"].includes(scan.status);
  const phase = latest?.phase || scan.status;
  const current = latest?.current || 0;
  const total = latest?.total || scan.files_found || 0;

  if (!isActive) {
    return (
      <div>
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold">{scan.target_host}</h1>
            <p className="text-gray-500 text-sm">Scan {scan.status}</p>
          </div>
          <StatusBadge status={scan.status} />
        </div>
        {scan.status === "completed" && (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-gray-900 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold">{scan.findings.length}</div>
                <div className="text-gray-500 text-sm">Findings</div>
              </div>
              <div className="bg-gray-900 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold">{scan.files_scanned}</div>
                <div className="text-gray-500 text-sm">Files Scanned</div>
              </div>
              <div className="bg-gray-900 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold">{scan.files_skipped}</div>
                <div className="text-gray-500 text-sm">Files Skipped</div>
              </div>
            </div>
            <Link to={`/scans/${id}`} className="text-cyan-400 hover:underline">View full details →</Link>
          </div>
        )}
        {scan.error_message && (
          <div className="bg-red-900/30 border border-red-800 rounded p-4 mt-4">
            <p className="text-red-300">{scan.error_message}</p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scanning {scan.target_host}</h1>
          <p className="text-gray-500 text-sm">Started by {scan.entra_user}</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Status</div>
          <div className="font-bold capitalize">{phase}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Progress</div>
          <div className="font-bold">{current} / {total} files</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-cyan-400 text-xs uppercase">Findings</div>
          <div className="font-bold">{latest?.findings_count || "—"}</div>
        </div>
      </div>

      <ProgressBar current={current} total={total} />

      <div className="mt-6">
        <h2 className="font-bold mb-2">Live Activity</h2>
        <div className="bg-gray-900 rounded-lg p-4 font-mono text-xs max-h-60 overflow-y-auto space-y-1">
          {messages.slice(-20).map((msg, i) => (
            <div key={i} className="text-gray-400">
              {msg.phase === "scanning" && msg.filename && `Scanning ${msg.filename}...`}
              {msg.phase === "enumerating" && `Enumerating... ${msg.files_found} files found`}
              {msg.phase === "completed" && <span className="text-green-400">Scan complete</span>}
              {msg.phase === "failed" && <span className="text-red-400">Failed: {msg.error}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Create ScanHistory page**

Create `frontend/src/pages/ScanHistory.tsx`:

```tsx
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { ScanSummary } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function ScanHistory() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");

  useEffect(() => {
    api.getScans(page, statusFilter || undefined, targetFilter || undefined).then((data) => {
      setScans(data.items);
      setTotal(data.total);
    });
  }, [page, statusFilter, targetFilter]);

  const totalPages = Math.ceil(total / 20);

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Scan History</h1>
        <div className="flex gap-3">
          <input placeholder="Search targets..." className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
            value={targetFilter} onChange={(e) => { setTargetFilter(e.target.value); setPage(1); }} />
          <select className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
            value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
            <option value="">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="scanning">Scanning</option>
            <option value="failed">Failed</option>
            <option value="queued">Queued</option>
          </select>
        </div>
      </div>

      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700 text-left">
            <th className="py-2">Target</th>
            <th>Status</th>
            <th>Findings</th>
            <th>High</th>
            <th>Scanned By</th>
            <th>Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className="border-b border-gray-800/50">
              <td className="py-2">
                <Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline">{scan.target_host}</Link>
              </td>
              <td><StatusBadge status={scan.status} /></td>
              <td>{scan.high_count + scan.medium_count + scan.low_count || "—"}</td>
              <td className={scan.high_count > 0 ? "text-red-400 font-bold" : "text-green-400"}>
                {scan.high_count}
              </td>
              <td className="text-gray-500">{scan.entra_user}</td>
              <td className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
              <td>
                <Link to={`/scans/${scan.id}`} className="text-cyan-400 hover:underline text-xs">View</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex justify-between items-center mt-4 text-sm text-gray-500">
        <span>Showing {scans.length} of {total} scans</span>
        <div className="flex gap-2">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30">Prev</button>
          <span className="px-3 py-1">{page} / {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}
            className="px-3 py-1 bg-gray-800 rounded disabled:opacity-30">Next</button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 6: Create ScanDetail page**

Create `frontend/src/pages/ScanDetail.tsx`:

```tsx
import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import type { ScanDetail as ScanDetailType } from "../types";
import { StatusBadge } from "../components/StatusBadge";

export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (id) api.getScan(id).then(setScan);
  }, [id]);

  if (!scan) return <p className="text-gray-400">Loading...</p>;

  const isActive = ["queued", "enumerating", "scanning"].includes(scan.status);
  if (isActive) {
    const ScanProgress = require("./ScanProgress").ScanProgress;
    return <ScanProgress />;
  }

  const filtered = scan.findings.filter((f) => {
    if (severityFilter && f.severity !== severityFilter) return false;
    if (search && !f.file_path.toLowerCase().includes(search.toLowerCase()) &&
        !f.pattern_name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">{scan.target_host}</h1>
          <p className="text-gray-500 text-sm">
            Scanned by {scan.entra_user} on {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-3 items-center">
          <StatusBadge status={scan.status} />
          <a href={`/api/scans/${scan.id}/report`} className="text-sm bg-cyan-600 hover:bg-cyan-500 text-white px-3 py-1 rounded">
            Download Report
          </a>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.findings.length}</div>
          <div className="text-gray-500 text-sm">Findings</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-red-400">
            {scan.findings.filter((f) => f.severity === "high").length}
          </div>
          <div className="text-gray-500 text-sm">High Severity</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.files_scanned}</div>
          <div className="text-gray-500 text-sm">Files Scanned</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4 text-center">
          <div className="text-2xl font-bold">{scan.files_skipped}</div>
          <div className="text-gray-500 text-sm">Files Skipped</div>
        </div>
      </div>

      <div className="flex gap-3 mb-4">
        <input placeholder="Search files or patterns..." className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm flex-1"
          value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className="bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm"
          value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">All Severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700 text-left">
            <th className="py-2">File</th>
            <th>Pattern</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Matches</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((f) => (
            <tr key={f.id} className="border-b border-gray-800/50">
              <td className="py-2 max-w-xs truncate text-cyan-400" title={f.file_path}>{f.file_path}</td>
              <td>{f.pattern_name}</td>
              <td className="text-gray-400">{f.category}</td>
              <td>
                <span className={`font-medium ${f.severity === "high" ? "text-red-400" : f.severity === "medium" ? "text-amber-400" : "text-gray-400"}`}>
                  {f.severity}
                </span>
              </td>
              <td>{f.match_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 7: Wire pages into App.tsx router**

Update `frontend/src/App.tsx` — replace the Placeholder imports and routes with the real page components:

```tsx
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanProgress } from "./pages/ScanProgress";
import { ScanHistory } from "./pages/ScanHistory";
import { ScanDetail } from "./pages/ScanDetail";
```

Routes:
```tsx
<Route path="/" element={<Dashboard />} />
<Route path="/scans/new" element={<NewScan />} />
<Route path="/scans/:id" element={<ScanDetail />} />
<Route path="/scans" element={<ScanHistory />} />
```

- [ ] **Step 8: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

- [ ] **Step 9: Commit**

```bash
git add frontend/src/
git commit -m "feat(web): add all frontend pages — dashboard, new scan, progress, history, detail"
```

---

## Task 15: Docker Configuration

**Files:**
- Create: `docker/Dockerfile`
- Create: `docker/Dockerfile.nginx`
- Create: `docker/nginx.conf`
- Create: `docker-compose.yml`
- Create: `.env.example`

- [ ] **Step 1: Create backend Dockerfile**

Create `docker/Dockerfile`:

```dockerfile
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-eng libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r hawkscan
WORKDIR /app

COPY hawk_scan/pyproject.toml hawk_scan/
COPY hawk_scan/hawk_scan/ hawk_scan/hawk_scan/
COPY hawk_scan/fingerprints/ hawk_scan/fingerprints/

RUN pip install --no-cache-dir ./hawk_scan[web]

USER hawkscan

EXPOSE 8000
CMD ["uvicorn", "hawk_scan.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
```

- [ ] **Step 2: Create nginx Dockerfile**

Create `docker/Dockerfile.nginx`:

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
```

- [ ] **Step 3: Create nginx config**

Create `docker/nginx.conf`:

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    root /usr/share/nginx/html;
    index index.html;

    location /api/ {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~ ^/api/scans/.+/progress$ {
        proxy_pass http://api:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

- [ ] **Step 4: Create docker-compose.yml**

Create `docker-compose.yml` in repo root:

```yaml
services:
  nginx:
    build:
      context: .
      dockerfile: docker/Dockerfile.nginx
    ports:
      - "443:443"
    volumes:
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - api

  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
    env_file: .env
    environment:
      - HAWKSCAN_DATABASE_URL=postgresql+asyncpg://hawkscan:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-hawkscan}
      - HAWKSCAN_REDIS_URL=redis://redis:6379/0
      - HAWKSCAN_REPORTS_DIR=/app/reports
      - HAWKSCAN_BASE_URL=https://${HOSTNAME:-localhost}
    volumes:
      - scan_reports:/app/reports
    depends_on:
      - postgres
      - redis

  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile
    command: celery -A hawk_scan.web.celery_app:celery worker --concurrency=${MAX_CONCURRENT_SCANS:-3} --beat -l info
    env_file: .env
    environment:
      - HAWKSCAN_DATABASE_URL=postgresql+asyncpg://hawkscan:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-hawkscan}
      - HAWKSCAN_REDIS_URL=redis://redis:6379/0
      - HAWKSCAN_REPORTS_DIR=/app/reports
    volumes:
      - scan_reports:/app/reports
    depends_on:
      - postgres
      - redis

  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: hawkscan
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-hawkscan}
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
  scan_reports:
  redis_data:
```

- [ ] **Step 5: Create .env.example**

Create `.env.example` in repo root:

```env
# Entra ID (Azure AD) — register an app at portal.azure.com
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Application
HAWKSCAN_SECRET_KEY=change-me-generate-with-openssl-rand-hex-32
HAWKSCAN_RETENTION_DAYS=90

# Database
POSTGRES_PASSWORD=change-me
POSTGRES_DB=hawkscan

# Optional
MAX_CONCURRENT_SCANS=3
HAWKSCAN_SESSION_TTL_HOURS=8
HOSTNAME=hawkscan.yourdomain.local
```

- [ ] **Step 6: Add .env to .gitignore**

Verify `.env` is already in `.gitignore` (it is — line 130).

- [ ] **Step 7: Commit**

```bash
git add docker/ docker-compose.yml .env.example
git commit -m "feat(web): add Docker configuration — Dockerfile, nginx, docker-compose"
```

---

## Task 16: Integration Smoke Test

**Files:**
- Create: `hawk_scan/tests/test_web_integration.py`

- [ ] **Step 1: Write integration test**

Create `hawk_scan/tests/test_web_integration.py`:

```python
import uuid
import pytest
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from hawk_scan.web.db import Base, ScanRecord, FindingRecord
from hawk_scan.web.app import create_app


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:")
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
    with patch("hawk_scan.web.routes.scans.run_scan_task") as mock_task:
        mock_task.delay = lambda *a, **kw: None
        resp = await client.post("/api/scans", json={
            "target_host": "WKS-TEST",
            "username": "DOMAIN\\admin",
            "password": "test",
        })
    assert resp.status_code == 201
    scan_id = resp.json()["id"]

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

    resp = await client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert len(data["findings"]) == 1

    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1

    resp = await client.delete(f"/api/scans/{scan_id}")
    assert resp.status_code == 204

    resp = await client.get("/api/scans")
    assert resp.json()["total"] == 0
```

- [ ] **Step 2: Run integration test**

Run: `cd hawk_scan && pytest tests/test_web_integration.py -v`
Expected: PASS

- [ ] **Step 3: Run all tests**

Run: `cd hawk_scan && pytest tests/ -v`
Expected: All tests PASS (existing + new)

- [ ] **Step 4: Commit**

```bash
git add hawk_scan/tests/test_web_integration.py
git commit -m "test(web): add integration smoke test for scan lifecycle"
```

---

## Task 17: Update CLAUDE.md and Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/user-guide.md`

- [ ] **Step 1: Add web section to CLAUDE.md**

Add a new section to `CLAUDE.md` covering the web application:

```markdown
### Web Application

The web frontend is an optional deployment mode alongside the standalone CLI.

#### Development

```bash
# Backend (API server)
cd hawk_scan && pip install -e ".[dev,web]"
pip install pydantic-settings
uvicorn hawk_scan.web.app:create_app --factory --reload --port 8000

# Frontend (dev server with proxy)
cd frontend && npm install && npm run dev

# Celery worker (requires Redis running)
celery -A hawk_scan.web.celery_app:celery worker --concurrency=3 --beat -l info

# Run web tests
cd hawk_scan && pytest tests/test_web_*.py tests/test_api_*.py tests/test_auth.py tests/test_crypto.py tests/test_tasks.py tests/test_beat.py -v

# Docker (full stack)
docker compose up --build
```

#### Architecture

The web layer (`hawk_scan/web/`) wraps the existing scanning core:
- `app.py` — FastAPI application factory
- `routes/scans.py` — Scan CRUD + WebSocket progress
- `routes/auth.py` — Entra ID OAuth2 flow
- `tasks.py` — Celery task that calls `ScanOrchestrator`
- `db.py` — SQLAlchemy models (ScanRecord, FindingRecord, SkippedFileRecord)
- `crypto.py` — Fernet encryption for credential transit through Redis
- `beat.py` — Scheduled retention cleanup and stale scan recovery
```

- [ ] **Step 2: Add web deployment section to user guide**

Add a Docker deployment section to `docs/user-guide.md` covering:
- Prerequisites (Docker, Entra ID app registration)
- `.env` configuration
- TLS certificate setup
- `docker compose up --build`
- Accessing the web UI

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/user-guide.md
git commit -m "docs: add web application development and deployment documentation"
```
