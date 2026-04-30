# Hawk Scan Web — Containerized Web Application Design

**Date:** 2026-04-30
**Status:** Draft
**Author:** Jeff Eickelberger + Claude

## Overview

Containerize Hawk Scan as a Docker-hosted web application with a React frontend, replacing the CLI workflow for day-to-day use. Techs start scans, monitor progress in real time, and review results from a browser instead of running the CLI on their workstations. A central database provides an audit trail of all scans performed.

The existing CLI remains functional for standalone/offline use. The scanning core (engine, readers, orchestrator, transport) is reused as-is — the web layer wraps it, not replaces it.

## Users & Access

- **Audience:** 5–15 IT/security admins on a single trusted team
- **Authentication:** Azure AD / Entra ID SSO (OAuth2 authorization code flow)
- **Authorization:** Binary — authenticated users can start scans and view all scan history. No role-based access control.

## System Architecture

Five containers orchestrated by Docker Compose, deployed on-prem:

| Container | Image | Role | Exposed Port |
|-----------|-------|------|--------------|
| **nginx** | `nginx:alpine` | Reverse proxy, serves React SPA, TLS termination | 443 |
| **api** | Custom (FastAPI + uvicorn) | REST API, WebSocket endpoint, Entra ID auth | 8000 (internal) |
| **worker** | Same image as api | Celery worker — executes scan jobs | none |
| **redis** | `redis:alpine` | Celery broker, session store, pub/sub for progress | 6379 (internal) |
| **postgres** | `postgres:16-alpine` | Scan history, findings, skipped files | 5432 (internal) |

### Network Requirements

- Only nginx (port 443) is exposed externally
- The worker container requires outbound access to Windows endpoints:
  - Port 445 (SMB)
  - Port 5985/5986 (WinRM)
- Internal container communication uses the Docker bridge network (unencrypted — standard practice behind TLS termination)

### Shared Volumes

- `postgres_data` — persistent database storage
- `scan_reports` — generated HTML/JSON report files (worker writes, API serves)

### Code Reuse

The existing scanning core becomes a library consumed by both the CLI and the web worker:

| Module | Reuse |
|--------|-------|
| `hawk_scan.scanner.engine` | Direct — no changes |
| `hawk_scan.scanner.readers` | Direct — no changes |
| `hawk_scan.scanner.orchestrator` | Direct — no changes |
| `hawk_scan.remote.smb_transport` | Direct — no changes |
| `hawk_scan.remote.winrm_transport` | Direct — no changes |
| `hawk_scan.report.generator` | Direct — generates reports to shared volume |
| `hawk_scan.cli` | Unchanged — remains as standalone CLI entry point |

New code lives under `hawk_scan.web.*`.

## API Design

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/login` | Redirect to Entra ID OAuth2 authorize endpoint |
| `GET` | `/api/auth/callback` | OAuth2 callback — exchanges code for token, creates session |
| `POST` | `/api/auth/logout` | Clear session |
| `GET` | `/api/auth/me` | Current user info (email, display name) |
| `POST` | `/api/scans` | Start a new scan |
| `GET` | `/api/scans` | List scans (paginated, filterable by status/target/date) |
| `GET` | `/api/scans/{id}` | Scan details including findings and skipped files |
| `DELETE` | `/api/scans/{id}` | Delete a scan and cascade to findings/skipped files |
| `GET` | `/api/scans/{id}/report` | Download generated HTML or JSON report file |
| `WS` | `/api/scans/{id}/progress` | WebSocket for live scan progress |

### Starting a Scan

`POST /api/scans` request body:

```json
{
  "target_host": "WORKSTATION-01",
  "username": "DOMAIN\\admin",
  "password": "...",
  "transport": null,
  "paths": ["C:\\Users"],
  "exclude_patterns": [],
  "max_file_size_mb": 50,
  "redact": true
}
```

The password is encrypted in the Celery task message using a per-task key derived from the API server's `SECRET_KEY`. Once the worker picks up the job and decrypts, the plaintext exists only in worker process memory for the duration of the scan. Credentials are never written to the database.

### Scan Lifecycle States

`queued` → `enumerating` → `scanning` → `completed` | `failed` | `cancelled`

## Database Schema

### `scans` Table

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID (PK) | |
| `target_host` | VARCHAR | |
| `transport` | VARCHAR | `smb` or `winrm` |
| `scan_user` | VARCHAR | Domain account used for scanning |
| `entra_user` | VARCHAR | Email of the logged-in web user who initiated |
| `status` | VARCHAR | Lifecycle state |
| `paths` | JSONB | List of scanned paths |
| `exclude_patterns` | JSONB | |
| `redacted` | BOOLEAN | |
| `files_found` | INTEGER | Set after enumeration |
| `files_scanned` | INTEGER | |
| `files_skipped` | INTEGER | |
| `error_message` | TEXT | Set on failure |
| `started_at` | TIMESTAMPTZ | |
| `completed_at` | TIMESTAMPTZ | |
| `report_path` | VARCHAR | Path to generated report file |
| `created_at` | TIMESTAMPTZ | |
| `expires_at` | TIMESTAMPTZ | `created_at` + retention period |

### `findings` Table

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID (PK) | |
| `scan_id` | UUID (FK → scans) | CASCADE delete |
| `file_path` | VARCHAR | |
| `pattern_name` | VARCHAR | |
| `category` | VARCHAR | |
| `severity` | VARCHAR | |
| `matches` | JSONB | |
| `match_count` | INTEGER | |
| `sample_text` | VARCHAR | |
| `file_owner` | VARCHAR | |
| `file_modified` | VARCHAR | |

### `skipped_files` Table

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID (PK) | |
| `scan_id` | UUID (FK → scans) | CASCADE delete |
| `file_path` | VARCHAR | |
| `reason` | VARCHAR | |

### Data Retention

A Celery Beat scheduled task runs daily and deletes scans where `expires_at < now()`, cascading to findings and skipped_files. Default retention period is configurable via `RETENTION_DAYS` environment variable (default: 90 days).

## Authentication

### Entra ID OAuth2 Flow

1. User opens React app → not authenticated → redirected to `/api/auth/login`
2. API redirects to Microsoft's `/authorize` endpoint (tenant-specific)
3. User authenticates with their Microsoft account
4. Microsoft redirects back to `/api/auth/callback` with an authorization code
5. API exchanges the code for an access token + ID token using `msal` library
6. API creates a server-side session stored in Redis (8-hour TTL) and sets an HTTP-only, Secure, SameSite session cookie
7. Subsequent API calls include the cookie; API validates the session against Redis

### Entra ID App Registration

- **Redirect URI:** `https://<hostname>/api/auth/callback`
- **API permissions:** `User.Read` (profile + email only)
- **No additional Graph API permissions** — Entra is used for identity only

### Client-Side Auth

The OAuth2 flow is server-driven: the React app detects a 401 from `/api/auth/me` and redirects the browser to `/api/auth/login`, which initiates the Microsoft OAuth2 flow. After callback, the API sets an HTTP-only session cookie that the browser attaches automatically to all subsequent API requests. No client-side token management is needed — `@azure/msal-react` is not required.

### Configuration

```
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<app-registration-client-id>
AZURE_CLIENT_SECRET=<app-registration-secret>
```

## Scan Execution

### Celery Task

The Celery worker executes scans using the existing scanning code:

1. Decrypt credentials from the task payload
2. Call `negotiate_transport()` to establish SMB or WinRM connection
3. Create `ScanOrchestrator` with the transport and a `ScanEngine`
4. Run `orchestrator.enumerate()` — publish file count to Redis pub/sub
5. Update database: `status=scanning`, `files_found=N`
6. Run `orchestrator.scan()` — publish per-file progress to Redis pub/sub
7. Call `generate_html_report()` — save to the shared `scan_reports` volume
8. Write findings and skipped files to PostgreSQL
9. Update database: `status=completed`, final counts, `report_path`

On failure: catch the exception, update `status=failed` with `error_message`, publish failure event.

### Concurrency

Celery worker runs with `--concurrency=3`, allowing 2–3 simultaneous scans against different targets. When all slots are occupied, new scans remain in `queued` state until a slot frees up.

### Progress Streaming

```
Worker → Redis pub/sub (channel: scan:{id}:progress) → API → WebSocket → React
```

Progress messages:

```json
{"phase": "enumerating", "files_found": 342}
{"phase": "scanning", "current": 45, "total": 342, "filename": "budget.xlsx"}
{"phase": "completed", "findings_count": 12, "skipped_count": 5}
{"phase": "failed", "error": "Cannot reach target"}
```

The API subscribes to the Redis pub/sub channel when a WebSocket client connects and unsubscribes on disconnect.

### Scheduled Maintenance (Celery Beat)

| Task | Schedule | Purpose |
|------|----------|---------|
| Retention cleanup | Daily at 2:00 AM | Delete scans where `expires_at < now()` |
| Stale scan recovery | Every 5 minutes | Mark scans stuck in `scanning` for 2+ hours as `failed` |

## Frontend

### Tech Stack

- React 18 + TypeScript
- React Router for navigation
- Tailwind CSS for styling
- Native WebSocket API for scan progress
- Server-driven OAuth2 (no client-side auth library needed)

### Key Views

1. **Dashboard (`/`)** — summary stat cards (total scans, active, findings, high-severity), active scans with live progress bars, recent scans table
2. **New Scan (`/scans/new`)** — form with target host, domain credentials, scan paths, options. Credentials entered per-scan, never persisted.
3. **Scan Progress (`/scans/:id`)** — real-time progress bar, file-by-file activity log, status cards, cancel button. WebSocket-driven updates.
4. **Scan History (`/scans`)** — paginated table of all scans, filterable by status/target/date, sortable columns. Links to view details or download reports.
5. **Scan Detail (`/scans/:id` — completed)** — findings table with severity/category filters, priority directories ranking, download report button. Mirrors the existing HTML report content.

## Docker & Deployment

### Single Dockerfile

Both `api` and `worker` services share the same Docker image. The image includes:
- Python 3.11 + all `hawk_scan` dependencies
- Tesseract OCR + English language data
- The React SPA build output (for nginx to serve)

Entrypoints differ:
- **api:** `uvicorn hawk_scan.web.app:app --host 0.0.0.0 --port 8000`
- **worker:** `celery -A hawk_scan.web.tasks worker --concurrency=3 --beat`

### nginx Configuration

- Serves the React SPA static files at `/`
- Proxies `/api/*` to the FastAPI container
- Proxies `/api/scans/*/progress` WebSocket connections (with `Upgrade` headers)
- TLS termination using a certificate mapped in via volume

### Configuration

All configuration via environment variables in a `.env` file:

```
# Entra ID
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...

# Application
SECRET_KEY=...              # Session + credential encryption
RETENTION_DAYS=90

# Database
POSTGRES_PASSWORD=...
POSTGRES_DB=hawkscan

# Optional
MAX_CONCURRENT_SCANS=3
SESSION_TTL_HOURS=8
```

### TLS

nginx terminates TLS using a certificate provided via volume mount or generated with an internal CA. Internal container traffic is unencrypted.

## Security

### Credential Handling

Per-scan Windows passwords follow this path:
1. **Browser → API:** Encrypted in transit via TLS (HTTPS)
2. **API → Redis:** Encrypted using Fernet symmetric encryption with a per-task nonce derived from `SECRET_KEY`
3. **Redis → Worker:** Decrypted in worker process memory at job start
4. **Worker memory:** Held only for scan duration, then garbage-collected when the task function returns
5. **Never:** written to database, logged, or persisted to disk

### Network Security

- Only port 443 exposed externally
- PostgreSQL, Redis, and the API are accessible only on the internal Docker network
- Worker requires outbound access to target endpoints on ports 445 and 5985/5986

### Container Hardening

- Non-root user in Dockerfile
- Read-only filesystem where possible
- No `--privileged` flag
- Minimal base image (python:3.11-slim)

### Application Security

- CSRF protection via SameSite cookies
- HTTP-only, Secure session cookies
- Input validation: target hostnames (alphanumeric + hyphens), paths (Windows path format)
- Report files served through authenticated API endpoints, not directly by nginx
- No shell command construction from user input

## Project Structure

New code under `hawk_scan/web/`:

```
hawk_scan/
├── hawk_scan/
│   ├── cli.py              # Existing CLI (unchanged)
│   ├── models.py            # Existing dataclasses (unchanged)
│   ├── scanner/             # Existing engine/readers/orchestrator (unchanged)
│   ├── remote/              # Existing transports (unchanged)
│   ├── report/              # Existing report generator (unchanged)
│   └── web/                 # NEW — web application layer
│       ├── app.py           # FastAPI application, middleware, auth routes
│       ├── tasks.py         # Celery task definitions (scan execution)
│       ├── db.py            # SQLAlchemy models + database connection
│       ├── schemas.py       # Pydantic request/response schemas
│       ├── routes/
│       │   ├── scans.py     # Scan CRUD + progress WebSocket
│       │   └── auth.py      # Entra ID OAuth2 flow
│       └── crypto.py        # Credential encryption/decryption
├── frontend/                # NEW — React application
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── NewScan.tsx
│   │   │   ├── ScanProgress.tsx
│   │   │   ├── ScanHistory.tsx
│   │   │   └── ScanDetail.tsx
│   │   ├── components/
│   │   └── hooks/
│   │       └── useWebSocket.ts
│   ├── package.json
│   └── tailwind.config.js
├── docker/
│   ├── Dockerfile           # Shared API/worker image
│   ├── Dockerfile.nginx     # nginx + React build
│   └── nginx.conf
├── docker-compose.yml
├── .env.example
└── pyproject.toml           # Updated with web dependencies
```

## New Dependencies

Added to `pyproject.toml` under an optional `[web]` group:

- `fastapi` — async web framework
- `uvicorn[standard]` — ASGI server with WebSocket support
- `celery[redis]` — task queue
- `sqlalchemy[asyncio]` — ORM
- `asyncpg` — async PostgreSQL driver
- `alembic` — database migrations
- `msal` — Microsoft Authentication Library
- `cryptography` — Fernet encryption for credential transit
- `pydantic` — request/response validation (bundled with FastAPI)
