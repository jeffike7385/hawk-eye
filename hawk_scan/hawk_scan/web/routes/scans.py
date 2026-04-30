"""Scan CRUD routes."""

import asyncio
import json
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from hawk_scan.web.crypto import encrypt_credentials
from hawk_scan.web.config import get_settings
from hawk_scan.web.db import ScanRecord
from hawk_scan.web.schemas import (
    ScanCreate,
    ScanResponse,
    ScanSummary,
    ScanListResponse,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

def _send_scan_task(scan_id, target_host, encrypted_creds, paths, exclude_patterns, max_file_size_mb, redact, transport_type):
    try:
        from hawk_scan.web.celery_app import celery
        celery.send_task("hawk_scan.run_scan", args=[
            scan_id, target_host, encrypted_creds, paths,
            exclude_patterns, max_file_size_mb, redact, transport_type,
        ])
    except Exception:
        pass


def _get_db():
    """Placeholder dependency; overridden by the app factory."""
    raise NotImplementedError("Override in app factory")


@router.post("", status_code=201, response_model=ScanResponse)
def create_scan(body: ScanCreate, db: Session = Depends(_get_db)):
    settings = get_settings()
    encrypted = encrypt_credentials(body.username, body.password, settings.secret_key)

    scan = ScanRecord(
        id=uuid.uuid4(),
        target_host=body.target_host,
        transport=body.transport,
        scan_user=body.username,
        entra_user="anonymous",
        status="queued",
        paths=body.paths,
        exclude_patterns=body.exclude_patterns,
        redacted=body.redact,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    _send_scan_task(
        str(scan.id), body.target_host, encrypted,
        body.paths, body.exclude_patterns, body.max_file_size_mb,
        body.redact, body.transport,
    )

    return scan


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    target: str | None = Query(default=None),
    db: Session = Depends(_get_db),
):
    query = db.query(ScanRecord)

    if status is not None:
        query = query.filter(ScanRecord.status == status)
    if target is not None:
        query = query.filter(ScanRecord.target_host.ilike(f"%{target}%"))

    total = query.count()
    scans = query.offset((page - 1) * per_page).limit(per_page).all()

    items = []
    for scan in scans:
        high = 0
        medium = 0
        low = 0
        for f in scan.findings:
            if f.severity == "high":
                high += 1
            elif f.severity == "medium":
                medium += 1
            elif f.severity == "low":
                low += 1
        summary = ScanSummary.model_validate(scan)
        summary.high_count = high
        summary.medium_count = medium
        summary.low_count = low
        items.append(summary)

    return ScanListResponse(items=items, total=total, page=page, per_page=per_page)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


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


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return Response(status_code=204)


@router.websocket("/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: uuid.UUID):
    # Get a DB session from the app's session factory
    try:
        session_factory = websocket.app.state.session_factory
        db = session_factory()
    except Exception:
        await websocket.close(code=4004, reason="Database unavailable")
        return

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
        try:
            await websocket.send_json({"phase": "completed"})
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
