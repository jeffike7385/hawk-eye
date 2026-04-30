"""Scan CRUD routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response
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

# Will be wired up when Celery is available (Task 6).
run_scan_task = None


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

    if run_scan_task is not None:
        run_scan_task.delay(str(scan.id))

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


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: uuid.UUID, db: Session = Depends(_get_db)):
    scan = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return Response(status_code=204)
