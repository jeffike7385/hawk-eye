import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, ForeignKey, JSON,
    TypeDecorator, event,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, relationship

RETENTION_DAYS_DEFAULT = 90


class UUIDType(TypeDecorator):
    """UUID column that stores as native UUID on PostgreSQL and as String(36) on SQLite."""

    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value  # psycopg2 handles UUID objects natively
        # SQLite: store as string
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
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

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
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

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUIDType, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String, nullable=False)
    reason = Column(String, nullable=False)

    scan = relationship("ScanRecord", back_populates="skipped_files")
