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
