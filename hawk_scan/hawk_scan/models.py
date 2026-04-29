# hawk_scan/hawk_scan/models.py
from dataclasses import dataclass, field
from collections import Counter


@dataclass
class FileMetadata:
    remote_path: str
    size_bytes: int
    extension: str
    owner: str | None = None
    modified_time: str | None = None


@dataclass
class Finding:
    file_path: str
    pattern_name: str
    category: str
    severity: str
    matches: list[str]
    match_count: int
    sample_text: str
    file_owner: str | None = None
    file_modified: str | None = None


@dataclass
class SkippedFile:
    file_path: str
    reason: str


@dataclass
class ScanResult:
    target_host: str
    transport_method: str
    scan_user: str
    start_time: str
    end_time: str
    duration_seconds: float
    total_files_scanned: int
    total_files_skipped: int
    findings: list[Finding]
    skipped_files: list[SkippedFile]


@dataclass
class ScanReport:
    result: ScanResult

    def severity_summary(self) -> dict[str, int]:
        return dict(Counter(f.severity for f in self.result.findings))

    def category_summary(self) -> dict[str, int]:
        return dict(Counter(f.category for f in self.result.findings))
