import os
from hawk_scan.models import FileMetadata, Finding, SkippedFile
from hawk_scan.remote.transport import Transport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.readers import read_file


class ScanOrchestrator:
    def __init__(self, transport: Transport, engine: ScanEngine, max_file_size_mb: int = 50, debug: bool = False):
        self._transport = transport
        self._engine = engine
        self._max_bytes = max_file_size_mb * 1024 * 1024
        self._debug = debug

    def run(self, paths: list[str], exclude_patterns: list[str], temp_dir: str, progress_callback=None) -> tuple[list[Finding], list[SkippedFile]]:
        findings: list[Finding] = []
        skipped: list[SkippedFile] = []
        file_list = self._transport.enumerate(paths, exclude_patterns)
        for meta in file_list:
            if progress_callback:
                progress_callback(meta.remote_path)
            if meta.size_bytes > self._max_bytes:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason=f"File size ({meta.size_bytes // (1024*1024)}MB) exceeds limit"))
                continue
            local_path = self._transport.retrieve(meta.remote_path, temp_dir)
            if local_path is None:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason="Failed to retrieve file (locked or permission denied)"))
                continue
            try:
                content = read_file(local_path)
                results = self._engine.scan_text(content)
                for result in results:
                    findings.append(Finding(
                        file_path=meta.remote_path,
                        pattern_name=result["pattern_name"],
                        category=result["category"],
                        severity=result["severity"],
                        matches=result["matches"],
                        match_count=result["match_count"],
                        sample_text=result["sample_text"],
                        file_owner=meta.owner,
                        file_modified=meta.modified_time,
                    ))
            except Exception as e:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason=f"Error reading file: {e}"))
            finally:
                try:
                    if local_path and os.path.exists(local_path):
                        os.remove(local_path)
                except OSError:
                    pass
        return findings, skipped
