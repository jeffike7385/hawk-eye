import os
import threading
from hawk_scan.models import FileMetadata, Finding, SkippedFile
from hawk_scan.remote.transport import Transport
from hawk_scan.scanner.engine import ScanEngine
from hawk_scan.scanner.readers import read_file

PER_FILE_TIMEOUT = 10
SELF_LIMITING_EXTENSIONS = {".pdf"}


class ScanOrchestrator:
    def __init__(self, transport: Transport, engine: ScanEngine, max_file_size_mb: int = 50, debug: bool = False):
        self._transport = transport
        self._engine = engine
        self._max_bytes = max_file_size_mb * 1024 * 1024
        self._debug = debug

    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]:
        return self._transport.enumerate(paths, exclude_patterns, progress_callback=progress_callback)

    def scan(self, file_list: list[FileMetadata], temp_dir: str, progress_callback=None) -> tuple[list[Finding], list[SkippedFile]]:
        findings: list[Finding] = []
        skipped: list[SkippedFile] = []
        for meta in file_list:
            if progress_callback:
                progress_callback(meta.remote_path)
            if meta.size_bytes > self._max_bytes:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason=f"File size ({meta.size_bytes // (1024*1024)}MB) exceeds limit"))
                continue
            try:
                local_path = self._transport.retrieve(meta.remote_path, temp_dir)
            except Exception as e:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason=str(e)))
                continue
            if local_path is None:
                skipped.append(SkippedFile(file_path=meta.remote_path, reason="Failed to retrieve file"))
                continue
            try:
                result_holder: list = [None, None, None]
                def _read_and_scan(path=local_path):
                    try:
                        result_holder[0] = read_file(path)
                        result_holder[1] = self._engine.scan_text(result_holder[0])
                    except Exception as exc:
                        result_holder[2] = exc
                t = threading.Thread(target=_read_and_scan)
                t.daemon = True
                t.start()
                timeout = None if meta.extension in SELF_LIMITING_EXTENSIONS else PER_FILE_TIMEOUT
                t.join(timeout=timeout)
                if t.is_alive():
                    skipped.append(SkippedFile(file_path=meta.remote_path, reason=f"Timed out after {PER_FILE_TIMEOUT}s"))
                    continue
                if result_holder[2] is not None:
                    skipped.append(SkippedFile(file_path=meta.remote_path, reason=f"Error reading file: {result_holder[2]}"))
                    continue
                for result in (result_holder[1] or []):
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

    def run(self, paths: list[str], exclude_patterns: list[str], temp_dir: str, progress_callback=None) -> tuple[list[Finding], list[SkippedFile]]:
        file_list = self.enumerate(paths, exclude_patterns)
        return self.scan(file_list, temp_dir, progress_callback)
