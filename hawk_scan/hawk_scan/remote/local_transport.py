import os
import fnmatch
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport
from hawk_scan.scanner.readers import SCANNABLE_EXTENSIONS


class LocalTransport(Transport):
    def __init__(self, debug: bool = False):
        self._debug = debug

    @property
    def name(self) -> str:
        return "local"

    @property
    def copies_files(self) -> bool:
        return False

    def is_available(self) -> bool:
        return True

    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]:
        results: list[FileMetadata] = []
        for root_path in paths:
            if self._debug:
                print(f"[DEBUG] Enumerating local path: {root_path}")
                print(f"[DEBUG] Exclude patterns: {exclude_patterns}")
            self._walk(root_path, exclude_patterns, results, progress_callback)
            if self._debug:
                print(f"[DEBUG] Found {len(results)} files so far")
        return results

    def _walk(self, root: str, exclude_patterns: list[str], results: list[FileMetadata], progress_callback=None):
        try:
            entries = os.scandir(root)
        except (PermissionError, OSError) as e:
            if self._debug:
                print(f"[DEBUG] scandir failed on {root}: {type(e).__name__}: {e}")
            return

        dirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    full = entry.path
                    if any(p in full for p in exclude_patterns if not p.startswith("*")):
                        continue
                    dirs.append(full)
                elif entry.is_file(follow_symlinks=False):
                    _, ext = os.path.splitext(entry.name)
                    if ext.lower() not in SCANNABLE_EXTENSIONS:
                        continue
                    if any(fnmatch.fnmatch(entry.name, p) for p in exclude_patterns if p.startswith("*")):
                        continue
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        size = 0
                    results.append(FileMetadata(
                        remote_path=entry.path,
                        size_bytes=size,
                        extension=ext.lower(),
                    ))
                    if progress_callback:
                        progress_callback(len(results), entry.name)
            except (PermissionError, OSError):
                continue

        for d in dirs:
            self._walk(d, exclude_patterns, results, progress_callback)

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        if not os.path.exists(remote_path):
            raise OSError(f"File not found: {remote_path}")
        return remote_path

    def detect_volumes(self) -> list[str]:
        volumes = []
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{letter}:\\"):
                volumes.append(f"{letter}:\\")
        return volumes
