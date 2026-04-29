import os
import stat
import ntpath
import fnmatch
import smbclient
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport, Credentials
from hawk_scan.scanner.readers import SCANNABLE_EXTENSIONS


class SmbTransport(Transport):
    def __init__(self, target_host: str, credentials: Credentials, timeout: int):
        self._host = target_host
        self._creds = credentials
        self._timeout = timeout
        self._registered = False

    def _ensure_session(self):
        if self._registered:
            return
        if self._creds.username and self._creds.password:
            smbclient.register_session(
                self._host,
                username=self._creds.username,
                password=self._creds.password,
            )
        self._registered = True

    @property
    def name(self) -> str:
        return "smb"

    def _unc(self, local_path: str) -> str:
        drive = local_path[0]
        rest = local_path[2:].replace("/", "\\")
        return f"\\\\{self._host}\\{drive}${rest}"

    def is_available(self) -> bool:
        try:
            self._ensure_session()
            smbclient.listdir(f"\\\\{self._host}\\C$")
            return True
        except Exception:
            return False

    def _walk_safe(self, unc_path: str, exclude_patterns: list[str], results: list[FileMetadata]):
        try:
            entries = list(smbclient.scandir(unc_path))
        except Exception:
            return

        dirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    full = ntpath.join(unc_path, entry.name)
                    if any(p in full for p in exclude_patterns if not p.startswith("*")):
                        continue
                    dirs.append(full)
                elif entry.is_file():
                    _, ext = os.path.splitext(entry.name)
                    if ext.lower() not in SCANNABLE_EXTENSIONS:
                        continue
                    if any(fnmatch.fnmatch(entry.name, p) for p in exclude_patterns if p.startswith("*")):
                        continue
                    full_path = ntpath.join(unc_path, entry.name)
                    try:
                        info = entry.stat()
                        size = info.st_size
                    except Exception:
                        size = 0
                    results.append(FileMetadata(
                        remote_path=full_path,
                        size_bytes=size,
                        extension=ext.lower(),
                    ))
            except Exception:
                continue

        for d in dirs:
            self._walk_safe(d, exclude_patterns, results)

    def enumerate(self, paths: list[str], exclude_patterns: list[str]) -> list[FileMetadata]:
        self._ensure_session()
        results = []
        for path in paths:
            unc = self._unc(path)
            self._walk_safe(unc, exclude_patterns, results)
        return results

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        self._ensure_session()
        filename = ntpath.basename(remote_path)
        local_path = os.path.join(local_dir, filename)
        try:
            with smbclient.open_file(remote_path, mode="rb") as remote_f:
                data = remote_f.read()
            with open(local_path, "wb") as local_f:
                local_f.write(data)
            return local_path
        except Exception:
            return None

    def detect_volumes(self) -> list[str]:
        self._ensure_session()
        volumes = []
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                smbclient.listdir(f"\\\\{self._host}\\{letter}$")
                volumes.append(f"{letter}:\\")
            except Exception:
                continue
        return volumes
