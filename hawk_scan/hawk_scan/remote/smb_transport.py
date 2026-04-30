import os
import sys
import stat
import ntpath
import fnmatch
import smbclient
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport, Credentials
from hawk_scan.scanner.readers import SCANNABLE_EXTENSIONS

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
CLOUD_STUB_ATTRS = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN

PROFILE_JUNCTIONS = frozenset({
    "Application Data", "Cookies", "Local Settings", "My Documents",
    "NetHood", "PrintHood", "Recent", "SendTo", "Start Menu", "Templates",
    "My Music", "My Pictures", "My Videos", "Default User",
})


class SmbTransport(Transport):
    def __init__(self, target_host: str, credentials: Credentials, timeout: int, debug: bool = False):
        self._host = target_host
        self._creds = credentials
        self._timeout = timeout
        self._debug = debug
        self._registered = False

    def _ensure_session(self):
        if self._registered:
            return
        if self._creds.username and self._creds.password:
            if self._debug:
                print(f"[DEBUG] Registering SMB session for {self._creds.username}@{self._host}", file=sys.stderr)
            smbclient.register_session(
                self._host,
                username=self._creds.username,
                password=self._creds.password,
            )
        else:
            if self._debug:
                print(f"[DEBUG] No explicit credentials, using implicit auth for {self._host}", file=sys.stderr)
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

    def _walk_safe(self, unc_path: str, exclude_patterns: list[str], results: list[FileMetadata], progress_callback=None):
        try:
            entries = list(smbclient.scandir(unc_path))
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] scandir failed on {unc_path}: {type(e).__name__}: {e}", file=sys.stderr)
            return

        dirs = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name in PROFILE_JUNCTIONS:
                        continue
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
                        if self._debug:
                            attrs = getattr(info, "st_file_attributes", 0) or 0
                            if attrs & CLOUD_STUB_ATTRS:
                                print(f"[DEBUG] Cloud-attributed file (may be stub): {full_path} (attrs=0x{attrs:X})", file=sys.stderr)
                    except Exception:
                        size = 0
                    results.append(FileMetadata(
                        remote_path=full_path,
                        size_bytes=size,
                        extension=ext.lower(),
                    ))
                    if progress_callback:
                        progress_callback(len(results), entry.name)
            except Exception:
                continue

        for d in dirs:
            self._walk_safe(d, exclude_patterns, results, progress_callback)

    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]:
        self._ensure_session()
        results = []
        for path in paths:
            unc = self._unc(path)
            if self._debug:
                print(f"[DEBUG] Enumerating: {path} -> {unc}", file=sys.stderr)
                print(f"[DEBUG] Exclude patterns: {exclude_patterns}", file=sys.stderr)
            self._walk_safe(unc, exclude_patterns, results, progress_callback)
            if self._debug:
                print(f"[DEBUG] Found {len(results)} files so far", file=sys.stderr)
        return results

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        import uuid
        self._ensure_session()
        filename = ntpath.basename(remote_path)
        _, ext = os.path.splitext(filename)
        local_path = os.path.join(local_dir, f"{uuid.uuid4().hex}{ext}")
        try:
            with smbclient.open_file(remote_path, mode="rb") as remote_f:
                data = remote_f.read()
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] SMB retrieve failed for {remote_path}: {type(e).__name__}: {e}", file=sys.stderr)
            err_str = str(e)
            if "0xc000cf01" in err_str:
                raise OSError("Cloud file not synced (STATUS_CLOUD_FILE_PROVIDER_NOT_RUNNING)") from e
            if "0xc000cf1d" in err_str:
                raise OSError("Cloud file provider terminated (STATUS_CLOUD_FILE_PROVIDER_TERMINATED)") from e
            if "0xc0000022" in err_str:
                raise OSError("Access denied") from e
            raise OSError(f"SMB read failed: {type(e).__name__}: {e}") from e
        with open(local_path, "wb") as local_f:
            local_f.write(data)
        return local_path

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
