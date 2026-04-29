import os
import fnmatch
import smbclient
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport, Credentials


class SmbTransport(Transport):
    def __init__(self, target_host: str, credentials: Credentials, timeout: int):
        self._host = target_host
        self._creds = credentials
        self._timeout = timeout
        if credentials.username and credentials.password:
            smbclient.ClientConfig(
                username=credentials.username,
                password=credentials.password,
            )

    @property
    def name(self) -> str:
        return "smb"

    def _unc(self, local_path: str) -> str:
        drive = local_path[0]
        rest = local_path[2:]
        return f"\\\\{self._host}\\{drive}${rest}"

    def is_available(self) -> bool:
        try:
            smbclient.listdir(f"\\\\{self._host}\\C$")
            return True
        except Exception:
            return False

    def enumerate(self, paths: list[str], exclude_patterns: list[str]) -> list[FileMetadata]:
        results = []
        for path in paths:
            unc = self._unc(path)
            try:
                for dirpath, dirnames, filenames in smbclient.walk(unc):
                    skip_dirs = []
                    for d in dirnames:
                        full = os.path.join(dirpath, d)
                        if any(p in full for p in exclude_patterns if not p.startswith("*")):
                            skip_dirs.append(d)
                    for d in skip_dirs:
                        dirnames.remove(d)

                    for filename in filenames:
                        if any(fnmatch.fnmatch(filename, p) for p in exclude_patterns if p.startswith("*")):
                            continue
                        full_path = os.path.join(dirpath, filename)
                        _, ext = os.path.splitext(filename)
                        try:
                            stat = smbclient.stat(full_path)
                            size = stat.st_size
                        except Exception:
                            size = 0
                        results.append(FileMetadata(
                            remote_path=full_path,
                            size_bytes=size,
                            extension=ext.lower(),
                        ))
            except Exception:
                continue
        return results

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        filename = os.path.basename(remote_path)
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
        volumes = []
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                smbclient.listdir(f"\\\\{self._host}\\{letter}$")
                volumes.append(f"{letter}:\\")
            except Exception:
                continue
        return volumes
