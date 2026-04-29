import os
import base64
import winrm
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport, Credentials


class WinRmTransport(Transport):
    SMALL_FILE_LIMIT = 150_000

    def __init__(self, target_host: str, credentials: Credentials, timeout: int):
        self._host = target_host
        self._creds = credentials
        self._timeout = timeout
        self._session: winrm.Session | None = None

    @property
    def name(self) -> str:
        return "winrm"

    def _get_session(self) -> winrm.Session:
        if self._session is None:
            url = f"http://{self._host}:5985/wsman"
            if self._creds.use_current_user:
                self._session = winrm.Session(
                    url, auth=(None, None), transport="kerberos",
                    read_timeout_sec=self._timeout,
                    operation_timeout_sec=self._timeout,
                )
            else:
                self._session = winrm.Session(
                    url,
                    auth=(self._creds.username, self._creds.password),
                    transport="ntlm",
                    read_timeout_sec=self._timeout,
                    operation_timeout_sec=self._timeout,
                )
        return self._session

    def is_available(self) -> bool:
        try:
            session = self._get_session()
            result = session.run_ps("Write-Output 'OK'")
            return result.status_code == 0
        except Exception:
            return False

    def enumerate(self, paths: list[str], exclude_patterns: list[str]) -> list[FileMetadata]:
        session = self._get_session()
        results = []
        for path in paths:
            exclude_clauses = ""
            for pat in exclude_patterns:
                if pat.startswith("*"):
                    exclude_clauses += f" | Where-Object {{ $_.Name -notlike '{pat}' }}"
                else:
                    exclude_clauses += f" | Where-Object {{ $_.FullName -notlike '*{pat}*' }}"
            ps_script = (
                f"Get-ChildItem -Path '{path}' -Recurse -File -ErrorAction SilentlyContinue"
                f"{exclude_clauses}"
                " | ForEach-Object { \"$($_.FullName)|$($_.Length)|$($_.Extension)\" }"
            )
            try:
                result = session.run_ps(ps_script)
                if result.status_code != 0:
                    continue
                output = result.std_out.decode("utf-8", errors="replace").strip()
                for line in output.splitlines():
                    parts = line.strip().split("|")
                    if len(parts) == 3:
                        results.append(FileMetadata(
                            remote_path=parts[0],
                            size_bytes=int(parts[1]) if parts[1].isdigit() else 0,
                            extension=parts[2].lower(),
                        ))
            except Exception:
                continue
        return results

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        session = self._get_session()
        filename = os.path.basename(remote_path)
        local_path = os.path.join(local_dir, filename)
        try:
            ps_script = (
                f"[Convert]::ToBase64String("
                f"[System.IO.File]::ReadAllBytes('{remote_path}'))"
            )
            result = session.run_ps(ps_script)
            if result.status_code != 0:
                return None
            b64_data = result.std_out.decode("utf-8").strip()
            file_bytes = base64.b64decode(b64_data)
            with open(local_path, "wb") as f:
                f.write(file_bytes)
            return local_path
        except Exception:
            return None

    def detect_volumes(self) -> list[str]:
        session = self._get_session()
        try:
            ps_script = (
                "Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } "
                "| ForEach-Object { $_.DriveLetter }"
            )
            result = session.run_ps(ps_script)
            if result.status_code != 0:
                return ["C:\\"]
            letters = result.std_out.decode("utf-8").strip().splitlines()
            return [f"{l.strip()}:\\" for l in letters if l.strip()]
        except Exception:
            return ["C:\\"]
