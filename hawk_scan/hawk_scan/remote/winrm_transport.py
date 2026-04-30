import os
import sys
import base64
import uuid
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from hawk_scan.models import FileMetadata
from hawk_scan.remote.transport import Transport, Credentials
from hawk_scan.scanner.readers import SCANNABLE_EXTENSIONS


class WinRmTransport(Transport):

    def __init__(self, target_host: str, credentials: Credentials, timeout: int, debug: bool = False):
        self._host = target_host
        self._creds = credentials
        self._timeout = timeout
        self._debug = debug
        self._wsman: WSMan | None = None
        self._pool: RunspacePool | None = None

    @property
    def name(self) -> str:
        return "winrm"

    def _get_pool(self) -> RunspacePool:
        if self._pool is None:
            kwargs = {
                "server": self._host,
                "port": 5985,
                "ssl": False,
                "connection_timeout": self._timeout,
                "read_timeout": self._timeout + 10,
            }
            if self._creds.use_current_user:
                kwargs["auth"] = "negotiate"
                kwargs["negotiate_delegate"] = True
            else:
                kwargs["auth"] = "ntlm"
                kwargs["username"] = self._creds.username
                kwargs["password"] = self._creds.password
            if self._debug:
                print(f"[DEBUG] WinRM: connecting to {self._host}:5985 (auth={kwargs['auth']})", file=sys.stderr)
            self._wsman = WSMan(**kwargs)
            self._pool = RunspacePool(self._wsman)
            self._pool.open()
        return self._pool

    def _run_ps(self, script: str) -> tuple[list, list, bool]:
        pool = self._get_pool()
        ps = PowerShell(pool)
        ps.add_script(script)
        output = ps.invoke()
        had_errors = ps.had_errors
        streams_err = [str(e) for e in ps.streams.error]
        return output, streams_err, had_errors

    def is_available(self) -> bool:
        try:
            if self._debug:
                print(f"[DEBUG] WinRM: testing {self._host}:5985", file=sys.stderr)
            output, errors, had_errors = self._run_ps("Write-Output 'OK'")
            if self._debug and had_errors:
                print(f"[DEBUG] WinRM: test errors: {errors}", file=sys.stderr)
            return not had_errors and len(output) > 0 and str(output[0]) == "OK"
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] WinRM: not available — {type(e).__name__}: {e}", file=sys.stderr)
            return False

    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]:
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
                output, errors, had_errors = self._run_ps(ps_script)
                if had_errors and self._debug:
                    print(f"[DEBUG] WinRM enumerate errors for {path}: {errors}", file=sys.stderr)
                for item in output:
                    line = str(item).strip()
                    parts = line.split("|")
                    if len(parts) == 3:
                        ext = parts[2].lower()
                        if ext not in SCANNABLE_EXTENSIONS:
                            continue
                        results.append(FileMetadata(
                            remote_path=parts[0],
                            size_bytes=int(parts[1]) if parts[1].isdigit() else 0,
                            extension=ext,
                        ))
                        if progress_callback:
                            progress_callback(len(results), parts[0])
            except Exception as e:
                if self._debug:
                    print(f"[DEBUG] WinRM enumerate error for {path}: {type(e).__name__}: {e}", file=sys.stderr)
                continue
        return results

    def retrieve(self, remote_path: str, local_dir: str) -> str | None:
        _, ext = os.path.splitext(remote_path)
        local_path = os.path.join(local_dir, f"{uuid.uuid4().hex}{ext}")
        ps_script = (
            f"[Convert]::ToBase64String("
            f"[System.IO.File]::ReadAllBytes('{remote_path}'))"
        )
        try:
            output, errors, had_errors = self._run_ps(ps_script)
            if had_errors or not output:
                err_msg = "; ".join(errors) if errors else "unknown error"
                if self._debug:
                    print(f"[DEBUG] WinRM retrieve failed for {remote_path}: {err_msg}", file=sys.stderr)
                raise OSError(f"WinRM read failed: {err_msg}")
            b64_data = str(output[0]).strip()
            file_bytes = base64.b64decode(b64_data)
            with open(local_path, "wb") as f:
                f.write(file_bytes)
            return local_path
        except OSError:
            raise
        except Exception as e:
            if self._debug:
                print(f"[DEBUG] WinRM retrieve failed for {remote_path}: {type(e).__name__}: {e}", file=sys.stderr)
            raise OSError(f"WinRM read failed: {type(e).__name__}: {e}") from e

    def detect_volumes(self) -> list[str]:
        try:
            output, _, had_errors = self._run_ps(
                "Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } "
                "| ForEach-Object { $_.DriveLetter }"
            )
            if had_errors or not output:
                return ["C:\\"]
            return [f"{str(l).strip()}:\\" for l in output if str(l).strip()]
        except Exception:
            return ["C:\\"]

    def __del__(self):
        try:
            if self._pool:
                self._pool.close()
        except Exception:
            pass
