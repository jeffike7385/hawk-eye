from abc import ABC, abstractmethod
from dataclasses import dataclass
from hawk_scan.models import FileMetadata


@dataclass
class Credentials:
    username: str | None = None
    password: str | None = None
    use_current_user: bool = False

    @classmethod
    def current_user(cls) -> "Credentials":
        return cls(use_current_user=True)


class Transport(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    def copies_files(self) -> bool:
        return True

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]: ...

    @abstractmethod
    def retrieve(self, remote_path: str, local_dir: str) -> str | None: ...

    @abstractmethod
    def detect_volumes(self) -> list[str]: ...


def _is_localhost(target_host: str) -> bool:
    import socket
    target_lower = target_host.lower().strip()
    if target_lower in ("localhost", "127.0.0.1", "::1", "."):
        return True
    try:
        local_hostname = socket.gethostname().lower()
        if target_lower == local_hostname:
            return True
        fqdn = socket.getfqdn().lower()
        if target_lower == fqdn:
            return True
    except Exception:
        pass
    return False


def negotiate_transport(
    target_host: str,
    credentials: Credentials,
    timeout: int,
    force_transport: str | None = None,
    debug: bool = False,
) -> Transport:
    from hawk_scan.remote.winrm_transport import WinRmTransport
    from hawk_scan.remote.smb_transport import SmbTransport
    from hawk_scan.remote.local_transport import LocalTransport

    if force_transport == "local":
        return LocalTransport(debug=debug)
    if force_transport == "smb":
        return SmbTransport(target_host, credentials, timeout, debug=debug)
    if force_transport == "winrm":
        return WinRmTransport(target_host, credentials, timeout, debug=debug)

    if _is_localhost(target_host):
        return LocalTransport(debug=debug)

    smb = SmbTransport(target_host, credentials, timeout, debug=debug)
    if smb.is_available():
        return smb
    winrm = WinRmTransport(target_host, credentials, timeout, debug=debug)
    if winrm.is_available():
        return winrm
    raise ConnectionError(
        f"Cannot reach {target_host} -- verify the machine is online, "
        "network accessible, and you have admin rights"
    )
