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

    @abstractmethod
    def is_available(self) -> bool: ...

    @abstractmethod
    def enumerate(self, paths: list[str], exclude_patterns: list[str], progress_callback=None) -> list[FileMetadata]: ...

    @abstractmethod
    def retrieve(self, remote_path: str, local_dir: str) -> str | None: ...

    @abstractmethod
    def detect_volumes(self) -> list[str]: ...


def negotiate_transport(
    target_host: str,
    credentials: Credentials,
    timeout: int,
    force_transport: str | None = None,
    debug: bool = False,
) -> Transport:
    from hawk_scan.remote.winrm_transport import WinRmTransport
    from hawk_scan.remote.smb_transport import SmbTransport

    if force_transport == "smb":
        return SmbTransport(target_host, credentials, timeout, debug=debug)
    if force_transport == "winrm":
        return WinRmTransport(target_host, credentials, timeout, debug=debug)

    winrm = WinRmTransport(target_host, credentials, timeout, debug=debug)
    if winrm.is_available():
        return winrm
    smb = SmbTransport(target_host, credentials, timeout, debug=debug)
    if smb.is_available():
        return smb
    raise ConnectionError(
        f"Cannot reach {target_host} -- verify the machine is online, "
        "network accessible, and you have admin rights"
    )
