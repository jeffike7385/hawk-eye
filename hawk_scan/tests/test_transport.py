import pytest
from unittest.mock import MagicMock, patch
from hawk_scan.remote.transport import Transport, Credentials, negotiate_transport
from hawk_scan.remote.smb_transport import SmbTransport
from hawk_scan.remote.winrm_transport import WinRmTransport


def test_credentials_from_current_user():
    creds = Credentials.current_user()
    assert creds.username is None
    assert creds.password is None
    assert creds.use_current_user is True


def test_credentials_explicit():
    creds = Credentials(username="DOMAIN\\admin", password="secret")
    assert creds.username == "DOMAIN\\admin"
    assert creds.use_current_user is False


def test_transport_is_abstract():
    with pytest.raises(TypeError):
        Transport()


def test_smb_transport_implements_interface():
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert isinstance(transport, Transport)
    assert transport.name == "smb"


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_is_available_success(mock_smb):
    mock_smb.listdir.return_value = ["Users", "Windows"]
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert transport.is_available() is True
    mock_smb.listdir.assert_called_once()


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_is_available_failure(mock_smb):
    mock_smb.listdir.side_effect = Exception("Connection refused")
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert transport.is_available() is False


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_enumerate(mock_smb):
    mock_smb.walk.return_value = [
        ("\\\\WS-01\\C$\\Users\\jsmith", ["Documents"], ["resume.docx"]),
        ("\\\\WS-01\\C$\\Users\\jsmith\\Documents", [], ["notes.txt"]),
    ]
    def mock_stat(path, **kwargs):
        m = MagicMock()
        m.st_size = 1024
        return m
    mock_smb.stat.side_effect = mock_stat

    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    files = list(transport.enumerate(
        paths=["C:\\Users\\jsmith"],
        exclude_patterns=[]
    ))
    assert len(files) == 2


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_enumerate_excludes_patterns(mock_smb):
    mock_smb.walk.return_value = [
        ("\\\\WS-01\\C$\\Users\\jsmith", [], ["resume.docx", "debug.log"]),
    ]
    def mock_stat(path, **kwargs):
        m = MagicMock()
        m.st_size = 1024
        return m
    mock_smb.stat.side_effect = mock_stat

    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    files = list(transport.enumerate(
        paths=["C:\\Users\\jsmith"],
        exclude_patterns=["*.log"]
    ))
    assert len(files) == 1
    assert files[0].extension == ".docx"


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_retrieve(mock_smb, tmp_scan_dir):
    mock_file = MagicMock()
    mock_file.read.return_value = b"file content"
    mock_smb.open_file.return_value.__enter__ = MagicMock(return_value=mock_file)
    mock_smb.open_file.return_value.__exit__ = MagicMock(return_value=False)

    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    local_path = transport.retrieve(
        remote_path="C:\\Users\\jsmith\\doc.txt",
        local_dir=tmp_scan_dir
    )
    assert local_path is not None


@patch("hawk_scan.remote.smb_transport.smbclient")
def test_smb_detect_volumes(mock_smb):
    def listdir_side_effect(path):
        if "C$" in path or "D$" in path:
            return ["dir"]
        raise Exception("Not found")
    mock_smb.listdir.side_effect = listdir_side_effect
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = SmbTransport(target_host="WS-01", credentials=creds, timeout=30)
    volumes = transport.detect_volumes()
    assert "C:\\" in volumes
    assert "D:\\" in volumes
    assert len(volumes) == 2


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_transport_implements_interface(mock_winrm):
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert isinstance(transport, Transport)
    assert transport.name == "winrm"


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_is_available_success(mock_winrm):
    mock_session = MagicMock()
    mock_session.run_ps.return_value = MagicMock(status_code=0, std_out=b"OK")
    mock_winrm.Session.return_value = mock_session
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert transport.is_available() is True


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_is_available_failure(mock_winrm):
    mock_winrm.Session.side_effect = Exception("Connection refused")
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    assert transport.is_available() is False


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_enumerate(mock_winrm):
    ps_output = (
        'C:\\Users\\jsmith\\resume.docx|1024|.docx\n'
        'C:\\Users\\jsmith\\notes.txt|512|.txt\n'
    )
    mock_session = MagicMock()
    mock_session.run_ps.return_value = MagicMock(
        status_code=0, std_out=ps_output.encode()
    )
    mock_winrm.Session.return_value = mock_session
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    files = list(transport.enumerate(
        paths=["C:\\Users\\jsmith"],
        exclude_patterns=[]
    ))
    assert len(files) == 2
    assert files[0].remote_path == "C:\\Users\\jsmith\\resume.docx"
    assert files[0].size_bytes == 1024


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_retrieve_small_file(mock_winrm):
    import base64
    content = b"hello world"
    b64 = base64.b64encode(content).decode()
    mock_session = MagicMock()
    mock_session.run_ps.return_value = MagicMock(
        status_code=0, std_out=b64.encode()
    )
    mock_winrm.Session.return_value = mock_session
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        local = transport.retrieve("C:\\Users\\jsmith\\test.txt", d)
        assert local is not None
        with open(local, "rb") as f:
            assert f.read() == content


@patch("hawk_scan.remote.winrm_transport.winrm")
def test_winrm_detect_volumes(mock_winrm):
    mock_session = MagicMock()
    mock_session.run_ps.return_value = MagicMock(
        status_code=0, std_out=b"C\nD\n"
    )
    mock_winrm.Session.return_value = mock_session
    creds = Credentials(username="DOMAIN\\admin", password="pass")
    transport = WinRmTransport(target_host="WS-01", credentials=creds, timeout=30)
    volumes = transport.detect_volumes()
    assert "C:\\" in volumes
    assert "D:\\" in volumes
