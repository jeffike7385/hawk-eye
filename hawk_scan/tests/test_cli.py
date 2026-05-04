import pytest
from hawk_scan.cli import build_parser


def test_parser_requires_target_or_local():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.target is None
    assert args.local is False


def test_parser_local_flag():
    parser = build_parser()
    args = parser.parse_args(["--local"])
    assert args.local is True
    assert args.target is None


def test_parser_local_transport():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--transport", "local"])
    assert args.transport == "local"


def test_parser_accepts_target():
    parser = build_parser()
    args = parser.parse_args(["WORKSTATION-01"])
    assert args.target == "WORKSTATION-01"


def test_parser_default_report_format():
    parser = build_parser()
    args = parser.parse_args(["WS-01"])
    assert args.report_format == "html"


def test_parser_json_report_format():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--report-format", "json"])
    assert args.report_format == "json"


def test_parser_custom_paths():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--paths", "C:\\Users\\jsmith", "D:\\Data"])
    assert args.paths == ["C:\\Users\\jsmith", "D:\\Data"]


def test_parser_credentials():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--username", "DOMAIN\\admin"])
    assert args.username == "DOMAIN\\admin"
    assert args.password is None


def test_parser_exclude():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--exclude", "*.log", "AppData"])
    assert args.exclude == ["*.log", "AppData"]


def test_parser_transport_force():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--transport", "smb"])
    assert args.transport == "smb"


def test_parser_max_file_size():
    parser = build_parser()
    args = parser.parse_args(["WS-01", "--max-file-size", "100"])
    assert args.max_file_size == 100


def test_parser_all_defaults():
    parser = build_parser()
    args = parser.parse_args(["WS-01"])
    assert args.redact is False
    assert args.debug is False
    assert args.config is None
    assert args.custom_fingerprints is None
    assert args.output == "."
    assert args.paths is None
    assert args.transport is None
    assert args.max_file_size == 50
