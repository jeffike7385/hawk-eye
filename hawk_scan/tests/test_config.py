import os
import pytest
import yaml
from hawk_scan.config import load_config, load_fingerprints, merge_fingerprints


def test_load_config_from_file(tmp_scan_dir):
    config_path = os.path.join(tmp_scan_dir, "config.yml")
    with open(config_path, "w") as f:
        yaml.dump({
            "default_paths": ["C:\\Users"],
            "exclude_patterns": ["AppData"],
            "report": {"format": "html", "output_dir": ".\\reports", "redact": False},
        }, f)
    config = load_config(config_path)
    assert config["default_paths"] == ["C:\\Users"]
    assert config["exclude_patterns"] == ["AppData"]
    assert config["report"]["format"] == "html"


def test_load_config_returns_defaults_when_no_file():
    config = load_config(None)
    assert "C:\\Users" in config["default_paths"]
    assert "AppData" in config["exclude_patterns"]
    assert config["report"]["format"] == "html"


def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yml")


def test_load_fingerprints_from_yaml(tmp_scan_dir):
    fp_path = os.path.join(tmp_scan_dir, "fingerprints.yml")
    with open(fp_path, "w") as f:
        yaml.dump({
            "SSN": {
                "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                "severity": "high",
                "category": "pii",
            }
        }, f)
    fps = load_fingerprints(fp_path)
    assert "SSN" in fps
    assert fps["SSN"]["severity"] == "high"
    assert fps["SSN"]["category"] == "pii"


def test_load_fingerprints_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_fingerprints("/nonexistent/fingerprints.yml")


def test_merge_fingerprints_custom_overrides_default():
    default = {
        "SSN": {"pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "severity": "high", "category": "pii"},
        "Email": {"pattern": "\\b[^@]+@[^@]+\\b", "severity": "low", "category": "pii"},
    }
    custom = {
        "SSN": {"pattern": "\\b\\d{9}\\b", "severity": "high", "category": "pii"},
        "Member ID": {"pattern": "\\bMID-\\d{8}\\b", "severity": "medium", "category": "custom"},
    }
    merged = merge_fingerprints(default, custom)
    assert merged["SSN"]["pattern"] == "\\b\\d{9}\\b"
    assert "Email" in merged
    assert "Member ID" in merged
    assert len(merged) == 3


def test_merge_fingerprints_empty_custom():
    default = {"Email": {"pattern": "x", "severity": "low", "category": "pii"}}
    merged = merge_fingerprints(default, {})
    assert merged == default


def test_merge_fingerprints_none_custom():
    default = {"Email": {"pattern": "x", "severity": "low", "category": "pii"}}
    merged = merge_fingerprints(default, None)
    assert merged == default
