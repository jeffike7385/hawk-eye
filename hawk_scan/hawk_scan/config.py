import os
import yaml

DEFAULT_CONFIG = {
    "default_paths": ["C:\\Users"],
    "exclude_patterns": [
        "AppData", "node_modules", ".git", "\\Windows",
        "\\Program Files", "\\Program Files (x86)",
        "$Recycle.Bin", "\\ProgramData",
    ],
    "report": {
        "format": "html",
        "output_dir": ".",
        "redact": False,
    },
    "max_file_size_mb": 50,
    "timeout_seconds": 30,
}


def load_config(config_path: str | None) -> dict:
    if config_path is None:
        return dict(DEFAULT_CONFIG)
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r") as f:
        user_config = yaml.safe_load(f) or {}
    merged = dict(DEFAULT_CONFIG)
    merged.update(user_config)
    if "report" in user_config:
        merged["report"] = {**DEFAULT_CONFIG["report"], **user_config["report"]}
    return merged


def load_fingerprints(fingerprint_path: str) -> dict:
    if not os.path.exists(fingerprint_path):
        raise FileNotFoundError(f"Fingerprint file not found: {fingerprint_path}")
    with open(fingerprint_path, "r") as f:
        return yaml.safe_load(f) or {}


def merge_fingerprints(default: dict, custom: dict | None) -> dict:
    if not custom:
        return dict(default)
    merged = dict(default)
    merged.update(custom)
    return merged
