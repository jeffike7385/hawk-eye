import os
import pytest
from hawk_scan.web.config import Settings


def test_settings_defaults():
    s = Settings(secret_key="test")
    assert s.retention_days == 90
    assert s.max_concurrent_scans == 3
    assert s.session_ttl_hours == 8


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("HAWKSCAN_RETENTION_DAYS", "30")
    monkeypatch.setenv("HAWKSCAN_SECRET_KEY", "test-key")
    s = Settings()
    assert s.retention_days == 30
    assert s.secret_key == "test-key"


def test_settings_database_url_default():
    s = Settings(secret_key="test")
    assert "asyncpg" in s.database_url
    assert "hawkscan" in s.database_url
