import os
import re
import yaml
import pytest


@pytest.fixture
def default_fingerprints():
    fp_path = os.path.join(os.path.dirname(__file__), "..", "fingerprints", "default.yml")
    with open(fp_path, "r") as f:
        return yaml.safe_load(f)


def test_default_fingerprints_has_us_pii(default_fingerprints):
    names = set(default_fingerprints.keys())
    assert "SSN" in names
    assert "Email" in names
    assert "US Phone Number" in names
    assert "Credit Card Number" in names


def test_default_fingerprints_has_azure_secrets(default_fingerprints):
    names = set(default_fingerprints.keys())
    assert "Azure Storage Account Key" in names
    assert "Azure SAS Token" in names
    assert "Azure AD Client Secret" in names


def test_default_fingerprints_has_m365_secrets(default_fingerprints):
    names = set(default_fingerprints.keys())
    assert "Azure DevOps PAT" in names


def test_all_patterns_compile(default_fingerprints):
    for name, fp in default_fingerprints.items():
        pattern = fp["pattern"] if isinstance(fp, dict) else fp
        try:
            re.compile(pattern)
        except re.error as e:
            pytest.fail(f"Pattern '{name}' failed to compile: {e}")


def test_all_patterns_have_severity(default_fingerprints):
    for name, fp in default_fingerprints.items():
        assert isinstance(fp, dict), f"Pattern '{name}' must be a dict with severity"
        assert "severity" in fp, f"Pattern '{name}' missing severity"
        assert fp["severity"] in ("high", "medium", "low"), f"Pattern '{name}' has invalid severity"


def test_all_patterns_have_category(default_fingerprints):
    for name, fp in default_fingerprints.items():
        assert "category" in fp, f"Pattern '{name}' missing category"


def test_ssn_pattern_matches(default_fingerprints):
    pattern = re.compile(default_fingerprints["SSN"]["pattern"])
    assert pattern.search("SSN: 123-45-6789")


def test_email_pattern_matches(default_fingerprints):
    pattern = re.compile(default_fingerprints["Email"]["pattern"], re.IGNORECASE)
    assert pattern.search("user@example.com")
    assert pattern.search("no-email-here") is None
