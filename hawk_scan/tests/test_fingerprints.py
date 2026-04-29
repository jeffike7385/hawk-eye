import os
import re
import yaml
import pytest


@pytest.fixture
def default_fingerprints():
    fp_path = os.path.join(os.path.dirname(__file__), "..", "fingerprints", "default.yml")
    with open(fp_path, "r") as f:
        return yaml.safe_load(f)


def test_default_fingerprints_has_pii(default_fingerprints):
    names = set(default_fingerprints.keys())
    assert "SSN" in names
    assert "Email" in names
    assert "Credit Card Number" in names


def test_default_fingerprints_has_classifications(default_fingerprints):
    names = set(default_fingerprints.keys())
    assert "Classification - Confidential" in names
    assert "Classification - Secret" in names
    assert "Classification - Internal Use Only" in names


def test_default_fingerprints_has_compound_rules(default_fingerprints):
    bank = default_fingerprints["Bank Account with Routing Number"]
    assert "require_all" in bank
    assert "routing_number" in bank["require_all"]
    assert "account_number" in bank["require_all"]


def test_all_patterns_compile(default_fingerprints):
    for name, fp in default_fingerprints.items():
        if "pattern" in fp:
            try:
                re.compile(fp["pattern"])
            except re.error as e:
                pytest.fail(f"Pattern '{name}' failed to compile: {e}")
        elif "require_all" in fp:
            for part_name, part_pattern in fp["require_all"].items():
                try:
                    re.compile(part_pattern)
                except re.error as e:
                    pytest.fail(f"Pattern '{name}.{part_name}' failed to compile: {e}")


def test_all_patterns_have_severity(default_fingerprints):
    for name, fp in default_fingerprints.items():
        assert isinstance(fp, dict), f"Pattern '{name}' must be a dict"
        assert "severity" in fp, f"Pattern '{name}' missing severity"
        assert fp["severity"] in ("high", "medium", "low"), f"Pattern '{name}' has invalid severity"


def test_all_patterns_have_category(default_fingerprints):
    for name, fp in default_fingerprints.items():
        assert "category" in fp, f"Pattern '{name}' missing category"


def test_pii_patterns_have_min_matches(default_fingerprints):
    assert default_fingerprints["SSN"]["min_matches"] == 3
    assert default_fingerprints["Credit Card Number"]["min_matches"] == 10
    assert default_fingerprints["Driver License"]["min_matches"] == 10
    assert default_fingerprints["Email"]["min_matches"] == 10


def test_ssn_pattern_matches(default_fingerprints):
    pattern = re.compile(default_fingerprints["SSN"]["pattern"])
    assert pattern.search("SSN: 123-45-6789")


def test_email_pattern_matches(default_fingerprints):
    pattern = re.compile(default_fingerprints["Email"]["pattern"], re.IGNORECASE)
    assert pattern.search("user@example.com")
    assert pattern.search("no-email-here") is None
