import pytest
from hawk_scan.scanner.engine import ScanEngine


@pytest.fixture
def engine(simple_fingerprints):
    return ScanEngine(simple_fingerprints, redact=False)


@pytest.fixture
def redacting_engine(simple_fingerprints):
    return ScanEngine(simple_fingerprints, redact=True)


def test_engine_compiles_patterns(engine):
    assert len(engine._compiled) == 2
    assert "Email" in engine._compiled
    assert "SSN" in engine._compiled


def test_engine_finds_email(engine):
    results = engine.scan_text("contact john@example.com please")
    assert len(results) == 1
    assert results[0]["pattern_name"] == "Email"
    assert "john@example.com" in results[0]["matches"]
    assert results[0]["severity"] == "low"
    assert results[0]["category"] == "pii"


def test_engine_finds_ssn(engine):
    results = engine.scan_text("SSN: 123-45-6789")
    assert len(results) == 1
    assert results[0]["pattern_name"] == "SSN"
    assert "123-45-6789" in results[0]["matches"]
    assert results[0]["severity"] == "high"


def test_engine_finds_multiple_patterns(engine):
    results = engine.scan_text("john@example.com and SSN 123-45-6789")
    names = {r["pattern_name"] for r in results}
    assert names == {"Email", "SSN"}


def test_engine_no_matches(engine):
    results = engine.scan_text("nothing interesting here")
    assert results == []


def test_engine_deduplicates_matches(engine):
    results = engine.scan_text("john@example.com and john@example.com again")
    email_result = [r for r in results if r["pattern_name"] == "Email"][0]
    assert len(email_result["matches"]) == 1


def test_engine_sample_text_truncated(engine):
    long_text = "x" * 100 + " john@example.com"
    results = engine.scan_text(long_text)
    assert len(results[0]["sample_text"]) == 50


def test_engine_redaction(redacting_engine):
    results = redacting_engine.scan_text("john@example.com")
    match = results[0]["matches"][0]
    assert "***" in match or "*" in match
    assert match != "john@example.com"


def test_engine_redaction_sample_text(redacting_engine):
    results = redacting_engine.scan_text("john@example.com is here")
    assert "*" in results[0]["sample_text"]


def test_engine_empty_text(engine):
    results = engine.scan_text("")
    assert results == []


def test_engine_context_keywords():
    fingerprints = {
        "SSN": {
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "severity": "high",
            "category": "pii",
            "context_keywords": ["ssn", "social security", "tax"],
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    high_conf = engine.scan_text("SSN: 123-45-6789")
    assert high_conf[0]["confidence"] == "high"

    low_conf = engine.scan_text("code is 123-45-6789")
    assert low_conf[0]["confidence"] == "low"


def test_min_matches_filters_below_threshold():
    fingerprints = {
        "SSN": {
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "severity": "high",
            "category": "pii",
            "min_matches": 3,
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("SSN: 123-45-6789 and 234-56-7890")
    assert results == []


def test_min_matches_passes_at_threshold():
    fingerprints = {
        "SSN": {
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "severity": "high",
            "category": "pii",
            "min_matches": 3,
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("SSN: 123-45-6789 and 234-56-7890 and 345-67-8901")
    assert len(results) == 1
    assert results[0]["match_count"] == 3


def test_require_context_suppresses_without_keywords():
    fingerprints = {
        "Confidential": {
            "pattern": "(?i)\\bCONFIDENTIAL\\b",
            "severity": "high",
            "category": "classification",
            "context_keywords": ["classified", "handling"],
            "require_context": True,
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("This email is confidential")
    assert results == []

    results = engine.scan_text("CONFIDENTIAL — classified handling instructions")
    assert len(results) == 1
    assert results[0]["confidence"] == "high"


def test_proximity_context_keywords():
    fingerprints = {
        "SSN": {
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "severity": "high",
            "category": "pii",
            "context_keywords": ["ssn", "social security"],
            "context_distance": 50,
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    near = engine.scan_text("SSN: 123-45-6789")
    assert near[0]["confidence"] == "high"

    far = engine.scan_text("social security" + (" " * 200) + "123-45-6789")
    assert far[0]["confidence"] == "low"


def test_luhn_validator():
    fingerprints = {
        "CC": {
            "pattern": "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b",
            "severity": "high",
            "category": "pii",
            "validator": "luhn",
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    valid = engine.scan_text("card: 4532015112830366")
    assert len(valid) == 1

    invalid = engine.scan_text("number: 1234567890123456")
    assert invalid == []


def test_min_matches_defaults_to_one():
    fingerprints = {
        "Email": {
            "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
            "severity": "low",
            "category": "pii",
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("contact john@example.com")
    assert len(results) == 1


def test_compound_rule_requires_all():
    fingerprints = {
        "Bank Combo": {
            "severity": "high",
            "category": "pii",
            "require_all": {
                "routing": "\\b\\d{9}\\b",
                "account": "\\b\\d{10,17}\\b",
            },
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("routing: 021000021 account: 1234567890")
    assert len(results) == 1
    assert results[0]["pattern_name"] == "Bank Combo"
    assert any("routing" in m for m in results[0]["matches"])
    assert any("account" in m for m in results[0]["matches"])


def test_compound_rule_skips_when_partial():
    fingerprints = {
        "Bank Combo": {
            "severity": "high",
            "category": "pii",
            "require_all": {
                "routing": "\\b\\d{9}\\b",
                "account": "\\b\\d{10,17}\\b",
            },
        },
    }
    engine = ScanEngine(fingerprints, redact=False)
    results = engine.scan_text("routing: 021000021 but no account number here")
    assert results == []


def test_compound_rule_with_redaction():
    fingerprints = {
        "Bank Combo": {
            "severity": "high",
            "category": "pii",
            "require_all": {
                "routing": "\\b\\d{9}\\b",
                "account": "\\b\\d{10,17}\\b",
            },
        },
    }
    engine = ScanEngine(fingerprints, redact=True)
    results = engine.scan_text("routing: 021000021 account: 1234567890")
    assert len(results) == 1
    assert any("*" in m for m in results[0]["matches"])
