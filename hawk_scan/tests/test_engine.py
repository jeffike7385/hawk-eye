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
