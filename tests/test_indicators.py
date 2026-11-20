import pytest

from services.normalization import (
    detect_indicator, normalize_domain, normalize_url, validate_hash
)
from services.scoring import calculate_score, classify_score


def test_indicator_detection():
    assert detect_indicator("8.8.8.8") == "ip"
    assert detect_indicator("https://example.com/path") == "url"
    assert detect_indicator("a" * 64) == "sha256"
    assert detect_indicator("a" * 40) == "sha1"
    assert detect_indicator("a" * 32) == "md5"
    assert detect_indicator("example.com") == "domain"


def test_normalizers_reject_invalid_values():
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_url("https://example.com/path").startswith("https://")
    with pytest.raises(ValueError):
        normalize_domain("not a domain")
    with pytest.raises(ValueError):
        normalize_url("javascript:alert(1)")
    with pytest.raises(ValueError):
        validate_hash("not-a-hash")


def test_risk_scoring_levels():
    assert classify_score(0) == "CLEAN"
    assert classify_score(16) == "LOW"
    assert classify_score(31) == "MEDIUM"
    assert classify_score(51) == "HIGH"
    assert classify_score(76) == "CRITICAL"
    assert classify_score(999) == "CRITICAL"
    assert 0 <= calculate_score(malicious=20, suspicious=20, multi_source=True) <= 100
