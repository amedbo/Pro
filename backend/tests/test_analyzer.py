import pytest
from backend.app.analyzer import classify_indicator_value

def test_classify_indicator_value():
    """
    Tests the helper function that classifies a string value into a specific IOC type.
    """
    # Test valid IOCs
    assert classify_indicator_value("8.8.8.8") == "ipv4"
    assert classify_indicator_value("google.com") == "domain"
    assert classify_indicator_value("https://example.com/path") == "url"
    assert classify_indicator_value("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2") == "file_hash_sha256"

    # Test invalid or unknown values
    assert classify_indicator_value("not an ioc") == "unknown"
    assert classify_indicator_value("123.456.789.10") == "unknown" # Invalid IP
    assert classify_indicator_value("just.a.string") == "domain" # This is a valid domain technically
    assert classify_indicator_value("http:/invalid-url") == "unknown"

# Note: Testing the functions that use the ML models directly (extract_iocs_with_ner, classify_threat)
# is difficult in a fast unit test because they are slow and require downloading models.
# The standalone execution in `analyzer.py` serves as a functional test for those.
