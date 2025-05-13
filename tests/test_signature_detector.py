# tests/test_signature_detector.py
import pytest
from packet_sniffer_gui import SignatureDetector

# Map each rule-name to a sample payload that should match
SAMPLES = {
    "SQL Injection":        "UNION SELECT",
    "XSS Attempt":          "<script>alert(1)</script>",
    "Suspicious User-Agent": "sqlmap",
    "Suspicious DNS Query": "malicious.example.com",
    "Suspicious TLS SNI":   "evil.example.com",
    "Test HTTP Header":     "X-Test-Alert",
    "Test DNS Query":       "badtest.local",
    "Test TLS SNI":         "sni-test.example",
    "Test Raw":             "RAWPAYLOAD123",
}

@pytest.fixture(scope="module")
def detector():
    # loads signature_rules.json and compiles everything
    return SignatureDetector('signature_rules.json')

@pytest.mark.parametrize("rule_name,payload", SAMPLES.items())
def test_rule_triggers(detector, rule_name, payload):
    alerts = detector._match_signatures(payload)
    assert any(rule_name in alert for alert in alerts), (
        f"Rule '{rule_name}' did not fire on sample payload: {payload}"
    )

