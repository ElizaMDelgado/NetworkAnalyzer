import pytest
from packet_sniffer_gui import SignatureDetector
from scapy.layers.http import HTTPRequest
from scapy.all import IP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.tls.all import TLSClientHello

@pytest.fixture(scope="module")
def detector():
    # Load and compile all signature rules once
    return SignatureDetector('signature_rules.json')


class DummySNIExt:
    """
    Minimal dummy extension to mimic a TLS SNI extension
    """
    def __init__(self, servername_bytes):
        # Matches ext.name == 'server_name'
        self.name = 'server_name'
        # Create a simple object with a .servername attribute (bytes)
        SN = type('SN', (), {'servername': servername_bytes})
        self.servernames = [SN()]


def test_http_header_signature(detector):
    """
    Craft an HTTPRequest with a test header and ensure the 'Test HTTP Header' rule fires
    """
    pkt = HTTPRequest(Method=b'GET', Host=b'example.com', Path=b'/')
    # Scapy stores response headers in .Headers; mimic that for our test
    pkt.Headers = {'X-Test-Alert': '1'}
    alerts = detector.inspect(pkt)
    assert any('Test HTTP Header' in a for a in alerts), f"Expected Test HTTP Header alert, got: {alerts}"


def test_dns_query_signature(detector):
    """
    Craft a DNS query for malicious.example.com and ensure the corresponding rule fires
    """
    pkt = IP()/UDP()/DNS(rd=1, qd=DNSQR(qname=b"malicious.example.com"))
    alerts = detector.inspect(pkt)
    assert any('Suspicious DNS Query' in a for a in alerts), f"Expected Suspicious DNS Query alert, got: {alerts}"


def test_tls_sni_signature(detector):
    """
    Craft a minimal TLSClientHello with a SNI extension and ensure the 'Suspicious TLS SNI' rule fires
    """
    ch = TLSClientHello()
    ch.extensions = [DummySNIExt(b'evil.example.com')]
    alerts = detector.inspect(ch)
    assert any('Suspicious TLS SNI' in a for a in alerts), f"Expected Suspicious TLS SNI alert, got: {alerts}"


def test_raw_fallback_signature(detector):
    """
    Test that a raw payload matching the 'Test Raw' pattern is detected via the fallback path
    """
    pkt = Raw(load=b"RAWPAYLOAD123")
    alerts = detector.inspect(pkt)
    assert any('Test Raw' in a for a in alerts), f"Expected Test Raw alert, got: {alerts}"


def test_sql_injection_signature(detector):
    """
    Test raw fallback for SQL Injection patterns
    """
    pkt = Raw(load=b"UNION SELECT")
    alerts = detector.inspect(pkt)
    assert any('SQL Injection' in a for a in alerts), f"Expected SQL Injection alert, got: {alerts}"
