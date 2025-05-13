# tests/test_http_edge_cases.py
import pytest
from packet_sniffer_gui import SignatureDetector
from scapy.all import Ether, IP, TCP, Raw
from scapy.layers.http import HTTPRequest

@pytest.fixture(scope="module")
def detector():
    return SignatureDetector('signature_rules.json')

def test_multiline_http_header(detector):
    """
    Simulate a folded HTTP header (value split across lines)
    and verify the 'Test HTTP Header' rule still fires.
    """
    # Build an HTTPRequest layer
    http = HTTPRequest(Method=b'GET', Host=b'example.com', Path=b'/')
    # Raw payload contains a folded header:
    #   X-Test-Alert: 1
    #     continued
    raw_headers = (
        b"X-Test-Alert: 1\r\n"
        b"  continued\r\n"
        b"Another-Header: foo\r\n"
    )
    pkt = Ether()/IP(dst="1.2.3.4")/TCP(dport=80)/http/Raw(load=raw_headers)
    alerts = detector.inspect(pkt)
    assert any('Test HTTP Header' in a for a in alerts), f"No alerts from payload:\n{raw_headers}"
