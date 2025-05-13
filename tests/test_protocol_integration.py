import pytest
from packet_sniffer_gui import SignatureDetector
from scapy.all import Ether, IP, TCP, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.dns  import DNS, DNSQR
from scapy.all import UDP
from scapy.layers.tls.all import TLS, TLSClientHello

@pytest.fixture(scope="module")
def detector():
    return SignatureDetector('signature_rules.json')

def test_full_http_packet(detector):
    http = HTTPRequest(Method=b'GET', Host=b'example.com', Path=b'/')
    pkt  = Ether()/IP(dst="1.2.3.4")/TCP(dport=80)/http/Raw(load=b"X-Test-Alert: 1")
    alerts = detector.inspect(pkt)
    assert any('Test HTTP Header' in a for a in alerts), alerts

def test_full_dns_packet(detector):
    dns = DNS(rd=1, qd=DNSQR(qname=b"malicious.example.com"))
    pkt = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)/dns
    alerts = detector.inspect(pkt)
    assert any('Suspicious DNS Query' in a for a in alerts), alerts

def test_full_tls_packet(detector):
    # Build just the ClientHello with SNI and invoke the helper
    ch = TLSClientHello()
    ext = type('E', (), {
        'name': 'server_name',
        'servernames': [ type('SN', (), {'servername': b'evil.example.com'})() ]
    })()
    ch.extensions = [ext]

    # Directly use the _inspect_tls path
    alerts = detector._inspect_tls(ch)
    assert any('Suspicious TLS SNI' in a for a in alerts), alerts
