# tests/test_additional_edge_cases.py
import pytest
from packet_sniffer_gui import SignatureDetector
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, fragment
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from hypothesis import given, strategies as st

@pytest.fixture(scope="module")
def detector():
    return SignatureDetector('signature_rules.json')


def test_ipv6_dns_query(detector):
    """
    Ensure DNS rule fires over IPv6/UDP/Ethernet.
    """
    pkt = Ether()/IPv6(dst="2001:4860:4860::8888")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=b"malicious.example.com"))
    alerts = detector.inspect(pkt)
    assert any('Suspicious DNS Query' in a for a in alerts), alerts


def test_ftp_command_injection(detector):
    """
    Simulate an FTP USER command carrying SQL injection.
    """
    payload = b"USER admin; DROP TABLE users;\r\n"
    pkt = Ether()/IP(dst="192.0.2.50")/TCP(dport=21)/Raw(load=payload)
    alerts = detector.inspect(pkt)
    assert any('SQL Injection' in a for a in alerts), alerts


def test_smtp_header_injection(detector):
    """
    Simulate SMTP DATA block with XSS in the Subject header.
    """
    data = (
        b"From: user@example.com\r\n"
        b"Subject: <script>alert(1)</script>\r\n"
        b"\r\n"
    )
    pkt = Ether()/IP(dst="198.51.100.5")/TCP(dport=25)/Raw(load=data)
    alerts = detector.inspect(pkt)
    assert any('XSS Attempt' in a for a in alerts), alerts


def test_fragmented_sql_injection(detector):
    """
    Fragment a UDP packet with SQL payload, then reassemble and test detection.
    """
    payload = b"UNION SELECT"
    full = IP(dst="203.0.113.1")/UDP(dport=9999)/Raw(load=payload)
    frags = fragment(full, fragsize=8)
    # Manually reassemble the payload bytes
    combined = b"".join([bytes(frag[Raw].load) for frag in frags if Raw in frag])
    pkt_reassembled = Raw(load=combined)
    alerts = detector.inspect(pkt_reassembled)
    assert any('SQL Injection' in a for a in alerts), alerts


@given(st.binary(min_size=0, max_size=256))
def test_inspect_no_crash(detector, random_data):
    """
    Property-based fuzz: random bytes should not crash inspect(), and returns a list.
    """
    pkt = Raw(load=random_data)
    out = detector.inspect(pkt)
    assert isinstance(out, list)
