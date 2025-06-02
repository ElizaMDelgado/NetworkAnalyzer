
from scapy.all import Ether, IP, TCP, sendp

dst_ip = "10.0.10.74"  # Your local IP
packet = Ether()/IP(dst=dst_ip)/TCP(dport=80)

while True:
    sendp(packet, verbose=False)
