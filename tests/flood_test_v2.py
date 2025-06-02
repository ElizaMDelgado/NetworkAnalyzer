from scapy.all import IP, TCP, send
import random
import time

packets = []
for _ in range(20000):
    dst_port = random.randint(1024, 65535)
    pkt = IP(dst="10.0.10.74") / TCP(dport=dst_port)  # Your local IP
    packets.append(pkt)

send(packets, inter=0.0002)
print("Excessive Packet Injection Complete.")



