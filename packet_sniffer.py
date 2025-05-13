import argparse  # For parsing command-line arguments
import csv       # For writing captured packet data to CSV
import platform  # To detect operating system

from scapy.all import sniff, Ether, wrpcap, get_if_hwaddr, get_if_list
from scapy.layers.inet import IP, TCP
from mac_vendor_lookup import MacLookup  # To lookup vendor information for MAC addresses

# Platform-specific get_windows_if_list to avoid winreg import errors
if platform.system() == "Windows":
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        # winreg not available, fallback to empty list
        get_windows_if_list = lambda: []
else:
    # On non-Windows, use the generic get_if_list
    get_windows_if_list = lambda: get_if_list()

# Buffer for reassembling TCP flows: keys are tuples (src_ip, src_port, dst_ip, dst_port)
tcp_reassembly_buffer = {}

# Lists to store captured packets and CSV rows
captured_packets = []
csv_data = []

def list_physical_interfaces():
    """Return only the 'Ethernet' and 'Wi-Fi' interface names."""
    result = []
    for entry in get_windows_if_list():
        # scapy may return dicts or strings
        if isinstance(entry, dict):
            name = entry.get('name', '')
        else:
            name = entry
        # Filter to only Ethernet or Wi-Fi
        if name in ("Ethernet", "Wi-Fi"):
            result.append(name)
    return result


def prompt_for_interface(interface_list, input_fn=input, print_fn=print):
    """Ask the user to choose one interface by index."""
    while True:
        print_fn("Available adapters:")
        for idx, name in enumerate(interface_list):
            print_fn(f"  [{idx}] {name}")
        try:
            response = input_fn("Select adapter number: ").strip()
        except EOFError:
            # Handle cases like piped input
            print_fn("No response; defaulting to [0].")
            return interface_list[0]
        if response == "":
            print_fn("Empty response; defaulting to [0].")
            return interface_list[0]
        token = response.split()[0]
        if not token.isdigit():
            print_fn(f"Invalid input '{response}'; enter a number.")
            continue
        choice = int(token)
        if 0 <= choice < len(interface_list):
            return interface_list[choice]
        print_fn(f"Out of range; enter 0 through {len(interface_list)-1}.")


def process_packet(packet, local_mac, vendor_lookup):
    """
    Process each captured packet:
      - Decode Ethernet, IP, and TCP layers
      - Print formatted summary
      - Store key data for CSV output
      - Reassemble TCP payloads
    """
    # Only process Ethernet frames
    if Ether not in packet:
        return

    eth = packet[Ether]
    source_mac = eth.src.upper()
    dest_mac = eth.dst.upper()
    ethertype = eth.type
    # Map common EtherTypes to human-readable
    ethertype_str = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6"
    }.get(ethertype, hex(ethertype))

    # Determine recipient description
    if dest_mac == local_mac:
        recipient = "this machine"
    elif dest_mac == "FF:FF:FF:FF:FF:FF":
        recipient = "broadcast"
    else:
        try:
            vendor = vendor_lookup.lookup(dest_mac)
        except Exception:
            vendor = "unknown"
        recipient = f"{dest_mac} ({vendor})"

    # Print Ethernet layer summary
    print("┌─ Ethernet Layer ─────────────────────")
    print(f"│ Source MAC      : {source_mac}")
    print(f"│ Destination MAC : {dest_mac}")
    print(f"│ Type            : {ethertype_str}")
    print(f"│ Recipient       : {recipient}")

    # Initialize variables for CSV
    proto_name = ""
    src_ip = dst_ip = src_port = dst_port = ""

    # Process IP layer if present
    if IP in packet:
        ip = packet[IP]
        protocol = ip.proto
        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, str(protocol))

        src_ip = ip.src
        dst_ip = ip.dst

        print("├─ IPv4 Layer ─────────────────────────")
        print(f"│ Source IP      : {src_ip}")
        print(f"│ Destination IP : {dst_ip}")
        print(f"│ Protocol       : {proto_name}")
        print(f"│ TTL            : {ip.ttl}")
        print(f"│ Total Length   : {ip.len}")

        # If TCP, handle ports, flags, and reassembly
        if protocol == 6 and packet.haslayer(TCP):
            tcp_segment = packet[TCP]
            flags = tcp_segment.sprintf("%flags%")
            payload = bytes(tcp_segment.payload)

            src_port = tcp_segment.sport
            dst_port = tcp_segment.dport

            print("├─ TCP Layer ──────────────────────────")
            print(f"│ Source Port      : {src_port}")
            print(f"│ Destination Port : {dst_port}")
            print(f"│ Flags            : {flags}")

            # Reassemble TCP payloads for flow tracking
            if payload:
                flow_key = (src_ip, src_port, dst_ip, dst_port)
                tcp_reassembly_buffer.setdefault(flow_key, []).append((tcp_segment.seq, payload))
                segments = sorted(tcp_reassembly_buffer[flow_key], key=lambda x: x[0])
                full_stream = b"".join(chunk for _, chunk in segments)
                print(f"│ Reassembled {len(full_stream)} bytes for flow {flow_key}")
                dump_payload(full_stream[:32])
        else:
            # Non-TCP payload preview
            raw_data = bytes(eth.payload)
            if raw_data:
                print("├─ Payload Preview (32 bytes) ─────────")
                dump_payload(raw_data[:32])
    else:
        # No IP layer, show raw Ethernet payload
        raw_data = bytes(eth.payload)
        if raw_data:
            print("├─ Payload Preview (32 bytes) ─────────")
            dump_payload(raw_data[:32])

    print("└──────────────────────────────────────\n")

    # Append captured info for CSV
    csv_data.append([
        packet.time,
        src_ip,
        dst_ip,
        proto_name,
        src_port,
        dst_port,
        len(packet)
    ])


def dump_payload(data: bytes):
    """Print a hex and ASCII preview of up to 32 bytes of payload data."""
    length = min(32, len(data))
    hex_str = " ".join(f"{b:02x}" for b in data[:length])
    ascii_str = "".join((chr(b) if 32 <= b < 127 else ".") for b in data[:length])
    print(f"│ HEX   : {hex_str}")
    print(f"│ ASCII : {ascii_str}")


def main():
    """Parse arguments, select interface, sniff packets, and save outputs."""
    parser = argparse.ArgumentParser(description="Packet Sniffer with PCAP and CSV Export")
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="captured_traffic.pcap",
        help="Output PCAP file name (default: captured_traffic.pcap)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run basic tests instead of sniffing"
    )
    args = parser.parse_args()

    # Run tests if --test flag is used
    if args.test:
        _run_tests()
        return

    # Discover available physical interfaces
    interfaces = list_physical_interfaces()
    if not interfaces:
        print("Error: no Ethernet/Wi-Fi adapters found.")
        return

    # Prompt user to select one
    selected_interface = prompt_for_interface(interfaces)
    print(f"\n→ Sniffing on {selected_interface}...\n")

    # Get local MAC and initialize vendor lookup
    local_mac = get_if_hwaddr(selected_interface).upper()
    vendor_lookup = MacLookup()

    try:
        # Start sniffing packets, processing each with process_packet
        packets = sniff(
            iface=selected_interface,
            prn=lambda pkt: process_packet(pkt, local_mac, vendor_lookup),
            store=True,
            promisc=True
        )
        captured_packets.extend(packets)
    except KeyboardInterrupt:
        print("\n→ Capture stopped by user.")

    # Write captured packets to PCAP file
    wrpcap(args.output, captured_packets)
    print(f"\n→ Packets saved to {args.output}")

    # Write CSV summary
    csv_file = "captured_traffic.csv"
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Length"])
        writer.writerows(csv_data)
    print(f"→ Packet data saved to {csv_file}")


def _run_tests():
    """Basic tests for helper functions to ensure correct behavior."""
    print("Running tests...")
    # Test list_physical_interfaces returns a list
    interfaces = list_physical_interfaces()
    assert isinstance(interfaces, list), "list_physical_interfaces should return a list"
    print("list_physical_interfaces() ->", interfaces or "[]")

    # Additional test: simulate interface list and verify filtering
    global get_windows_if_list
    orig = get_windows_if_list
    get_windows_if_list = lambda: [{'name':'Ethernet'},{'name':'Wi-Fi'},{'name':'Other'}]
    interfaces2 = list_physical_interfaces()
    assert interfaces2 == ['Ethernet','Wi-Fi'], "Should only include Ethernet and Wi-Fi"
    print("list_physical_interfaces filter ->", interfaces2)

    # Test get_windows_if_list raw fallback
    raw_list = get_windows_if_list()
    assert isinstance(raw_list, list), "get_windows_if_list should return a list"
    print("get_windows_if_list raw ->", raw_list)

    # Restore original get_windows_if_list
    get_windows_if_list = orig
    print("All tests passed.")

if __name__ == "__main__":
    main()
