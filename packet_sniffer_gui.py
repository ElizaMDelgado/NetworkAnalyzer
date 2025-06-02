import os
import json
import re
import math
import threading
import queue
import argparse
import csv
import platform
import time
import sys
import datetime
import requests
from collections import defaultdict
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.tls.all import TLSClientHello
from scapy.all import rdpcap, sniff, Ether, wrpcap, get_if_hwaddr, get_if_list, hexdump, load_layer
from scapy.arch.windows import get_windows_if_list
from mac_vendor_lookup import MacLookup

import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Setup Scapy HTTP
load_layer("http")


from scapy.all          import (
    sniff, Ether, IP, TCP, wrpcap,
    get_if_hwaddr, get_if_list, hexdump
)
from scapy.arch.windows import get_windows_if_list
from mac_vendor_lookup import MacLookup

# Optional charting
try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure          import Figure
except ImportError:
    FigureCanvasTkAgg = Figure = None
    print("[WARN] matplotlib missing—charts disabled")
    
def list_physical_interfaces():
    """
    Return only the 'Ethernet' and 'Wi-Fi' adapter names.
    Works on Windows (via get_windows_if_list) or any OS via get_if_list().
    """
    # try Windows list first, fall back to generic
    try:
        raw = get_windows_if_list()
    except NameError:
        raw = get_if_list()

    results = []
    for entry in raw:
        # Windows entries may be dicts; others are strs
        name = entry.get('name', entry) if isinstance(entry, dict) else entry
        if name in ('Ethernet', 'Wi-Fi'):
            results.append(name)
    return results

def build_iface_map():
    """
    Map friendly Windows names (e.g. 'Ethernet','Wi-Fi')
    to Scapy's NPF device strings (\\Device\\NPF_{...}).
    """
    win_ifaces = get_windows_if_list()  # dicts with 'name' & 'guid'
    npf_ifaces = get_if_list()          # strings like '\\Device\\NPF_{...}'
    mapping = {}

    for win in win_ifaces:
        name = win.get('name', str(win))
        guid = win.get('guid', '').upper()
        if guid:
            # match by GUID
            for dev in npf_ifaces:
                if guid in dev.upper():
                    mapping[name] = dev
                    break
        else:
            # fallback: substring of friendly name
            simple = name.replace(' ', '').upper()
            for dev in npf_ifaces:
                if simple in dev.upper():
                    mapping[name] = dev
                    break
    return mapping

class GeoIPResolver:
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        # Skip local/private IPs
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172.") or ip.startswith("127.") or ip.startswith("::1"):
            self.cache[ip] = "Local Network"
            return "Local Network"

        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                loc = f"{data.get('city', '')}, {data.get('country', '')}".strip(', ')
                self.cache[ip] = loc or "Unknown"
                return self.cache[ip]
        except Exception:
            pass

        self.cache[ip] = "Unknown"
        return "Unknown"

# ── Signature-Based Detection ──
class SignatureDetector:
    def __init__(self, rule_file):
        self.rule_file = rule_file
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, rule_file)
        try:
            data = json.load(open(path))
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
            print(f"[WARN] Could not load signature rules from {path}")
        self.rules = [
            {
                'name': e.get('name', 'Unnamed Rule'),
                'regex': re.compile(e['pattern'], re.IGNORECASE),
                'category': e.get('category', 'Uncategorized'),
                'severity': e.get('severity', 'Medium')
            }
            for e in data
        ]
        self.enabled_categories = { r['category'] for r in self.rules }


    def inspect(self, pkt):
        alerts = []
        
        # ── HTTP Inspection ──
        if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
            alerts.extend(self._inspect_http(pkt))

        # ── DNS Inspection ──
        if pkt.haslayer(DNSQR) or pkt.haslayer(DNSRR):
            alerts.extend(self._inspect_dns(pkt))

        # ── TLS Inspection ──
        if pkt.haslayer(TLSClientHello):
            alerts.extend(self._inspect_tls(pkt))

        # ── Fallback to Raw ──
        elif pkt.haslayer('Raw'):
            try:
                text = pkt['Raw'].load.decode(errors='ignore')
            except Exception:
                text = ''
            alerts.extend(self._match_signatures(text))

        return alerts
    
    def _inspect_http(self, pkt):
        """
        Pulls HTTP request‐line, headers, and small bodies for signature matching.
        """
        parts = []
        
        # ---- HTTP Request ----
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            # Method, Host, Path
            try:
                parts.append(req.Method.decode())
                parts.append(req.Host.decode())
                parts.append(req.Path.decode())
            except Exception:
                pass

            # All headers
            hdrs = getattr(req, 'Headers', {})
            for h, v in hdrs.items():
                parts.append(f"{h}: {v}")

            # Include body if present
            if pkt.haslayer('Raw'):
                try:
                    parts.append(pkt['Raw'].load.decode(errors='ignore'))
                except Exception:
                    pass

        # ---- HTTP Response ----
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            # Status code
            parts.append(str(resp.Status_Code))

            # Headers
            hdrs = getattr(resp, 'Headers', {})
            for h, v in hdrs.items():
                parts.append(f"{h}: {v}")

            # Body (e.g. small HTML snippets)
            if pkt.haslayer('Raw'):
                try:
                    parts.append(pkt['Raw'].load.decode(errors='ignore'))
                except Exception:
                    pass

        # Run the combined text through your regex rules
        return self._match_signatures("\n".join(parts))

    def _inspect_dns(self, pkt):
        """
        Extracts DNS query names and resource data for matching.
        """
        parts = []

        # Query section
        if pkt.haslayer(DNSQR):
            try:
                parts.append(pkt[DNSQR].qname.decode(errors='ignore'))
            except Exception:
                pass

        # Answer / resource record section
        if pkt.haslayer(DNSRR):
            rdata = pkt[DNSRR].rdata
            if isinstance(rdata, bytes):
                try:
                    parts.append(rdata.decode(errors='ignore'))
                except Exception:
                    pass
            else:
                parts.append(str(rdata))

        return self._match_signatures(" ".join(parts))

    def _inspect_tls(self, pkt):
        """
        Pulls the SNI (Server Name Indication) from a TLS ClientHello.
        """
        ch = pkt[TLSClientHello]
        # TLSClientHello.extensions is a list of objects with .name and .servernames
        for ext in getattr(ch, 'extensions', []):
            if getattr(ext, 'name', '') == 'server_name':
                # ext.servernames is a list; take the first one
                try:
                    sni = ext.servernames[0].servername.decode(errors='ignore')
                    return self._match_signatures(sni)
                except Exception:
                    break

        # No SNI found
        return []

    def _match_signatures(self, text):
        matches = []
        for rule in self.rules:
            # skip rules whose category is not currently enabled
            if rule['category'] not in self.enabled_categories:
                continue

            if rule['regex'].search(text):
                alert = (
                    f"[{rule['severity'].upper()}] Signature match: {rule['name']} "
                    f"(Category: {rule['category']})"
                )
                matches.append(alert)

        return matches

    def load_rules(self):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, self.rule_file)
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
            print(f"[WARN] Could not load signature rules from {path}")
        self.rules = []
        for entry in data:
            try:
                compiled = re.compile(entry['pattern'], re.IGNORECASE)
                self.rules.append({
                    'name': entry.get('name', 'Unnamed Rule'),
                    'regex': compiled,
                    'category': entry.get('category', 'Uncategorized'),
                    'severity': entry.get('severity', 'Medium')
                })
            except re.error as err:
                print(f"[ERROR] Invalid regex '{entry.get('pattern')}': {err}")

    def reload_rules(self):
        self.load_rules()
        self.enabled_categories = { r['category'] for r in self.rules }
        print("[INFO] Signature rules reloaded.")
    
    def set_enabled_categories(self, categories):
        """
        GUI calls this to turn categories on/off.
        Pass in a list or set of the category names to ENABLE.
        """
        self.enabled_categories = set(categories)
        
# ── Anomaly-Based Alerts ──
class AnomalyDetector:
    def __init__(self, threshold_sigma=3, min_samples=30):
        self.n           = 0
        self.mean        = 0.0
        self.M2          = 0.0
        self.threshold   = threshold_sigma
        self.min_samples = min_samples

    def update(self, value):
        self.n    += 1
        delta   = value - self.mean
        self.mean += delta / self.n
        self.M2   += delta * (value - self.mean)

    def stddev(self):
        return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0

    def inspect(self, pkt):
        length = len(pkt)
        alerts = []
        if self.n >= self.min_samples:
            σ = self.stddev()
            if σ > 0 and abs(length - self.mean) > self.threshold * σ:
               alerts.append(
               f"Anomaly: packet size {length} B is >{self.threshold}x "
               f"from mean ({self.mean:.1f}±{σ:.1f})"
            )

        self.update(length)
        return alerts

# ── Alert Manager ──
class AlertManager:
    def __init__(self, gui=None):
        self.gui = gui

    def notify(self, msg, severity="INFO"):
        line = f"[{severity}] {msg}\n"
        print(line, end='')
        if self.gui:
            self.gui.alert_text.configure(state='normal')
            self.gui.alert_text.insert('end', line)
            self.gui.alert_text.configure(state='disabled')
            self.gui.alert_text.see('end')

# Globals
packet_queue     = queue.Queue()
stop_sniff_event = threading.Event()
csv_data         = []
gui_packets      = []

sig_det  = SignatureDetector('signature_rules.json')
anom_det = AnomalyDetector()
alerts   = AlertManager()  # will be re-bound to GUI below


def process_packet_gui(packet, local_mac, gui, vendor_lookup=None):
    """
    Lightweight packet processing - just extract essential data and queue it.
    Heavy processing is done in background thread.
    """
    if Ether not in packet:
        return
    
    # Quick timestamp extraction
    dt = datetime.datetime.fromtimestamp(float(packet.time))
    ts = dt.strftime("%H:%M:%S.%f")[:-3]  # Only time, not full date for display
    
    # Quick protocol detection
    proto = src = dst = sport = dport = ""
    length = len(packet)
    
    # Simplified protocol extraction
    if ARP in packet:
        arp = packet[ARP]
        proto = "ARP"
        src = arp.psrc
        dst = arp.pdst
    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        proto = {6:'TCP', 17:'UDP', 58:'ICMPv6'}.get(ipv6.nh, str(ipv6.nh))
        src, dst = ipv6.src, ipv6.dst
        if proto == 'TCP' and packet.haslayer(TCP):
            tcp = packet[TCP]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 'UDP' and packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = udp.sport, udp.dport
    elif IP in packet:
        ip = packet[IP]
        proto = {1:'ICMP', 6:'TCP', 17:'UDP'}.get(ip.proto, str(ip.proto))
        src, dst = ip.src, ip.dst
        if proto == 'TCP' and packet.haslayer(TCP):
            tcp = packet[TCP]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 'UDP' and packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = udp.sport, udp.dport

    # Create lightweight packet data for GUI
    packet_data = {
        'timestamp': ts,
        'src': src,
        'dst': dst,
        'protocol': proto,
        'sport': sport,
        'dport': dport,
        'length': length,
        'raw_packet': packet  # Keep reference for detailed analysis
    }
    
    # Queue for GUI processing (non-blocking)
    try:
        packet_queue.put_nowait(packet_data)
    except queue.Full:
        # Drop packets if queue is full to prevent memory issues
        pass
    
    # Queue for background analysis (separate queue)
    try:
        gui.analysis_queue.put_nowait(packet)
    except queue.Full:
        pass

class SnifferApp(ctk.CTk):
    MAX_PACKETS = 500  # Limit memory usage and improve GUI responsiveness
    
    def __init__(self, interface, pcap_file, csv_file):
        super().__init__()
        self.sessions = defaultdict(list)
        
        # Define constants FIRST, before using them
        self.MAX_QUEUE_SIZE = 2000  # Move this line up here
        
        self.interface = interface
        self.pcap_file = pcap_file
        self.csv_file = csv_file
        self.vendor = MacLookup()
        self.local_mac = get_if_hwaddr(interface).upper() 
        self.geoip = GeoIPResolver()
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.byte_rate_history = []
        
        self.memory_check_counter = 0

        # ── Theme setup ──
        self.theme_var = ctk.StringVar(value='Light')  # Set default theme
        ctk.set_appearance_mode(self.theme_var.get())
        ctk.set_default_color_theme('blue')


        # ── DEFINE YOUR FONTS HERE ──
        self.text_font   = ctk.CTkFont(size=14)
        self.header_font = ctk.CTkFont(size=18, weight="bold")

        # Ttk style for treeview headings and rows (uses the fonts you just defined)
        style = ttk.Style(self)
        style.configure("Treeview.Heading", font=("Arial", 30, "bold"))
        style.configure("Treeview",         font=("Arial", 14))
        style.configure("Treeview",         rowheight=30)

        # load signature & anomaly detectors
        self.sig_det = SignatureDetector('signature_rules.json')
        self.anom_det = AnomalyDetector()
        self.alerts = AlertManager(gui=self)

        # packet buffers & stats
        self.all_packets = []
        self.bytes_per_src = {}
        self.total_bytes = 0
        self.bytes_last = 0

        # Filters
        self.capture_filter_var = ctk.StringVar()
        self.display_filter_var = ctk.StringVar()
        self.display_filter_var.trace_add('write', self.apply_display_filter)

        # Build UI
        self.title("Packet Sniffer Dashboard")
        self.geometry('1200x800')
        self._build_capture_controls()
        self._build_paned_view()
        self._build_alerts_panel()

        # Start loops
        self.after(300, self.poll_queue)
        self.after(1000, self.update_bandwidth_metrics)
        self.after(5000, self.update_protocol_chart)

        self.last_tree_index = 0
        self.mac_vendor_cache = {}
        
        # Initialize queues AFTER MAX_QUEUE_SIZE is defined
        global packet_queue
        packet_queue = queue.Queue(maxsize=self.MAX_QUEUE_SIZE)
        
        # Separate queue for background analysis
        self.analysis_queue = queue.Queue(maxsize=1000)  # Limit queue size
        self.analysis_results_queue = queue.Queue(maxsize=500)
        
        # Background analysis thread
        self.analysis_thread = threading.Thread(target=self._background_analysis_worker, daemon=True)
        self.analysis_thread.start()
        
        # Start background analysis results polling
        self.after(200, self.poll_analysis_results)
    
    def reconstruct_stream(self, key):
        """Reconstruct payload stream for a given TCP session key."""
        packets = self.sessions.get(key, [])
        if not packets:
            return b""
        # Sort by sequence number and concatenate payloads
        packets.sort()
        return b''.join(bytes(payload) for _, payload in packets if bytes(payload))

    
    def _background_analysis_worker(self):
        """
        Background thread that runs signature and anomaly detection
        on packets received in the analysis_queue.
        """
        while True:
            try:
                pkt = self.analysis_queue.get(timeout=1)
                sig_alerts = self.sig_det.inspect(pkt)
                anom_alerts = self.anom_det.inspect(pkt)
                for msg in sig_alerts:
                    self.analysis_results_queue.put(("HIGH", msg))
                for msg in anom_alerts:
                    self.analysis_results_queue.put(("MEDIUM", msg))
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ERROR] in analysis worker: {e}")

    def poll_analysis_results(self):
        """
        Periodically checks for results from background analysis
        and pushes them to the alert system.
        """
        try:
            while True:
                severity, msg = self.analysis_results_queue.get_nowait()
                self.alerts.notify(msg, severity)
        except queue.Empty:
            pass
        self.after(300, self.poll_analysis_results)

    
    def _memory_cleanup(self):
        """
        Periodic memory cleanup to prevent memory leaks
        """
        # Clean up old GeoIP cache entries
        if len(self.geoip.cache) > 1000:
            # Keep only the 500 most recent entries
            items = list(self.geoip.cache.items())
            self.geoip.cache = dict(items[-500:])
        
        # Clean up MAC vendor cache
        if len(self.mac_vendor_cache) > 500:
            items = list(self.mac_vendor_cache.items())
            self.mac_vendor_cache = dict(items[-250:])
        
        # Clean up top talkers if too many
        if len(self.bytes_per_src) > 200:
            # Keep only top 100 talkers
            sorted_talkers = sorted(self.bytes_per_src.items(), key=lambda x: x[1], reverse=True)
            self.bytes_per_src = dict(sorted_talkers[:100])
        
        # Clean up rate history
        if len(self.byte_rate_history) > 60:  # Keep last 60 seconds
            self.byte_rate_history = self.byte_rate_history[-30:]
            
    def _build_capture_controls(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=0, column=0, sticky='ew', padx=10, pady=5)

                # ─── Dark Mode Switch ───
        self.dark_mode_var = ctk.BooleanVar(value=False)

        def toggle_theme():
            mode = 'Dark' if self.dark_mode_var.get() else 'Light'
            ctk.set_appearance_mode(mode)

        theme_switch = ctk.CTkSwitch(
            frame, text='Dark Mode',
            variable=self.dark_mode_var,
            command=toggle_theme
        )
        theme_switch.grid(row=0, column=9, padx=5)

    
        # Configure grid columns and rows
        for col in range(0, 10):  # allow space for extra buttons
            frame.grid_columnconfigure(col, weight=0)
        frame.grid_columnconfigure(10, weight=1)  # final spacer column
        frame.grid_rowconfigure(1, weight=0)      # allow row 1 for buttons

        # ─── Column 0: Controller dropdown ───
        iface_map = build_iface_map()
        self.iface_var = ctk.StringVar(value=self.interface)
        vals = list(iface_map.keys())
        self.iface_menu = ctk.CTkOptionMenu(
            frame,
            values=vals,
            variable=self.iface_var,
            font=self.text_font,
            width=120,
            dynamic_resizing=False
        )
        self.iface_menu.grid(row=0, column=0, padx=5)

        # ─── Column 1 & 2: BPF filter label + entry ───
        ctk.CTkLabel(frame, text="BPF Filter:", font=self.text_font)\
            .grid(row=0, column=1, padx=(10, 2), sticky='e')
        ctk.CTkEntry(
            frame,
            placeholder_text='e.g. tcp port 80',
            textvariable=self.capture_filter_var,
            width=150,
            font=self.text_font
        ).grid(row=0, column=2, padx=(2, 10))

        # ─── Column 3 & 4: Display filter label + entry ───
        ctk.CTkLabel(frame, text="Display Filter:", font=self.text_font)\
            .grid(row=0, column=3, padx=(10, 2), sticky='e')
        ctk.CTkEntry(
            frame,
            placeholder_text='e.g. http',
            textvariable=self.display_filter_var,
            width=150,
            font=self.text_font
        ).grid(row=0, column=4, padx=(2, 10))

        # ─── Column 5: Start / Stop ───
        self.start_btn = ctk.CTkButton(
            frame, text="Start", command=self.start_capture,
            width=80, height=28, font=self.text_font
        )
        self.start_btn.grid(row=0, column=5, padx=5)

        self.stop_btn = ctk.CTkButton(
            frame, text="Stop", command=self.stop_capture,
            state="disabled", width=80, height=28, font=self.text_font
        )
        self.stop_btn.grid(row=0, column=6, padx=5)

        # ─── Row 0 Buttons (column 7+) ───
        row0_buttons = [
            ('Categories…',  self.open_category_window),
            ('Reload Rules', self.reload_rules)
        ]

        # ─── Row 1 Buttons (below) ───
        row1_buttons = [
            ('Save PCAP',    self.save_pcap),
            ('Save CSV',     self.save_csv),
             ('Load PCAP...', self.load_pcap),
            ('Test Rule...', self.open_rule_test_panel)
        ]

        for idx, (txt, cmd) in enumerate(row0_buttons, start=7):
            ctk.CTkButton(
                frame, text=txt, command=cmd,
                width=100, height=28, font=self.text_font
            ).grid(row=0, column=idx, padx=3)

        row1_columns = [5, 6, 7, 8]  # Align under Start, Stop, and one new column
        for idx, (txt, cmd) in zip(row1_columns, row1_buttons):
            ctk.CTkButton(
                frame, text=txt, command=cmd,
                width=80, height=28, font=self.text_font
            ).grid(row=1, column=idx, padx=4, pady=(3, 0))
        

    def _build_paned_view(self):
        pane = ctk.CTkFrame(self)
        pane.grid(row=1, column=0, columnspan=4, rowspan=2, sticky='nsew', padx=10, pady=5)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        # Define styles for fonts here (insert this new section)
        style = ttk.Style(self)
        style.configure("Treeview", font=("Arial", 25))  # Increased size for main packet table
        style.configure("Treeview.Heading", font=("Arial", 25, "bold"))
        style.configure("TopTalkers.Treeview", font=("Arial", 25))  # Increased size for top talkers
        style.configure("TopTalkers.Treeview.Heading", font=("Arial", 25, "bold"))

        # Left: table
        tbl_frame = ctk.CTkFrame(pane, corner_radius=8)
        tbl_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        cols = ['Time', 'Src IP', 'Dst IP', 'Proto', 'SP', 'DP', 'Len']
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show='headings')

        for c in cols:
            if c == 'Src IP':
                self.tree.heading(c, text=c, anchor='w')
                self.tree.column(c, width=140, anchor='w', stretch=True)
            else:
                self.tree.heading(c, text=c, anchor='center')
                self.tree.column(c, width=120, anchor='center', stretch=True)

        self.tree.pack(fill='both', expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_click)

        # Middle: metrics
        met_frame = ctk.CTkFrame(pane, corner_radius=8)
        met_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        ctk.CTkLabel(met_frame, text='Live Metrics', font=('Arial', 16)).pack(pady=5)
        self.lbl_pkts = ctk.CTkLabel(met_frame, text='Packets: 0', font=self.text_font)
        self.lbl_bytes = ctk.CTkLabel(met_frame, text='Total Bytes: 0', font=self.text_font)
        self.lbl_rate = ctk.CTkLabel(met_frame, text='Bytes/sec: 0', font=self.text_font)

        for w in (self.lbl_pkts, self.lbl_bytes, self.lbl_rate):
            w.pack(anchor='w', padx=10)

        # chart
        fig = Figure(figsize=(3, 2))
        ax = fig.add_subplot(111)
        self.line, = ax.plot([])
        canvas = FigureCanvasTkAgg(fig, master=met_frame)
        canvas.get_tk_widget().pack(fill='both', expand=True)
        self.chart_ax, self.chart_canvas = ax, canvas

        # Right: top talkers
        top_frame = ctk.CTkFrame(pane, corner_radius=8)
        top_frame.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)
        ctk.CTkLabel(top_frame, text='Top Talkers', font=('Arial', 16)).pack(pady=5)

        self.talker = ttk.Treeview(
            top_frame,
            columns=('IP', 'Bytes'),
            show='headings',
            height=5,
            style="TopTalkers.Treeview"  # Apply the new style here
        )      
        # Left-align headers and cell data
        self.talker.heading('IP', text='IP', anchor='w')
        self.talker.heading('Bytes', text='Bytes', anchor='w')
        self.talker.column('IP', anchor='w', width=180, stretch=True)
        self.talker.column('Bytes', anchor='w', width=80, stretch=True)

        self.talker.pack(fill='both', expand=True)
        
        # ── Protocol Pie Chart ──
        ctk.CTkLabel(top_frame, text='Protocol Breakdown', font=('Arial', 16)).pack(pady=(15, 5))

        fig2 = Figure(figsize=(3, 2))
        self.ax_protocol = fig2.add_subplot(111)
        self.pie_chart = FigureCanvasTkAgg(fig2, master=top_frame)
        self.pie_chart.get_tk_widget().pack(fill='both', expand=True)

        pane.columnconfigure(0, weight=5)
        pane.columnconfigure(1, weight=1)
        pane.columnconfigure(2, weight=1)
        pane.rowconfigure(0, weight=1)
 
    def _build_alerts_panel(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=3, column=0, columnspan=4, sticky='ew', padx=6, pady=5)
        ctk.CTkLabel(frame, text='Alerts', font=('Arial',16)).pack(anchor='w', pady=5)
        self.alert_text = ctk.CTkTextbox(frame, height=60)
        self.alert_text.pack(fill='both', expand=True)

    # -- Capture callbacks --
    def start_capture(self):
        iface = self.iface_var.get()
        stop_sniff_event.clear()
        self.start_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')

        bpf_filter = self.capture_filter_var.get().strip()
        if not bpf_filter:
            bpf_filter = None  # No filter

        def safe_sniff():
            try:
                sniff(
                    iface=iface,
                    filter=bpf_filter,
                    prn=lambda p: process_packet_gui(p, self.local_mac, self, self.vendor),
                    store=True,
                    promisc=True,
                    stop_filter=lambda p: stop_sniff_event.is_set()
                )
            except Exception as e:
                print(f"[ERROR] Failed to start sniffing: {e}")
                messagebox.showerror("Sniff Error", f"Failed to start sniffing:\n{e}")
                self.start_btn.configure(state='normal')
                self.stop_btn.configure(state='disabled')

        threading.Thread(target=safe_sniff, daemon=True).start()

    def stop_capture(self):
        stop_sniff_event.set(); self.stop_btn.configure(state='disabled'); self.start_btn.configure(state='normal')

    def reload_rules(self):
        try:
            self.sig_det.reload_rules()
            self.alerts.notify("Signature rules reloaded.", severity="INFO")
        except Exception as e:
            self.alerts.notify(f"Error reloading rules: {e}", severity="HIGH")
        messagebox.showinfo('Reload', 'Rules reloaded')

    def save_csv(self):
        with open(self.csv_file,'w',newline='') as f:
            w=csv.writer(f); w.writerows(csv_data)
        messagebox.showinfo('Save CSV', self.csv_file)

    def save_pcap(self):
        wrpcap(self.pcap_file, self.all_packets)
        messagebox.showinfo('Save PCAP', self.pcap_file)

    def open_category_window(self):
        # Prevent multiple windows
        if hasattr(self, 'cat_win') and self.cat_win.winfo_exists():
            self.cat_win.focus()
            return

        self.cat_win = ctk.CTkToplevel(self)
        self.cat_win.title("Signature Categories")
        self.cat_win.geometry("300x400")

        ctk.CTkLabel(self.cat_win, text="Enable/Disable Signature Categories", font=self.header_font)\
            .pack(pady=10)

        current_cats = self.sig_det.enabled_categories
        all_cats = sorted({r['category'] for r in self.sig_det.rules})
        self.cat_vars = {}

        for cat in all_cats:
            var = ctk.BooleanVar(value=cat in current_cats)
            chk = ctk.CTkCheckBox(self.cat_win, text=cat, variable=var)
            chk.pack(anchor='w', padx=20, pady=2)
            self.cat_vars[cat] = var

        def apply_changes():
            selected = [cat for cat, var in self.cat_vars.items() if var.get()]
            self.sig_det.set_enabled_categories(selected)
            self.cat_win.destroy()

        ctk.CTkButton(self.cat_win, text="Apply", command=apply_changes).pack(pady=10)

    # -- Poll & update --
    def poll_queue(self):
        """
        Optimized polling that processes packets in batches and limits GUI updates
        """
        packets_processed = 0
        max_batch_size = 50  # Process max 50 packets per poll cycle

        try:
            while packets_processed < max_batch_size:
                packet_data = packet_queue.get_nowait()

                # Add to packet storage with memory limit
                self.all_packets.append(packet_data['raw_packet'])
                if len(self.all_packets) > self.MAX_PACKETS:
                    removed_count = len(self.all_packets) - self.MAX_PACKETS
                    self.all_packets = self.all_packets[removed_count:]
                    self.last_tree_index = max(0, self.last_tree_index - removed_count)

                # Update statistics
                length = packet_data['length']
                self.total_bytes += length
                self.bytes_last += length

                # Update bytes per source (for top talkers)
                src = packet_data['src']
                if src:
                    self.bytes_per_src[src] = self.bytes_per_src.get(src, 0) + length

                # Update protocol counters
                proto = packet_data['protocol']
                if proto == 'ARP':
                    self.protocol_counts['ARP'] += 1
                elif proto == 'TCP':
                    self.protocol_counts['TCP'] += 1
                elif proto == 'UDP':
                    self.protocol_counts['UDP'] += 1
                elif proto == 'ICMP':
                    self.protocol_counts['ICMP'] += 1
                else:
                    self.protocol_counts['Other'] += 1

                # Session tracking
                if IP in packet_data['raw_packet'] and TCP in packet_data['raw_packet']:
                    ip_pkt = packet_data['raw_packet'][IP]
                    tcp_pkt = packet_data['raw_packet'][TCP]
                    key = tuple(sorted([
                        (ip_pkt.src, tcp_pkt.sport),
                        (ip_pkt.dst, tcp_pkt.dport)
                    ]))
                    self.sessions[key].append((tcp_pkt.seq, tcp_pkt.payload))

                packets_processed += 1

        except queue.Empty:
            pass

        if packets_processed > 0:
            self.lbl_pkts.configure(text=f"Packets: {len(self.all_packets)}")

            if packets_processed >= 10 or len(self.all_packets) % 25 == 0:
                self._refresh_tree()

            if len(self.all_packets) % 20 == 0:
                self._refresh_talkers()

        next_poll_time = 100 if packets_processed > 20 else 300
        self.after(next_poll_time, self.poll_queue)

   
    def update_bandwidth_metrics(self):
        """
        Optimized bandwidth metrics with reduced chart redraws
        """
        rate = self.bytes_last
        self.bytes_last = 0
        
        # Update text labels (fast)
        self.lbl_bytes.configure(text=f"Total Bytes: {self.total_bytes:,}")
        self.lbl_rate.configure(text=f"Bytes/sec: {rate:,}")
        
        # Update rate history
        self.byte_rate_history.append(rate)
        if len(self.byte_rate_history) > 30:
            self.byte_rate_history.pop(0)
        
        # Only redraw chart if there's significant change or every 5 seconds
        should_update_chart = (
            not hasattr(self, '_last_chart_update') or
            time.time() - self._last_chart_update > 5.0 or
            (rate > 0 and len(self.byte_rate_history) % 5 == 0)
        )
        
        if should_update_chart and self.byte_rate_history:
            try:
                self.chart_ax.clear()
                self.chart_ax.plot(self.byte_rate_history, 'b-', linewidth=1)
                self.chart_ax.set_title('Bytes/sec', fontsize=10)
                self.chart_ax.grid(True, alpha=0.3)
                
                # Optimize chart appearance
                self.chart_ax.tick_params(labelsize=8)
                self.chart_canvas.draw_idle()  # Use draw_idle instead of draw
                self._last_chart_update = time.time()
            except Exception as e:
                print(f"Chart update error: {e}")
        
        self.after(1000, self.update_bandwidth_metrics)

    def update_protocol_chart(self):
        """
        Optimized protocol chart with less frequent updates
        """
        # Only update every 5 seconds or if significant changes
        if (hasattr(self, '_last_pie_update') and 
            time.time() - self._last_pie_update < 5.0):
            self.after(5000, self.update_protocol_chart)
            return
        
        total = sum(self.protocol_counts.values())
        if total == 0:
            self.after(5000, self.update_protocol_chart)
            return
        
        # Only update if counts have changed significantly
        current_counts = dict(self.protocol_counts)
        if (hasattr(self, '_last_protocol_counts') and 
            current_counts == self._last_protocol_counts):
            self.after(5000, self.update_protocol_chart)
            return
        
        try:
            # Prepare data
            labels = []
            sizes = []
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#ff99cc']
            
            for i, (proto, count) in enumerate(self.protocol_counts.items()):
                if count > 0:
                    labels.append(f"{proto}\n({count})")
                    sizes.append(count)
            
            if sizes:
                self.ax_protocol.clear()
                wedges, texts, autotexts = self.ax_protocol.pie(
                    sizes, 
                    labels=labels, 
                    autopct='%1.1f%%', 
                    startangle=140,
                    colors=colors[:len(sizes)],
                    textprops={'fontsize': 8}
                )
                
                self.ax_protocol.set_title('Protocol Distribution', fontsize=10)
                self.pie_chart.draw_idle()
                
            self._last_pie_update = time.time()
            self._last_protocol_counts = current_counts.copy()
            
        except Exception as e:
            print(f"Protocol chart update error: {e}")
        
        self.after(5000, self.update_protocol_chart)
    
    def apply_display_filter(self,*_): self._refresh_tree()

    def _refresh_views(self): self._refresh_tree(); self._refresh_talkers(); self.lbl_pkts.configure(text=f"Packets: {len(self.all_packets)}")
    
    def on_row_click(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        selected = selected_items[0]
        values = self.tree.item(selected, 'values')
        if not values or len(values) != 7:
            return

        ts, src_ip, dst_ip, proto, sport, dport, length = values
        index = self.tree.index(selected)
        if index >= len(self.all_packets):
            return

        pkt = self.all_packets[index]
        info = f"""--- General Info ---
                Timestamp: {ts}
                Source IP: {src_ip}
                Destination IP: {dst_ip}
                Protocol: {proto}
                Source Port: {sport}
                Destination Port: {dport}
                Packet Length: {length} bytes
                """

        # GeoIP & Vendor Info
        src_loc = self.geoip.lookup(src_ip)
        dst_loc = self.geoip.lookup(dst_ip)
        info += f"\n--- GeoIP & MAC Vendor ---\n"
        info += f"Src GeoIP: {src_loc}\nDst GeoIP: {dst_loc}\n"

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            src_mac = eth.src
            dst_mac = eth.dst
            if src_mac in self.mac_vendor_cache:
                vendor = self.mac_vendor_cache[src_mac]
            else:
                try:
                    vendor = self.vendor.lookup(src_mac)
                except:
                    vendor = "Unknown"
                self.mac_vendor_cache[src_mac] = vendor
            info += f"Src MAC: {src_mac} ({vendor})\nDst MAC: {dst_mac}\n"

        # --- Protocol-Specific Deep Dives ---
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors='ignore')
                info += f"\n--- DNS ---\nQuery: {qname}\n"
            except:
                info += f"\n--- DNS ---\nQuery: [unreadable]\n"

        if pkt.haslayer(DNSRR):
            try:
                rdata = pkt[DNSRR].rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors='ignore')
                info += f"Answer: {rdata}\n"
            except:
                info += "Answer: [unreadable]\n"

        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            info += "\n--- HTTP Request ---\n"
            try:
                info += f"Method: {req.Method.decode()}\n"
                info += f"Host: {req.Host.decode()}\n"
                info += f"Path: {req.Path.decode()}\n"
            except:
                info += "Headers: [partial/unreadable]\n"

        if pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            info += "\n--- HTTP Response ---\n"
            info += f"Status Code: {resp.Status_Code}\n"

        if pkt.haslayer(TLSClientHello):
            try:
                info += "\n--- TLS ---\n"
                ch = pkt[TLSClientHello]
                for ext in getattr(ch, 'extensions', []):
                    if getattr(ext, 'name', '') == 'server_name':
                        sni = ext.servernames[0].servername.decode(errors='ignore')
                        info += f"SNI: {sni}\n"
                        break
            except:
                info += "TLS Info: [unreadable]\n"

        if pkt.haslayer('Raw'):
            try:
                raw_data = pkt['Raw'].load[:100]
                if raw_data:
                    hexed = ' '.join(f"{b:02x}" for b in raw_data)
                    info += f"\n--- Hex Preview ---\n{hexed}\n"
                else:
                    info += "\n--- Hex Preview ---\n[empty payload]\n"
            except:
                info += "\n--- Hex Preview ---\n[error reading payload]\n"
        else:
            info += "\n--- Hex Preview ---\n[no raw layer in packet]\n"

         # Show the info
        popup = ctk.CTkToplevel(self)
        popup.title("Packet Details")
        popup.geometry("700x500")

        ctk.CTkLabel(popup, text="Packet Details", font=self.header_font).pack(pady=5)
        text_box = ctk.CTkTextbox(popup, wrap="word")
        text_box.pack(fill="both", expand=True, padx=10, pady=10)

        text_box.insert("1.0", info)
        text_box.configure(state="normal")
        text_box.focus_set()
        
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            key = tuple(sorted([
            (ip_layer.src, tcp_layer.sport),
            (ip_layer.dst, tcp_layer.dport)
        ]))

            def show_session():
                stream = self.reconstruct_stream(key)
                sess_win = ctk.CTkToplevel(self)
                sess_win.title("Reconstructed TCP Stream")
                sess_win.geometry("700x400")

                sess_text = ctk.CTkTextbox(sess_win, wrap="word")
                sess_text.pack(expand=True, fill="both", padx=10, pady=10)

                if stream.startswith(b'\x16\x03') or stream.startswith(b'\x17\x03'):
                    sess_text.insert("end", "[TLS-encrypted stream — contents not human-readable]")
                elif stream:
                    try:
                        decoded = stream.decode(errors="replace").strip()
                        if decoded:
                            sess_text.insert("end", decoded)
                        else:
                            sess_text.insert("end", "[No session data available]")
                    except Exception as e:
                        sess_text.insert("end", f"[Error decoding stream: {e}]")
                else:
                    sess_text.insert("end", "[No session data available]")

            ctk.CTkButton(popup, text="Reassembled TCP Stream", command=show_session).pack(pady=10)

        # Then move the save prompt into a callback on popup close:
        def on_close():
            save = messagebox.askyesno("Save Info", "Would you like to save this packet info to a file?")
            if save:
                filepath = filedialog.asksaveasfilename(
                    defaultextension=".txt",
                    filetypes=[("Text Files", "*.txt")],
                    title="Save Packet Details"
                )
                if filepath:
                    try:
                        with open(filepath, 'w') as f:
                            f.write(info)
                        messagebox.showinfo("Saved", f"Packet info saved to:\n{filepath}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not save file:\n{e}")

        popup.protocol("WM_DELETE_WINDOW", on_close)

    def _refresh_tree(self):
        """
        Optimized tree refresh - only adds new packets, doesn't rebuild entire tree
        """
        flt = self.display_filter_var.get().strip().lower()
        use_regex = any(c in flt for c in ".|*+?[](){}\\^$") if flt else False

        # Only process new packets since last update
        packets_to_add = []
        start_index = max(0, self.last_tree_index)

        for i, pkt in enumerate(self.all_packets[start_index:], start_index):
            try:
                # Determine protocol for precise filtering
                if pkt.haslayer(TCP):
                    proto = 'tcp'
                    sp, dp = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = 'udp'
                    sp, dp = pkt[UDP].sport, pkt[UDP].dport
                elif pkt.haslayer(ICMP):
                    proto = 'icmp'
                    sp = dp = ''
                elif pkt.haslayer(ARP):
                    proto = 'arp'
                    sp = dp = ''
                else:
                    proto = 'other'
                    sp = dp = ''

                # Apply filter based on exact match or regex
                if flt:
                    if use_regex:
                        try:
                            if not re.search(flt, proto, re.IGNORECASE):
                                continue
                        except re.error:
                            continue
                    else:
                        if flt != proto:
                            continue

                # Extract display data efficiently
                ts = datetime.datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")

                # Get IP addresses
                if pkt.haslayer(IP):
                    src, dst = pkt[IP].src, pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                elif pkt.haslayer(ARP):
                    src, dst = pkt[ARP].psrc, pkt[ARP].pdst
                else:
                    src = dst = ''

                packets_to_add.append((ts, src, dst, proto.upper(), sp, dp, len(pkt)))

            except Exception as e:
                # Skip problematic packets
                continue

        # Batch insert new rows
        if packets_to_add:
            # Limit tree size to prevent GUI slowdown
            current_count = len(self.tree.get_children())
            if current_count > self.MAX_PACKETS:
                # Remove oldest entries
                children = self.tree.get_children()
                for child in children[:len(children) - self.MAX_PACKETS + len(packets_to_add)]:
                    self.tree.delete(child)

            # Add new packets
            for row_data in packets_to_add:
                self.tree.insert('', 'end', values=row_data)

            # Auto-scroll to bottom if user hasn't manually scrolled
            if not hasattr(self, '_user_scrolled') or not self._user_scrolled:
                children = self.tree.get_children()
                if children:
                    self.tree.see(children[-1])

        self.last_tree_index = len(self.all_packets)


    # Add this method to track user scrolling behavior:
    def _on_tree_scroll(self, event):
        """Track if user has manually scrolled the tree"""
        self._user_scrolled = True
        # Reset after 5 seconds of no scrolling
        if hasattr(self, '_scroll_timer'):
            self.after_cancel(self._scroll_timer)
        self._scroll_timer = self.after(5000, lambda: setattr(self, '_user_scrolled', False))

    def _refresh_talkers(self):
        for i in self.talker.get_children(): self.talker.delete(i)
        for ip, cnt in sorted(self.bytes_per_src.items(), key=lambda x:-x[1])[:5]:
            self.talker.insert('', 'end', values=(ip,cnt))
    
    def open_rule_test_panel(self):
        win = ctk.CTkToplevel(self)
        win.title("Test Signature Rules")
        win.geometry("500x400")

        ctk.CTkLabel(win, text="Enter Text to Test Against Signature Rules", font=self.header_font)\
            .pack(pady=10)

        entry = ctk.CTkTextbox(win, height=200, wrap='word')
        entry.pack(fill='both', expand=True, padx=10)

        output = ctk.CTkTextbox(win, height=150, wrap='word')
        output.pack(fill='both', expand=True, padx=10, pady=(10, 5))
        output.configure(state='disabled')

        def run_test():
            test_input = entry.get("1.0", "end").strip()
            matches = self.sig_det._match_signatures(test_input)
            output.configure(state='normal')
            output.delete("1.0", "end")
            if matches:
                for m in matches:
                    output.insert("end", f"{m}\n")
            else:
                output.insert("end", "No signature matched.")
            output.configure(state='disabled')

        ctk.CTkButton(win, text="Run Test", command=run_test).pack(pady=5)

    def load_pcap(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("PCAP Files", "*.pcap *.pcapng")],
            title="Open PCAP File"
        )
        if not filepath:
            return

        try:
            packets = rdpcap(filepath)
            count = 0
            for pkt in packets:
                try:
                    pkt.time = float(pkt.time)
                    self.all_packets.append(pkt)
                    length = len(pkt)
                    self.total_bytes += length
                    self.bytes_last += length

                    # Get source IP if available
                    src = pkt[IP].src if IP in pkt else pkt[IPv6].src if IPv6 in pkt else None
                    if src:
                        self.bytes_per_src[src] = self.bytes_per_src.get(src, 0) + length

                    # Run detection engines
                    for msg in self.sig_det.inspect(pkt):
                        self.alerts.notify(msg, severity="HIGH")
                    for msg in self.anom_det.inspect(pkt):
                        self.alerts.notify(msg, severity="MEDIUM")

                    # Update protocol counters
                    if ARP in pkt:
                        self.protocol_counts['ARP'] += 1
                    elif IP in pkt:
                        p = pkt[IP].proto
                        if p == 6:
                            self.protocol_counts['TCP'] += 1
                        elif p == 17:
                            self.protocol_counts['UDP'] += 1
                        elif p == 1:
                            self.protocol_counts['ICMP'] += 1
                        else:
                            self.protocol_counts['Other'] += 1

                    count += 1
                except Exception as inner_err:
                    print(f"[WARN] Skipped packet due to error: {inner_err}")

            self._refresh_views()
            self.update_protocol_chart()  # <- immediate update
            messagebox.showinfo("Load PCAP", f"Loaded {count} packets from:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not load file:\n{e}")
    
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('-i','--iface', default=None)
    parser.add_argument('-p','--pcap', default='out.pcap')
    parser.add_argument('-c','--csv', default='out.csv')
    args=parser.parse_args()
    imap=build_iface_map()
    friendly=args.iface or (next(iter(imap)) if imap else None)
    if not friendly: sys.exit('No iface')
    npf=imap.get(friendly, friendly)
    app=SnifferApp(npf, args.pcap, args.csv)
    app.mainloop()
