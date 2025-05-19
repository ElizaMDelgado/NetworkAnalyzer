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
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.tls.all import TLSClientHello
from scapy.all import (
    sniff, Ether, wrpcap, get_if_hwaddr,
    get_if_list, hexdump, load_layer
)
from scapy.arch.windows import get_windows_if_list
from mac_vendor_lookup import MacLookup

import customtkinter as ctk
from tkinter import ttk, messagebox
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
                    f"Anomaly: packet size {length} B is >{self.threshold}σ "
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


def process_packet_gui(packet, local_mac, vendor_lookup=None):
    if Ether not in packet:
        return

        # Run detections
    for m in sig_det.inspect(packet):
        print("[SIG DETECTED]", m)
        alerts.notify(m, severity="HIGH")

    for m in anom_det.inspect(packet):
        alerts.notify(m, severity="MEDIUM")

    gui_packets.append(packet)

    # Timestamp
    dt = datetime.datetime.fromtimestamp(packet.time)
    ts = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    proto = src = dst = sport = dport = ""
    # ---- handle ARP before any IP ----
    if ARP in packet:
        arp   = packet[ARP]
        proto = "ARP"
        src   = arp.psrc    # sender IP
        dst   = arp.pdst    # target IP

    # ---- handle IPv6 ----
    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        # next-header numbers: 6=TCP, 17=UDP, 58=ICMPv6
        proto = {6:'TCP',17:'UDP',58:'ICMPv6'}.get(ipv6.nh, str(ipv6.nh))
        src, dst = ipv6.src, ipv6.dst
        if proto == 'TCP' and packet.haslayer(TCP):
            tcp = packet[TCP]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 'UDP' and packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = udp.sport, udp.dport

    # ---- fallback to IPv4 ----
    elif IP in packet:
        ip    = packet[IP]
        proto = {1:'ICMP',6:'TCP',17:'UDP'}.get(ip.proto, str(ip.proto))
        src, dst = ip.src, ip.dst
        if proto == 'TCP' and packet.haslayer(TCP):
            tcp = packet[TCP]
            sport, dport = tcp.sport, tcp.dport
        elif proto == 'UDP' and packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = udp.sport, udp.dport

    length = len(packet)
    row    = [ts, src, dst, proto, sport, dport, length]
    csv_data.append(row)
    packet_queue.put(packet)

class SnifferApp(ctk.CTk):
    def __init__(self, interface, pcap_file, csv_file):
        super().__init__()
        self.interface = interface
        self.pcap_file = pcap_file
        self.csv_file = csv_file
        self.vendor = MacLookup()
        self.local_mac = get_if_hwaddr(interface).upper() 

        # ── Theme setup ──
        ctk.set_appearance_mode('Light')
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
        self.after(100, self.poll_queue)
        self.after(1000, self.update_bandwidth_metrics)

    
    def _build_capture_controls(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=0, column=0, sticky='ew', padx=10, pady=5)

        # ─── Prevent EVERY column from expanding except the last one ───
        for col in range(0,  7):    # replace nine with however many columns you're using
            frame.grid_columnconfigure(col, weight=0)
        frame.grid_columnconfigure( 7, weight=1)  # final spacer column

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
        .grid(row=0, column=1, padx=(10,2), sticky='e')
        ctk.CTkEntry(
            frame,
            placeholder_text='e.g. tcp port 80',
            textvariable=self.capture_filter_var,
            width=150,
            font=self.text_font
        ).grid(row=0, column=2, padx=(2,10))

        # ─── Column 3 & 4: Display filter label + entry ───
        ctk.CTkLabel(frame, text="Display Filter:", font=self.text_font)\
        .grid(row=0, column=3, padx=(10,2), sticky='e')
        ctk.CTkEntry(
            frame,
            placeholder_text='e.g. http',
            textvariable=self.display_filter_var,
            width=150,
            font=self.text_font
        ).grid(row=0, column=4, padx=(2,10))

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

        # ─── Columns 7–10: Other buttons ───
        other = [
            ('Categories…',      self.open_category_window),
            ('Reload Rules',     self.reload_rules),
            ('Save PCAP',        self.save_pcap),
            ('Save CSV',         self.save_csv),
        ]
        for idx, (txt, cmd) in enumerate(other, start=7):
            ctk.CTkButton(
                frame, text=txt, command=cmd,
                width=100, height=28, font=self.text_font
            ).grid(row=0, column=idx, padx=4)


    def _build_paned_view(self):
        pane = ctk.CTkFrame(self)
        pane.grid(row=1, column=0, columnspan=4, rowspan=2, sticky='nsew', padx=10, pady=5)
        self.rowconfigure(1, weight=1); self.columnconfigure(0, weight=1)

        # Left: table
        tbl_frame = ctk.CTkFrame(pane, corner_radius=8)
        tbl_frame.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)
        cols=['Time','Src IP','Dst IP','Proto','SP','DP','Len']
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show='headings')
        for c in cols:
            self.tree.heading(c, text=c); self.tree.column(c,width=100)

        self.tree.pack(fill='both', expand=True)

        # Middle: metrics
        met_frame = ctk.CTkFrame(pane, corner_radius=8)
        met_frame.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)
        ctk.CTkLabel(met_frame, text='Live Metrics', font=('Arial', 16)).pack(pady=5)
        self.lbl_pkts  = ctk.CTkLabel(met_frame, text='Packets: 0',     font=self.text_font)
        self.lbl_bytes = ctk.CTkLabel(met_frame, text='Total Bytes: 0', font=self.text_font)
        self.lbl_rate  = ctk.CTkLabel(met_frame, text='Bytes/sec: 0',   font=self.text_font)

        for w in (self.lbl_pkts, self.lbl_bytes, self.lbl_rate): w.pack(anchor='w', padx=10)
        # chart
        fig = Figure(figsize=(3,2)); ax=fig.add_subplot(111); self.line,=ax.plot([])
        canvas=FigureCanvasTkAgg(fig,master=met_frame); canvas.get_tk_widget().pack(fill='both',expand=True)
        self.chart_ax, self.chart_canvas = ax, canvas

        # Right: top talkers
        top_frame = ctk.CTkFrame(pane, corner_radius=8)
        top_frame.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)
        ctk.CTkLabel(top_frame, text='Top Talkers', font=('Arial',16)).pack(pady=5)
        self.talker = ttk.Treeview(top_frame, columns=('IP','Bytes'), show='headings', height=5)
        self.talker.heading('IP',text='IP'); self.talker.heading('Bytes',text='Bytes')
        self.talker.pack(fill='both',expand=True)

        pane.columnconfigure(0,weight=3); pane.columnconfigure(1,weight=1); pane.columnconfigure(2,weight=1)
        pane.rowconfigure(0,weight=1)

    def _build_alerts_panel(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.grid(row=3, column=0, columnspan=4, sticky='ew', padx=10, pady=5)
        ctk.CTkLabel(frame, text='Alerts', font=('Arial',16)).pack(anchor='w', pady=5)
        self.alert_text = ctk.CTkTextbox(frame, height=6)
        self.alert_text.pack(fill='both', expand=True)

    # -- Capture callbacks --
    def start_capture(self):
        iface = self.iface_var.get()
        stop_sniff_event.clear()
        self.start_btn.configure(state='disabled'); self.stop_btn.configure(state='normal')
        threading.Thread(target=lambda: sniff(
            iface=iface, filter=self.capture_filter_var.get() or None,
            prn=lambda p: process_packet_gui(p, self.local_mac, self.vendor),
            store=True, promisc=True,
            stop_filter=lambda p: stop_sniff_event.is_set()
        ), daemon=True).start()

    def stop_capture(self):
        stop_sniff_event.set(); self.stop_btn.configure(state='disabled'); self.start_btn.configure(state='normal')

    def reload_rules(self):
        self.sig_det.reload_rules(); messagebox.showinfo('Reload','Rules reloaded')

    def save_csv(self):
        with open(self.csv_file,'w',newline='') as f:
            w=csv.writer(f); w.writerows(csv_data)
        messagebox.showinfo('Save CSV', self.csv_file)

    def save_pcap(self):
        wrpcap(self.pcap_file, self.all_packets)
        messagebox.showinfo('Save PCAP', self.pcap_file)

    def open_category_window(self):
        # implement similar to earlier but with CTkCheckBox
        pass

    # -- Poll & update --
    def poll_queue(self):
        try:
            while True:
                pkt=packet_queue.get_nowait(); self.all_packets.append(pkt)
                length=len(pkt); self.total_bytes+=length; self.bytes_last+=length
                src = pkt[IP].src if IP in pkt else pkt[IPv6].src if IPv6 in pkt else None
                if src: self.bytes_per_src[src]=self.bytes_per_src.get(src,0)+length
        except queue.Empty:
            pass
        self._refresh_views()
        self.after(100, self.poll_queue)

    def update_bandwidth_metrics(self):
        rate=self.bytes_last; self.bytes_last=0
        self.lbl_bytes.configure(text=f"Total Bytes: {self.total_bytes}")
        self.lbl_rate.configure(text=f"Bytes/sec: {rate}")
        # update chart
        y=list(self.line.get_ydata())+ [rate]
        x=list(range(len(y)))
        self.chart_ax.clear(); self.chart_ax.plot(x,y)
        self.chart_canvas.draw_idle()
        self.after(1000, self.update_bandwidth_metrics)

    def apply_display_filter(self,*_): self._refresh_tree()

    def _refresh_views(self): self._refresh_tree(); self._refresh_talkers(); self.lbl_pkts.configure(text=f"Packets: {len(self.all_packets)}")

    def _refresh_tree(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        flt=self.display_filter_var.get().lower()
        for pkt in self.all_packets:
            if flt and flt not in pkt.summary().lower(): continue
            ts=datetime.datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")
            proto='TCP' if pkt.haslayer(TCP) else 'UDP' if pkt.haslayer(UDP) else 'ICMP' if pkt.haslayer(ICMP) else ''
            sp=pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else ''
            dp=pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else ''
            src=pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else '')
            dst=pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else '')
            ln=len(pkt)
            self.tree.insert('', 'end', values=(ts,src,dst,proto,sp,dp,ln))

    def _refresh_talkers(self):
        for i in self.talker.get_children(): self.talker.delete(i)
        for ip, cnt in sorted(self.bytes_per_src.items(), key=lambda x:-x[1])[:5]:
            self.talker.insert('', 'end', values=(ip,cnt))

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
