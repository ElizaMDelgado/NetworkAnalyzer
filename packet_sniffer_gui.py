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
from scapy.layers.inet import IP, TCP, UDP
from tkinter import messagebox

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.layers.http import HTTPRequest, HTTPResponse     # HTTP layer
from scapy.layers.dns  import DNSQR, DNSRR                 # you already have these
from scapy.layers.tls.all import TLS, TLSClientHello       # TLS layer
from scapy.all import load_layer
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
        print("[INFO] Signature rules reloaded.")
        
    


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
    packet_queue.put(row)


class SnifferGUI(tk.Tk):
    def __init__(self, interface, pcap_file, csv_file):
        super().__init__()
        self.title('Packet Sniffer Dashboard')
        self.state('zoomed')
    

        # ── Styling ───────────────────────────────────────────────────────────
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        bg, fg = 'white', 'black'
        for sel in ["TFrame","TLabelframe","TLabel","Treeview"]:
            self.style.configure(sel, background=bg, foreground=fg)
        self.style.configure("Treeview.Heading", background="lightgray", foreground=fg)
        # ──────────────────────────────────────────────────────────────────────

         # ── Theme Menu ─────────────────────────────────────────────────────────
        self.menubar = tk.Menu(self)
        theme_menu   = tk.Menu(self.menubar, tearoff=False)
        theme_menu.add_command(label="Light",
                            command=lambda: self.set_theme('light'))
        theme_menu.add_command(label="Dark",
                            command=lambda: self.set_theme('dark'))
        self.menubar.add_cascade(label="Theme", menu=theme_menu)
        self.config(menu=self.menubar)
          # ──────────────────────────────────────────────────────────────────────

        # Parameters
        self.interface = interface
        self.pcap_file = pcap_file
        self.csv_file  = csv_file
        self.vendor    = MacLookup()
        self.local_mac = get_if_hwaddr(interface).upper()
    
        # Stats counters
        self.total_bytes = 0
        self.bytes_last  = 0
        self.total_count = 0
        self.times       = []
        self.tcp_count   = 0
        self.udp_count   = 0
        self.icmp_count  = 0

        # Layout grid
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=0, minsize=350)
        self.rowconfigure(1, weight=1)

        # ─── Capture Controls ─────────────────────────────────────────────────
        cap_frame = ttk.Labelframe(self, text='Capture Controls')
        cap_frame.grid(row=0, column=0, columnspan=2, sticky='ew',
                       padx=10, pady=5)

        # Friendly→NPF dropdown
        self.iface_map  = build_iface_map()
        choices        = list(self.iface_map.keys())
        default_choice = choices[0] if choices else ''
        self.iface_var = tk.StringVar(value=default_choice)
        ttk.OptionMenu(cap_frame,
                       self.iface_var,
                       default_choice,
                       *choices
        ).pack(side='left', padx=5)   

        self.start_btn = ttk.Button(cap_frame,
                                    text='Start',
                                    command=self.start_capture)
        self.start_btn.pack(side='left', padx=5)

        self.stop_btn = ttk.Button(cap_frame,
                                   text='Stop',
                                   command=self.stop_capture,
                                   state='disabled')
        self.stop_btn.pack(side='left', padx=5)

        ttk.Button(cap_frame,
                   text='Save CSV',
                   command=self.save_csv).pack(side='right', padx=5)
        ttk.Button(cap_frame,
                   text='Save PCAP',
                   command=self.save_pcap).pack(side='right')
        ttk.Button(cap_frame,
           text='Reload Rules',
           command=self.reload_signatures).pack(side='right', padx=5)

        # ──────────────────────────────────────────────────────────────────────

        # ─── Packet Table ─────────────────────────────────────────────────────
        table_frame = ttk.Frame(self)
        table_frame.grid(row=1, column=0, sticky='nsew', padx=(10,5), pady=5)
        cols = ['Date/Time','Src IP','Dst IP','Proto','Src Port','Dst Port','Len']
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings')
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120, anchor='center')
        self.tree.pack(expand=True, fill='both')
        self.tree.bind('<<TreeviewSelect>>', self.on_row_selected)
        # ──────────────────────────────────────────────────────────────────────

        # ─── Live Metrics Pane ────────────────────────────────────────────────
        stats = ttk.Labelframe(self, text='Live Metrics')
        stats.grid(row=1, column=1, sticky='nsew', padx=(5,10), pady=5)
        stats.columnconfigure(0, weight=1)

        # Packet stats
        ps = ttk.Frame(stats)
        ps.grid(row=0, column=0, sticky='ew', padx=5, pady=5)
        ttk.Label(ps, text='Total Packets:').grid(row=0, column=0, sticky='w')
        self.lbl_total = ttk.Label(ps, text='0')
        self.lbl_total.grid(row=0, column=1, sticky='e')
        ttk.Label(ps, text='Pkt/s (1s):').grid(row=1, column=0, sticky='w')
        self.lbl_rate  = ttk.Label(ps, text='0')
        self.lbl_rate.grid(row=1, column=1, sticky='e')

        # Bandwidth table
        bwf = ttk.Frame(stats)
        bwf.grid(row=1, column=0, sticky='ew', padx=5, pady=5)
        self.bw_table = ttk.Treeview(bwf,
                                     columns=('metric','value'),
                                     show='headings',
                                     height=2)
        self.bw_table.heading('metric', text='Metric')
        self.bw_table.heading('value',  text='Value')
        self.bw_table.column('metric', width=120, anchor='w')
        self.bw_table.column('value',  width=80,  anchor='e')
        self.bw_table.insert('', 'end', iid='Bytes/sec',   values=('Bytes/sec','0'))
        self.bw_table.insert('', 'end', iid='Total bytes', values=('Total bytes','0'))
        self.bw_table.pack(fill='x')

        # Chart area
        cf = ttk.Frame(stats)
        cf.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)
        if FigureCanvasTkAgg:
            fig = Figure(figsize=(3,2))
            self.ax  = fig.add_subplot(111)
            self.bar = self.ax.bar(['Bytes/sec'], [0])
            self.ax.grid(True, axis='y', linestyle='--', alpha=0.5)
            self.canvas = FigureCanvasTkAgg(fig, master=cf)
            self.canvas.get_tk_widget().pack(fill='both', expand=True)
        # ──────────────────────────────────────────────────────────────────────

        # Status bar
        self.status = ttk.Label(self, text='Ready')
        self.status.grid(row=2, column=0, columnspan=2,
                         sticky='ew', padx=10, pady=(0,5))

        # Alerts pane
        alerts_frame = ttk.Labelframe(self, text='Alerts')
        alerts_frame.grid(row=3, column=0, columnspan=2,
                          sticky='ew', padx=10, pady=5)
        self.alert_text = tk.Text(alerts_frame,
                                  height=5,
                                  state='disabled',
                                  wrap='none')
        self.alert_text.pack(fill='both', expand=True)

        # Rebind our AlertManager to this GUI
        global alerts
        alerts = AlertManager(gui=self)

        # Kick off loops
        self.after(100,  self.poll_queue)
        self.after(1000, self.update_bandwidth_metrics)
      
    def set_theme(self, mode):
     if mode == 'light':
         self.style.theme_use('clam')
         self._apply_colors(bg='white', fg='black', heading_bg='lightgray')
     else:
         DARK_BG      = '#2b2b2b'
         DARK_FG      = '#e0e0e0'
         DARK_HEAD_BG = '#3e3e3e'
         DARK_SEL_BG  = '#5a5a5a'
         self.style.theme_use('alt')
         self._apply_colors(bg=DARK_BG,
                            fg=DARK_FG,
                            heading_bg=DARK_HEAD_BG,
                            sel_bg=DARK_SEL_BG)

    def _apply_colors(self, bg, fg, heading_bg, sel_bg=None):
     for cls in ('TFrame','TLabelframe','TLabel',
                 'Treeview','TEntry','TMenubutton'):
         self.style.configure(cls, background=bg, foreground=fg)
     self.style.configure('Treeview',
                          background=bg,
                          fieldbackground=bg,
                          foreground=fg)
     self.style.configure('Treeview.Heading',
                          background=heading_bg,
                          foreground=fg)
     if sel_bg:
         self.style.map('Treeview',
                        background=[('selected', sel_bg)],
                        foreground=[('selected', fg)])
     self.configure(bg=bg)
     self.menubar.config(bg=bg,
                         fg=fg,
                         activebackground=heading_bg,
                         activeforeground=fg)
     # recolor the alerts box too
     self.alert_text.config(bg=bg, fg=fg, insertbackground=fg)
    
        

    def start_capture(self):
        # translate friendly → actual NPF
        friendly = self.iface_var.get()
        iface    = self.iface_map.get(friendly, friendly)

        stop_sniff_event.clear()
        self.status.config(text=f'Capturing on {friendly}')
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')

        self.local_mac = get_if_hwaddr(iface).upper()

        threading.Thread(
            target=lambda: sniff(
                iface=iface,
                prn=lambda p: process_packet_gui(p, self.local_mac, self.vendor),
                store=True,
                promisc=True,
                stop_filter=lambda p: stop_sniff_event.is_set()
            ),
            daemon=True
        ).start()

    def stop_capture(self):
        stop_sniff_event.set()
        self.stop_btn.config(state='disabled')
        self.start_btn.config(state='normal')

    def poll_queue(self):
        now = time.time()
        new = 0
        while not packet_queue.empty():
            row = packet_queue.get()
            new += 1
            proto, length = row[3], row[6]
            self.tree.insert('', 'end', values=row)
            self.total_count += 1
            self.bytes_last  += length
            self.total_bytes += length
            if proto == 'TCP':
                self.tcp_count += 1
            elif proto == 'UDP':
                self.udp_count += 1
            elif proto == 'ICMP':
                self.icmp_count += 1
            self.times.append(now)

        if new:
            self.lbl_total.config(text=str(self.total_count))
            rate = len([t for t in self.times if t >= now - 1])
            self.lbl_rate.config(text=str(rate))

        self.after(100, self.poll_queue)

    def update_bandwidth_metrics(self):
        bps = self.bytes_last
        self.bytes_last = 0

        self.bw_table.set('Bytes/sec',   column='value', value=str(bps))
        self.bw_table.set('Total bytes', column='value', value=str(self.total_bytes))

        if FigureCanvasTkAgg:
            self.bar[0].set_height(bps)
            ymin, ymax = self.ax.get_ylim()
            if bps > ymax:
                self.ax.set_ylim(0, bps * 1.2)
            self.canvas.draw_idle()

        self.after(1000, self.update_bandwidth_metrics)

    def on_row_selected(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        pkt = gui_packets[idx]

        win = tk.Toplevel(self)
        win.title('Packet Details')
        txt = tk.Text(win, wrap='none')
        txt.pack(expand=True, fill='both')
        txt.insert('end', pkt.show(dump=True) + '\n')
        if pkt.haslayer(TCP):
            txt.insert('end', f"Flags: {pkt[TCP].sprintf('%flags%')}\n\n")
        txt.insert('end', 'Hex Dump:\n' + hexdump(pkt, dump=True))

    def save_csv(self):
        with open(self.csv_file, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow([
                'Date/Time','Source IP','Destination IP',
                'Protocol','Source Port','Destination Port','Packet Length'
            ])
            w.writerows(csv_data)
        messagebox.showinfo('Saved', f'CSV → {self.csv_file}')

    def save_pcap(self):
        wrpcap(self.pcap_file, gui_packets)
        messagebox.showinfo('Saved', f'PCAP → {self.pcap_file}')
    
    def reload_signatures(self):
        sig_det.reload_rules()
        self.status.config(text='Signature rules reloaded.')
        alerts.notify("Signature rules reloaded from disk.", severity="INFO")
        sig_det.reload_rules()
        self.status.config(text='Signature rules reloaded.')
        alerts.notify("Signature rules reloaded from disk.", severity="INFO")
        messagebox.showinfo("Reload Complete", "Signature rules successfully reloaded.")
        count = len(sig_det.rules)  # count the loaded rules
        self.status.config(text=f'Signature rules reloaded ({count} rules).')
        alerts.notify(f"{count} signature rules reloaded from disk.", severity="INFO")
        messagebox.showinfo("Reload Complete", f"{count} signature rules successfully reloaded.")
    
    def _inspect_http(self, pkt):
        parts = []
    
        print("DEBUG HTTP parts:", parts)  # <-- temporary
        return self._match_signatures("\n".join(parts))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--iface', default=None)
    parser.add_argument('-p','--pcap',  default='out.pcap')
    parser.add_argument('-c','--csv',   default='out.csv')
    args = parser.parse_args()

    iface_map = build_iface_map()
    friendly  = args.iface or (next(iter(iface_map)) if iface_map else None)
    if not friendly:
        print('No interfaces found; exiting.')
        sys.exit(1)

    npf_iface = iface_map.get(friendly, friendly)
    app       = SnifferGUI(npf_iface, args.pcap, args.csv)
    app.mainloop()


