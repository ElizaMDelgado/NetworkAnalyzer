# 🕵️ Network Analyzer & Packet Sniffer

A powerful Python-based network analyzer and packet sniffer with real-time traffic inspection, GUI dashboard, protocol breakdown charts, anomaly detection, signature-based alerts, GeoIP lookups, and PCAP import/export.

[Dashboard Preview]




---

## 🚀 Features

- **Live Packet Capture** using Scapy
- **Signature-Based Detection** via JSON regex rules
- **Anomaly Detection** with Welford’s algorithm for outlier packet sizes
- **GeoIP Lookup** using `ipinfo.io`
- **MAC Vendor Identification** via `mac-vendor-lookup`
- **GUI Interface** using `CustomTkinter`
- **Bandwidth & Protocol Charts** with Matplotlib
- **Top Talkers Panel** to show highest traffic sources
- **Hex Preview** of packet payloads
- **PCAP Import & Export**
- **CSV Export** of captured data
- **Category-Based Rule Filtering**
- **Rule Testing Panel** to test signature rules on-the-fly

---

## 🛠 Requirements

Install dependencies using pip:

```bash
pip install -r requirements.txt
