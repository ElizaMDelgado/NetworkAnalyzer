#  Network Analyzer & Packet Sniffer

A powerful Python-based network analyzer and packet sniffer with real-time traffic inspection, GUI dashboard, protocol breakdown charts, anomaly detection, signature-based alerts, GeoIP lookups, and PCAP import/export.

[Dashboard Preview]


![Dashbaord 5-24](https://github.com/user-attachments/assets/fb26a918-c4f4-4938-9c0d-12e18117a0a9)


---

## Features

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

## Steps to Run The Network Analyzer
Follow these steps to install the required dependencies and run the project locally on Windows.
### 1. Install Python 3.11

   Download Python 3.11 from the official site:
    👉 https://www.python.org/downloads/windows/

  On the installer screen, make sure to check:
    ✔️ “Add Python 3.11 to PATH”

   Complete the installation.

To verify:

Open PowerShell or Command Prompt and run:
```bash
python --version
```

Expected output:
```bash
Python 3.11.x
```

### 2. Install Microsoft Visual C++ Build Tools

Some dependencies (e.g., matplotlib) require build tools to compile.

  Download the C++ Build Tools:
    👉 https://visualstudio.microsoft.com/visual-cpp-build-tools/

  During installation, select:
    ✔️ "Desktop development with C++"

  This ensures you have Visual C++ 14.0 or newer, required for building native extensions.

### 3. Install Python Dependencies

   Once Python and C++ tools are set up, run the following command:
```bash
python -m pip install scapy mac-vendor-lookup customtkinter matplotlib requests pytest hypothesis coverage --only-binary matplotlib
```
   This installs all runtime and development packages needed for the GUI, packet capture, and testing.

### 4. Run the Application
 
   Navigate to the project folder (where packet_sniffer_gui.py is located) and run:
```bash
python packet_sniffer_gui.py
```


### Optional arguments:
- `-i`, `--iface` — Friendly name of the network interface (e.g., "Wi-Fi", "Ethernet")
- `-p`, `--pcap` — Output file for saved packets (default: `out.pcap`)
- `-c`, `--csv` — Output file for CSV data (default: `out.csv`)

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `packet_sniffer_gui.py` | Main GUI application |
| `signature_rules.json` | Signature rules for detection |
| `out.pcap` | Saved packet capture |
| `out.csv` | Exported CSV summary |

---

## 🖥️ GUI Overview

- **Top Bar**: Interface selector, BPF filter, display filter, and control buttons
- **Left Panel**: Live packet table
- **Middle Panel**: Live metrics and bandwidth chart
- **Right Panel**: Top talkers and protocol distribution
- **Bottom**: Alert panel for anomalies and rule matches
- **Popups**: Packet detail views with GeoIP, MAC vendor, and hex payload preview


