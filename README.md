# Packet Sniffer

A real-time packet capture and inspection app built with Python, Scapy, and Streamlit. This project lets you select a network interface, start packet capture, view live traffic summaries, search captured packets, inspect detailed protocol data, and export the capture to a `.pcap` file.

## Features

- Live packet capture from a selected network interface
- BPF filter support for targeted traffic capture
- Packet statistics including packets per second, total sniffed packets, and dropped packets
- Packet summary table with source, destination, protocol, and length
- Search through captured packets
- Detailed inspection of protocol layers for each packet
- Export captured traffic as a `.pcap` file

## Tech Stack

- Python
- Scapy
- Streamlit
- streamlit-autorefresh

## Project Structure

- `main.py` - app entry point and Streamlit UI startup
- `sniffer.py` - packet capture logic using Scapy
- `parser.py` - packet parsing and protocol classification
- `controller.py` - coordinates capture, parsing, storage, and export flow
- `storage.py` - in-memory storage for packets
- `ui.py` - Streamlit dashboard for controls and packet inspection

## Requirements

Before running the project, make sure you have:

- Python 3.10 or newer
- An installed packet capture dependency on your OS
  - Windows: Npcap or WinPcap
  - Linux: libpcap + appropriate permissions
- Administrator or root privileges for packet capture on many systems

## Installation

```bash
git clone https://github.com/TheBetter-Alex/packet-sniffer.git
cd packet-sniffer
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Running the App

```bash
streamlit run main.py
```

or:

```bash
python -m streamlit run main.py
```

Then open the local URL shown by Streamlit in your browser, usually:

```text
http://localhost:8501
```

## Usage

1. Select the network interface you want to monitor.
2. Optionally enter a BPF filter such as:
   - `tcp port 80`
   - `udp port 53`
   - `icmp`
3. Click `Start` to begin capture.
4. Watch the packet statistics update in real time.
5. Search or click a packet in the table to inspect the detailed protocol layers.
6. Click `Save PCAP` to export the current captured traffic.

## Important Notes

- Packet capture may require administrator privileges.
- Some network interfaces may not allow promiscuous mode or raw packet capture.
- Only capture traffic on networks you are authorized to monitor.
- This is intended for educational and legitimate network analysis use.
