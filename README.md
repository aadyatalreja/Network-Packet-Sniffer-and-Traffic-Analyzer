# NetSniffer — Packet Analyzer Dashboard

A live **network packet sniffer** and **traffic analyzer** with a modern terminal-style dashboard.

Inspired by Wireshark and built using **Python (FastAPI + Scapy)** and **React**, NetSniffer captures, analyzes, and visualizes network traffic in real time.

---

## Features

- Live packet capture using **Scapy** with BPF filter support
- Real-time packet streaming via **WebSockets**
- Protocol detection
  - TCP
  - UDP
  - ICMP
  - DNS
  - HTTP
  - HTTPS
  - ARP
- Traffic analytics
  - Protocol distribution
  - Top talkers
  - Packet rate
  - Port usage
  - Packet size histogram
- Real-time anomaly detection
  - SYN Flood
  - Port Scan
  - High-rate IP detection
  - Oversized packets
- SQLite persistence
- PCAP export for Wireshark
- Demo mode when Scapy or Administrator privileges are unavailable

---

## Project Structure

```text
Network-Packet-Sniffer-and-Traffic-Analyzer/
│
├── backend/
│   ├── main.py
│   ├── packet_capture.py
│   ├── analyzer.py
│   └── database.py
│
├── frontend/
│   └── index.html
│
├── requirements.txt
└── README.md
```

---

## Quick Start

### Clone the Repository

```bash
git clone https://github.com/aadyatalreja/Network-Packet-Sniffer-and-Traffic-Analyzer.git

cd Network-Packet-Sniffer-and-Traffic-Analyzer
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Backend

#### Linux / macOS

```bash
cd backend

sudo uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Windows

Run the terminal as **Administrator**.

```powershell
cd backend

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

> If Scapy or Administrator privileges are unavailable, the application automatically starts in **Demo Mode** with simulated traffic.

### Open the Frontend

Open `frontend/index.html` directly in your browser, or serve it locally:

```bash
cd frontend

python -m http.server 3000
```

Visit:

```
http://localhost:3000
```

---

## REST API

| Method | Endpoint | Description |
|---------|----------|-------------|
| POST | `/start_capture` | Start packet capture |
| POST | `/stop_capture` | Stop packet capture |
| GET | `/capture_status` | Capture status |
| GET | `/traffic_stats` | Traffic statistics |
| GET | `/packets?limit=500` | Recent packets |
| GET | `/alerts` | Active alerts |
| GET | `/interfaces` | Available network interfaces |
| GET | `/export_pcap` | Download captured packets as a PCAP file |
| WS | `/ws` | Live packet and statistics stream |

---

## WebSocket Messages

### Packet

```json
{
  "type": "packet",
  "data": {},
  "alert": {}
}
```

### Statistics

```json
{
  "type": "stats",
  "data": {
    "total_packets": 1234,
    "packet_rate": 45
  }
}
```

---

## BPF Filter Examples

| Filter | Description |
|---------|-------------|
| `tcp` | Capture TCP traffic |
| `udp` | Capture UDP traffic |
| `icmp` | Capture ICMP traffic |
| `port 80` | Capture HTTP traffic |
| `port 443` | Capture HTTPS traffic |
| `host 192.168.1.5` | Capture traffic to/from a specific host |
| `not port 22` | Exclude SSH traffic |

---

## Anomaly Detection

| Rule | Threshold | Severity |
|------|-----------|----------|
| SYN Flood | More than 100 SYN packets/sec from one IP | HIGH |
| Port Scan | More than 20 destination ports from one IP | HIGH |
| High Traffic Rate | More than 200 packets from one IP | MEDIUM |
| Oversized Packet | Packet size greater than 9000 bytes | LOW |

---

## Requirements

- Python 3.10+
- FastAPI
- Scapy
- SQLite
- Modern web browser
- Administrator or Root privileges (for live packet capture)

---

## Troubleshooting

### Permission Denied

Linux/macOS:

```bash
sudo python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Windows:

Run Command Prompt or PowerShell as **Administrator**.

### No Interfaces Found

Install Scapy:

```bash
pip install scapy
```

Then restart the application with Administrator or Root privileges.

### Backend Offline

Ensure the backend is running on:

```
http://localhost:8000
```

and that CORS settings allow frontend access.


<div align="center">

Built with FastAPI, Scapy, and React.

</div>
