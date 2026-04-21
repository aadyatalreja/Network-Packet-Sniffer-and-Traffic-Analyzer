"""
Packet Capture Engine using Scapy.
Runs in a background thread so it doesn't block FastAPI.
"""

import asyncio
import threading
import time
import os
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, conf as scapy_conf
    scapy_conf.use_pcap = True          # required on Windows for Npcap
    scapy_conf.verb = 0                 # suppress scapy noise
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠ Scapy not installed. Running in DEMO mode with simulated packets.")


class PacketCapture:
    def __init__(self, db, analyzer):
        self.db = db
        self.analyzer = analyzer
        self.is_running = False
        self.current_interface: Optional[str] = None
        self.current_filter: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._broadcast_callback: Optional[Callable] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._captured_packets = []

    def set_broadcast_callback(self, callback: Callable):
        self._broadcast_callback = callback

    def start(self, interface: str = "eth0", bpf_filter: Optional[str] = None):
        if self.is_running:
            return
        self.is_running = True
        self.current_interface = interface
        self.current_filter = bpf_filter
        self._stop_event.clear()
        self._captured_packets.clear()

        # get_event_loop() is deprecated and unreliable in threads on Python 3.10+
        # grab the running loop from the main asyncio thread instead
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.get_event_loop()

        target = self._capture_loop if SCAPY_AVAILABLE else self._demo_loop
        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False
        self._stop_event.set()

    def export_pcap(self, path: str = "/tmp/capture.pcap") -> Optional[str]:
        if self._captured_packets and SCAPY_AVAILABLE:
            wrpcap(path, self._captured_packets)
            return path
        return None

    # ── Real capture ──────────────────────────────────────────────────────────
    def _capture_loop(self):
        try:
            # test sniff for 3 seconds — if we get nothing, fall back to demo
            test_count = {"n": 0}
            def _prn(pkt):
                test_count["n"] += 1
                self._process_packet(pkt)

            sniff(
                iface=self.current_interface,
                filter=self.current_filter or "",
                prn=_prn,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
                timeout=3,
            )
            if self._stop_event.is_set():
                return
            if test_count["n"] == 0:
                print(f"[capture] No packets on {self.current_interface} after 3s — falling back to demo mode")
                self._demo_loop()
                return
            # got packets — continue full capture
            sniff(
                iface=self.current_interface,
                filter=self.current_filter or "",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as e:
            print(f"[capture error] {e} — falling back to demo mode")
            self._demo_loop()

    def _process_packet(self, pkt):
        self._captured_packets.append(pkt)
        parsed = self._parse_packet(pkt)
        self._handle_parsed(parsed)

    def _parse_packet(self, pkt) -> dict:
        ts = datetime.utcnow().isoformat()
        src_ip = dst_ip = src_port = dst_port = protocol = flags = ""
        length = len(pkt)

        if pkt.haslayer(ARP):
            protocol = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                protocol = "HTTPS" if dport in (443, 8443) or sport in (443, 8443) else \
                           "HTTP"  if dport == 80 or sport == 80 else "TCP"
                src_port = str(sport)
                dst_port = str(dport)
                flags = str(pkt[TCP].flags)
                if pkt.haslayer(DNS):
                    protocol = "DNS"
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = str(pkt[UDP].sport)
                dst_port = str(pkt[UDP].dport)
                if pkt.haslayer(DNS):
                    protocol = "DNS"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            protocol = "IPv6"

        return {
            "timestamp": ts,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol or "OTHER",
            "length":    length,
            "flags":     flags,
        }

    # ── Demo mode (no Scapy / no root) ───────────────────────────────────────
    def _demo_loop(self):
        import random
        protocols = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "ARP"]
        weights   = [35,    20,    10,     15,    8,      10,      2]
        ips = [f"192.168.1.{i}" for i in range(2, 20)] + [
            "10.0.0.1", "8.8.8.8", "1.1.1.1", "172.217.14.196",
            "151.101.1.140", "185.199.108.153",
        ]
        ports_map = {
            "TCP":   [22, 80, 443, 8080, 3306, 5432],
            "UDP":   [53, 123, 161, 5353],
            "HTTP":  [80],
            "HTTPS": [443],
            "DNS":   [53],
            "ICMP":  [0],
            "ARP":   [0],
        }
        while not self._stop_event.is_set():
            for _ in range(random.randint(1, 5)):
                proto = random.choices(protocols, weights=weights)[0]
                src   = random.choice(ips)
                dst   = random.choice([ip for ip in ips if ip != src])
                sp    = str(random.choice(ports_map.get(proto, [0])))
                dp    = str(random.choice(ports_map.get(proto, [0])))
                parsed = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "src_ip":    src,
                    "dst_ip":    dst,
                    "src_port":  sp,
                    "dst_port":  dp,
                    "protocol":  proto,
                    "length":    random.randint(40, 1500),
                    "flags":     random.choice(["S", "SA", "A", "FA", "PA", ""]) if proto == "TCP" else "",
                }
                self._handle_parsed(parsed)
            time.sleep(random.uniform(0.1, 0.4))

    # ── Shared handler ────────────────────────────────────────────────────────
    def _handle_parsed(self, parsed: dict):
        self.db.insert_packet(parsed)
        alert = self.analyzer.update(parsed)
        if self._broadcast_callback and self._loop and not self._loop.is_closed():
            payload = {"type": "packet", "data": parsed}
            if alert:
                payload["alert"] = alert
            # ← FIX 3: schedule coroutine onto the main event loop from this background thread
            asyncio.run_coroutine_threadsafe(
                self._broadcast_callback(payload), self._loop
            )