"""
Traffic Analyzer — computes protocol distribution, top talkers,
packet rate, port usage, and basic anomaly detection.
"""

import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional


class TrafficAnalyzer:
    # Anomaly thresholds
    SYN_FLOOD_THRESHOLD = 100       # SYN packets/sec from single IP
    RATE_PER_IP_THRESHOLD = 200     # total packets from single IP
    PORT_SCAN_THRESHOLD = 20        # unique dst ports from single IP
    LARGE_PACKET_THRESHOLD = 9000   # bytes

    def __init__(self):
        self.total_packets = 0
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.src_ip_counts: dict[str, int] = defaultdict(int)
        self.dst_ip_counts: dict[str, int] = defaultdict(int)
        self.port_counts: dict[str, int] = defaultdict(int)
        self.packet_sizes: list[int] = []
        self.alerts: list[dict] = []

        # For packet rate (sliding 1-second window)
        self._timestamps: deque = deque()
        self._start_time = time.time()

        # Anomaly tracking
        self._syn_counts: dict[str, int] = defaultdict(int)
        self._syn_window_start = time.time()
        self._ip_dst_ports: dict[str, set] = defaultdict(set)
        self._alerted_ips: set[str] = set()

    # ── Ingest one packet ────────────────────────────────────────────────────
    def update(self, pkt: dict) -> Optional[dict]:
        self.total_packets += 1
        now = time.time()

        # Sliding window for rate
        self._timestamps.append(now)
        while self._timestamps and self._timestamps[0] < now - 1:
            self._timestamps.popleft()

        proto = pkt.get("protocol", "OTHER")
        self.protocol_counts[proto] += 1

        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if src:
            self.src_ip_counts[src] += 1
        if dst:
            self.dst_ip_counts[dst] += 1

        dst_port = pkt.get("dst_port", "")
        if dst_port and dst_port != "0":
            self.port_counts[dst_port] += 1

        length = pkt.get("length", 0)
        if isinstance(length, int):
            self.packet_sizes.append(length)

        # Port scan tracking
        if src and dst_port:
            self._ip_dst_ports[src].add(dst_port)

        return self._detect_anomaly(pkt, now)

    # ── Anomaly detection ────────────────────────────────────────────────────
    def _detect_anomaly(self, pkt: dict, now: float) -> Optional[dict]:
        src = pkt.get("src_ip", "")
        flags = pkt.get("flags", "")
        length = pkt.get("length", 0)

        # Reset SYN window every second
        if now - self._syn_window_start > 1:
            self._syn_counts.clear()
            self._syn_window_start = now

        if "S" in flags and "A" not in flags:
            self._syn_counts[src] += 1

        alert = None

        if src and src not in self._alerted_ips:
            if self._syn_counts.get(src, 0) > self.SYN_FLOOD_THRESHOLD:
                alert = self._make_alert("SYN Flood", src, "HIGH",
                    f"Possible SYN flood from {src}: {self._syn_counts[src]} SYNs/sec")
            elif self.src_ip_counts.get(src, 0) > self.RATE_PER_IP_THRESHOLD:
                alert = self._make_alert("High Traffic Rate", src, "MEDIUM",
                    f"Unusually high traffic from {src}: {self.src_ip_counts[src]} packets")
            elif len(self._ip_dst_ports.get(src, set())) > self.PORT_SCAN_THRESHOLD:
                alert = self._make_alert("Port Scan", src, "HIGH",
                    f"Possible port scan from {src}: {len(self._ip_dst_ports[src])} unique ports")

        if isinstance(length, int) and length > self.LARGE_PACKET_THRESHOLD:
            alert = self._make_alert("Large Packet", src, "LOW",
                f"Abnormally large packet ({length}B) from {src}")

        if alert:
            self._alerted_ips.add(src)
        return alert

    def _make_alert(self, kind: str, src: str, severity: str, msg: str) -> dict:
        alert = {
            "id": len(self.alerts),
            "type": kind,
            "src_ip": src,
            "severity": severity,
            "message": msg,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.alerts.append(alert)
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        return alert

    # ── Stats snapshot ───────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        total = self.total_packets or 1
        sizes = self.packet_sizes[-5000:] if self.packet_sizes else [0]

        return {
            "total_packets": self.total_packets,
            "packet_rate": len(self._timestamps),  # packets in last second
            "unique_src_ips": len(self.src_ip_counts),
            "unique_dst_ips": len(self.dst_ip_counts),
            "protocol_distribution": {
                k: {"count": v, "pct": round(v / total * 100, 1)}
                for k, v in sorted(self.protocol_counts.items(),
                                   key=lambda x: -x[1])
            },
            "top_src_ips": dict(
                sorted(self.src_ip_counts.items(), key=lambda x: -x[1])[:10]
            ),
            "top_dst_ips": dict(
                sorted(self.dst_ip_counts.items(), key=lambda x: -x[1])[:10]
            ),
            "top_ports": dict(
                sorted(self.port_counts.items(), key=lambda x: -x[1])[:10]
            ),
            "packet_size": {
                "avg": round(sum(sizes) / len(sizes), 1),
                "min": min(sizes),
                "max": max(sizes),
                "histogram": self._histogram(sizes),
            },
            "alert_count": len(self.alerts),
        }

    def get_alerts(self) -> list:
        return list(reversed(self.alerts))

    def _histogram(self, sizes: list, bins: int = 8) -> list[dict]:
        if not sizes:
            return []
        lo, hi = min(sizes), max(sizes)
        if lo == hi:
            return [{"range": f"{lo}", "count": len(sizes)}]
        step = (hi - lo) / bins
        counts = [0] * bins
        for s in sizes:
            idx = min(int((s - lo) / step), bins - 1)
            counts[idx] += 1
        return [
            {"range": f"{int(lo + i*step)}-{int(lo + (i+1)*step)}", "count": counts[i]}
            for i in range(bins)
        ]
