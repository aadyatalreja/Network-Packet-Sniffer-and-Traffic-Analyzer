"""
SQLite persistence layer for captured packet metadata.
"""

import sqlite3
import threading
from typing import Optional


class Database:
    DB_PATH = "packets.db"

    def __init__(self):
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

    def init(self):
        self._conn = sqlite3.connect(self.DB_PATH, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip    TEXT,
                    dst_ip    TEXT,
                    src_port  TEXT,
                    dst_port  TEXT,
                    protocol  TEXT,
                    length    INTEGER,
                    flags     TEXT
                )
            """)
            self._conn.commit()

    def insert_packet(self, pkt: dict):
        with self._lock:
            self._conn.execute(
                """INSERT INTO packets
                   (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pkt.get("timestamp"),
                    pkt.get("src_ip"),
                    pkt.get("dst_ip"),
                    pkt.get("src_port"),
                    pkt.get("dst_port"),
                    pkt.get("protocol"),
                    pkt.get("length"),
                    pkt.get("flags"),
                ),
            )
            self._conn.commit()

    def get_recent_packets(self, limit: int = 500) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = cur.fetchall()
        return [dict(r) for r in reversed(rows)]

    def close(self):
        if self._conn:
            self._conn.close()
