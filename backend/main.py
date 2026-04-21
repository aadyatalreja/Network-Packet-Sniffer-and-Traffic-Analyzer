"""
Packet Sniffer - FastAPI Backend
Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
(Run as Administrator on Windows for real packet capture)
"""

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn

from backend.packet_capture import PacketCapture
from backend.analyzer import TrafficAnalyzer
from backend.database import Database

# ── Globals ───────────────────────────────────────────────────────────────────
db       = Database()
analyzer = TrafficAnalyzer()
capture  = PacketCapture(db, analyzer)
connected_clients: list[WebSocket] = []


# ── App lifespan ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    # ← FIX: store the running event loop NOW (in the async context),
    #   so capture threads can schedule broadcasts onto it later
    capture._loop = asyncio.get_running_loop()
    yield
    capture.stop()
    db.close()


app = FastAPI(title="Packet Sniffer API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket broadcast helper ────────────────────────────────────────────────
async def broadcast(data: dict):
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        connected_clients.remove(ws)


capture.set_broadcast_callback(broadcast)


# ── Frontend ──────────────────────────────────────────────────────────────────
@app.get("/")
async def serve_frontend():
    # Look for index.html next to main.py, or one level up in frontend/
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "index.html"),
        os.path.join(here, "..", "frontend", "index.html"),
        os.path.join(here, "frontend", "index.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return FileResponse(path)
    return {"error": "index.html not found", "searched": candidates}


# ── REST endpoints ────────────────────────────────────────────────────────────
@app.post("/start_capture")
async def start_capture(interface: str = "eth0", filter: Optional[str] = None):
    if capture.is_running:
        return {"status": "already_running"}
    capture.start(interface=interface, bpf_filter=filter)
    return {"status": "started", "interface": interface, "filter": filter}


@app.post("/stop_capture")
async def stop_capture():
    capture.stop()
    return {"status": "stopped"}


@app.get("/capture_status")
async def capture_status():
    return {
        "running":       capture.is_running,
        "interface":     capture.current_interface,
        "filter":        capture.current_filter,
        "packet_count":  analyzer.total_packets,
    }


@app.get("/traffic_stats")
async def traffic_stats():
    return analyzer.get_stats()


@app.get("/packets")
async def get_packets(limit: int = 500):
    return db.get_recent_packets(limit)


@app.get("/alerts")
async def get_alerts():
    return analyzer.get_alerts()


@app.get("/interfaces")
async def list_interfaces():
    try:
        from scapy.all import conf as scapy_conf
        scapy_conf.use_pcap = True          # ← required on Windows
        ifaces = []
        for name, iface in scapy_conf.ifaces.items():
            desc = getattr(iface, "description", "") or getattr(iface, "name", name)
            ip   = getattr(iface, "ip", "") or ""
            # include all interfaces that have a GUID-style name
            ifaces.append({"id": name, "description": desc, "ip": ip})
        return {"interfaces": ifaces}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


@app.get("/export_pcap")
async def export_pcap():
    path = capture.export_pcap()
    if path:
        return FileResponse(path, filename="capture.pcap", media_type="application/octet-stream")
    return {"error": "No capture data available"}


# ── WebSocket endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        await websocket.send_json({"type": "stats", "data": analyzer.get_stats()})
        while True:
            await asyncio.sleep(1)
            if capture.is_running:
                await websocket.send_json({
                    "type": "stats",
                    "data": analyzer.get_stats(),
                })
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
    except Exception:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)