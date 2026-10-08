"""FastAPI Server and WebSocket Event Hub for CICFlowMeter Live Dashboard

Provides:
- REST API (/api/stats, /api/flows, /api/alerts, /api/clear)
- WebSocket (/ws) for zero-latency live flow and alert streaming
- Color-based severity mapping (DDoS/DoS -> Critical, Brute Force -> High, Port Scan -> Medium)
- Static file hosting for the React dashboard UI
- Automatic browser launcher
- Background daemon server runner
"""

import os
import json
import asyncio
import logging
import threading
import webbrowser
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .alerts import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_NORMAL,
    SEVERITY_COLOR_MAP, ATTACK_SEVERITY_MAP
)

logger = logging.getLogger("cicflowmeter.server")

# Maximum items to keep in memory buffers
MAX_FLOWS_BUFFER = 1000
MAX_ALERTS_BUFFER = 500

class DashboardState:
    """Thread-safe store for live capture statistics and recent events."""

    def __init__(self):
        self.lock = threading.RLock()
        self.total_flows = 0
        self.total_attacks = 0
        self.normal_traffic = 0
        self.severity_counts = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 0,
            SEVERITY_MEDIUM: 0,
            SEVERITY_NORMAL: 0,
        }
        self.category_counts = {
            "DDoS": 0,
            "DoS": 0,
            "Brute Force": 0,
            "Port Scan": 0,
            "Normal Traffic": 0,
        }
        self.top_attackers: Dict[str, int] = {}
        self.top_targets: Dict[str, int] = {}
        self.recent_flows: deque = deque(maxlen=MAX_FLOWS_BUFFER)
        self.recent_alerts: deque = deque(maxlen=MAX_ALERTS_BUFFER)
        self.start_time = None
        self.active_interface: Optional[str] = None
        self.ml_enabled: bool = False
        self.psd_enabled: bool = False

    def add_flow_event(self, event: Dict[str, Any]) -> None:
        """Update aggregate counts and store the event."""
        with self.lock:
            self.total_flows += 1
            severity = event.get("severity", SEVERITY_NORMAL)
            label = event.get("label", "Normal Traffic")
            is_attack = event.get("is_attack", False)
            src_ip = event.get("src_ip", "")
            dst_ip = event.get("dst_ip", "")

            if is_attack:
                self.total_attacks += 1
                self.top_attackers[src_ip] = self.top_attackers.get(src_ip, 0) + 1
                self.top_targets[dst_ip] = self.top_targets.get(dst_ip, 0) + 1
                self.recent_alerts.appendleft(event)
            else:
                self.normal_traffic += 1

            self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1
            self.category_counts[label] = self.category_counts.get(label, 0) + 1
            self.recent_flows.appendleft(event)

    def get_summary(self) -> Dict[str, Any]:
        """Return a snapshot of current metrics."""
        with self.lock:
            # Sort top 5 attackers and targets
            sorted_attackers = sorted(self.top_attackers.items(), key=lambda x: x[1], reverse=True)[:5]
            sorted_targets = sorted(self.top_targets.items(), key=lambda x: x[1], reverse=True)[:5]

            return {
                "total_flows": self.total_flows,
                "total_attacks": self.total_attacks,
                "normal_traffic": self.normal_traffic,
                "attack_rate": (self.total_attacks / self.total_flows * 100) if self.total_flows > 0 else 0.0,
                "severity_counts": dict(self.severity_counts),
                "category_counts": dict(self.category_counts),
                "top_attackers": dict(sorted_attackers),
                "top_targets": dict(sorted_targets),
                "interface": self.active_interface,
                "ml_enabled": self.ml_enabled,
                "psd_enabled": self.psd_enabled,
                "severity_colors": SEVERITY_COLOR_MAP,
            }

    def clear(self) -> None:
        """Reset historical data."""
        with self.lock:
            self.total_flows = 0
            self.total_attacks = 0
            self.normal_traffic = 0
            for k in self.severity_counts:
                self.severity_counts[k] = 0
            for k in self.category_counts:
                self.category_counts[k] = 0
            self.top_attackers.clear()
            self.top_targets.clear()
            self.recent_flows.clear()
            self.recent_alerts.clear()


state = DashboardState()

# WebSocket client manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self.lock:
            self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        with self.lock:
            self.active_connections.discard(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        dead_connections = []
        with self.lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)

        if dead_connections:
            with self.lock:
                for dc in dead_connections:
                    self.active_connections.discard(dc)


connection_manager = ConnectionManager()
loop_holder: Dict[str, Optional[asyncio.AbstractEventLoop]] = {"loop": None}

# Initialize FastAPI
app = FastAPI(title="CICFlowMeter Live IDS Dashboard", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    loop_holder["loop"] = asyncio.get_running_loop()
    logger.info("FastAPI dashboard server event loop registered.")


@app.get("/api/stats")
async def get_stats():
    return JSONResponse(content=state.get_summary())


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    with state.lock:
        alerts = list(state.recent_alerts)[:limit]
    return JSONResponse(content=alerts)


@app.get("/api/flows")
async def get_flows(limit: int = 100):
    with state.lock:
        flows = list(state.recent_flows)[:limit]
    return JSONResponse(content=flows)


@app.post("/api/clear")
async def clear_data():
    state.clear()
    msg = {"type": "clear", "stats": state.get_summary()}
    if loop_holder["loop"]:
        asyncio.run_coroutine_threadsafe(connection_manager.broadcast_json(msg), loop_holder["loop"])
    return {"status": "ok", "message": "State cleared"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await connection_manager.connect(websocket)
    try:
        # Send initial state immediately upon connection
        with state.lock:
            init_payload = {
                "type": "init",
                "stats": state.get_summary(),
                "recent_flows": list(state.recent_flows)[:50],
                "recent_alerts": list(state.recent_alerts)[:30],
            }
        await websocket.send_text(json.dumps(init_payload))

        while True:
            # Keep alive and receive any client events (e.g. ping)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket client error: {e}")
        connection_manager.disconnect(websocket)


# Function called from main.py
def broadcast_flow(flow_event: Dict[str, Any]) -> None:
    """Thread-safe function to broadcast a completed flow and alert."""
    state.add_flow_event(flow_event)

    loop = loop_holder.get("loop")
    if loop and loop.is_running():
        msg = {
            "type": "flow",
            "flow": flow_event,
            "stats": state.get_summary()
        }
        asyncio.run_coroutine_threadsafe(connection_manager.broadcast_json(msg), loop)


def set_system_metadata(interface: Optional[str] = None, ml: bool = False, psd: bool = False):
    """Set metadata visible on UI header."""
    state.active_interface = interface
    state.ml_enabled = ml
    state.psd_enabled = psd


STATIC_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
(STATIC_DIR / "assets").mkdir(parents=True, exist_ok=True)
app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

from fastapi.responses import FileResponse

@app.get("/", include_in_schema=False)
async def serve_root():
    return FileResponse(str(STATIC_DIR / "index.html"))

@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    return FileResponse(str(STATIC_DIR / "index.html"))


def start_dashboard_server(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> threading.Thread:
    """Run FastAPI inside a background daemon thread and auto-open browser."""
    import uvicorn

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True, name="FastAPIDashboardServer")
    thread.start()

    url = f"http://{host}:{port}"
    print(f"\n[FastAPI] Dashboard server running at: {url}")

    if open_browser:
        # Check if running as root on Unix, because browsers crash when opened as root without sandbox
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            print(f"[FastAPI] Running as root. Auto-browser launch disabled to prevent sandbox crash.")
            print(f"[FastAPI] Please open {url} manually in your regular browser.")
        else:
            def _open():
                # Small delay to ensure the HTTP server is listening
                import time
                time.sleep(1.2)
                try:
                    print(f"[FastAPI] Launching web UI at {url}...")
                    webbrowser.open(url)
                except Exception as e:
                    logger.warning(f"Failed to auto-open browser: {e}")

            threading.Thread(target=_open, daemon=True).start()

    return thread
