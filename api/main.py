"""
api/main.py — FastAPI dashboard: serves the HTML client and broadcasts every
SecurityEvent (plus kill-chain incident escalations) to connected browsers
over a /ws WebSocket.
"""

import asyncio
import json
import threading
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from xdr.core.event_bus import ENGINE
from xdr.core.events import SecurityEvent
from xdr.correlation.kill_chain_rules import KillChainCorrelator

TEMPLATES_DIR = Path(__file__).parent / "templates"

engine_ready = threading.Event()


class EventBusManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)


bus_manager = EventBusManager()

kill_chain = KillChainCorrelator(window_duration=300.0, on_incident=bus_manager.broadcast)


def serialize_event(event: SecurityEvent) -> str:
    payload = asdict(event)
    payload["vector"] = event.vector.value
    return json.dumps(payload)


async def drain_engine_to_dashboard():
    ENGINE.bind_loop()
    engine_ready.set()

    while True:
        event = await ENGINE.get()
        await bus_manager.broadcast(serialize_event(event))
        await kill_chain.add_event(event)


async def inject_event_to_dashboard(event_json: str):
    await bus_manager.broadcast(event_json)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(drain_engine_to_dashboard())
    yield
    task.cancel()


app = FastAPI(title="XDR Real-Time Correlator Dashboard", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def get_index():
    return (TEMPLATES_DIR / "index.html").read_text()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await bus_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        bus_manager.disconnect(websocket)
