"""
Paladin Dashboard — FastAPI backend.
Three sections:
1. /incidents — real-time incident feed with approve/reject
2. /actions — full action log
3. /graph — incident subgraph for visualization
Plus WebSocket for live updates.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from paladin.dashboard.auth import create_access_token, verify_token, verify_ws_token

log = structlog.get_logger(__name__)

app = FastAPI(title="Paladin Security Dashboard", version="0.1.0")

# ── Global references (set by main.py at startup) ────────────────────────────
_neo4j = None
_event_bus: asyncio.Queue | None = None
_connected_ws: list[WebSocket] = []
_auto_exec = None


def init_dashboard(neo4j_client, event_bus: asyncio.Queue, auto_exec=None):
    global _neo4j, _event_bus, _auto_exec
    _neo4j = neo4j_client
    _event_bus = event_bus
    _auto_exec = auto_exec


# ── Models ────────────────────────────────────────────────────────────────────

class IncidentAction(BaseModel):
    incident_id: str
    decision: str  # "approve" or "reject"
    reason: str


class ScenarioRequest(BaseModel):
    scenario: str
    source: str  # "logs", "emails", "messages", "calls"
    actor_uid: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    # Dummy auth for demo
    if req.username == "admin" and req.password == "admin":
        token = create_access_token({"sub": req.username})
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Incorrect username or password")


# ── Incidents ─────────────────────────────────────────────────────────────────

@app.get("/api/incidents")
async def get_incidents(
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    user: dict = Depends(verify_token),
):
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    incidents = await _neo4j.get_open_incidents(limit=limit)
    return {"incidents": incidents, "count": len(incidents)}


@app.post("/api/incidents/action")
async def handle_incident_action(action: IncidentAction, user: dict = Depends(verify_token)):
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    if action.decision not in ("approve", "reject"):
        raise HTTPException(400, "Decision must be 'approve' or 'reject'")

    new_status = "resolved" if action.decision == "approve" else "rejected"
    await _neo4j.update_incident(action.incident_id, {
        "action_status": action.decision,
        "status": new_status,
        "operator_note": action.reason,
    })

    # Broadcast to WebSocket clients
    await _broadcast({
        "type": "incident_update",
        "incident_id": action.incident_id,
        "status": new_status,
        "decision": action.decision,
    })

    return {"ok": True, "incident_id": action.incident_id, "status": new_status}


# ── Action Log ────────────────────────────────────────────────────────────────

@app.get("/api/actions")
async def get_action_log(
    action_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    user: dict = Depends(verify_token),
):
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    actions = await _neo4j.get_action_log(limit=limit, action_type=action_type)
    return {"actions": actions, "count": len(actions)}


# ── Graph Viewer ──────────────────────────────────────────────────────────────

@app.get("/api/graph/{incident_id}")
async def get_incident_graph(incident_id: str, user: dict = Depends(verify_token)):
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    subgraph = await _neo4j.get_incident_subgraph(incident_id)
    return subgraph


# ── Scenario Trigger (for demo/testing) ───────────────────────────────────────

@app.post("/api/scenario")
async def trigger_scenario(req: ScenarioRequest, user: dict = Depends(verify_token)):
    if not _event_bus:
        raise HTTPException(503, "Event bus not initialized")
    # Put scenario request on the event bus for the orchestrator to pick up
    await _event_bus.put({
        "type": "scenario_trigger",
        "scenario": req.scenario,
        "source": req.source,
        "actor_uid": req.actor_uid,
    })
    return {"ok": True, "scenario": req.scenario}


# ── Mode Toggle ───────────────────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str

@app.post("/api/config/mode")
async def set_mode(req: ModeRequest, user: dict = Depends(verify_token)):
    if not _auto_exec:
        raise HTTPException(503, "AutoExecutor not available")
    
    if req.mode == "autonomous":
        _auto_exec.set_timeout(0)
    elif req.mode == "human_in_loop":
        _auto_exec.set_timeout(60)
    else:
        raise HTTPException(400, "Invalid mode")
        
    return {"ok": True, "mode": req.mode, "timeout": _auto_exec._timeout}


# ── System Status ─────────────────────────────────────────────────────────────

@app.get("/api/status")
async def system_status(user: dict = Depends(verify_token)):
    neo4j_ok = False
    if _neo4j:
        try:
            async with _neo4j._driver.session() as s:
                await s.run("RETURN 1")
            neo4j_ok = True
        except Exception:
            pass

    return {
        "neo4j": "online" if neo4j_ok else "offline",
        "websocket_clients": len(_connected_ws),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── WebSocket for live updates ────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    
    # Wait for authentication message
    auth_data = await ws.receive_text()
    token_valid = False
    if auth_data.startswith("Bearer "):
        token = auth_data.split(" ")[1]
        if verify_ws_token(token):
            token_valid = True
            
    if not token_valid:
        await ws.send_text("error: Unauthorized")
        await ws.close()
        return

    _connected_ws.append(ws)
    log.info("ws_connected", total=len(_connected_ws))
    try:
        while True:
            # Keep connection alive, receive pings
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        _connected_ws.remove(ws)
        log.info("ws_disconnected", total=len(_connected_ws))


async def _broadcast(message: dict):
    """Send message to all connected WebSocket clients."""
    text = json.dumps(message, default=str)
    disconnected = []
    for ws in _connected_ws:
        try:
            await ws.send_text(text)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        _connected_ws.remove(ws)


async def broadcast_incident(incident_data: dict):
    """Public API for other modules to push incident updates."""
    await _broadcast({
        "type": "new_incident",
        "data": incident_data,
    })


# ── Serve frontend ───────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return FileResponse("paladin/dashboard/frontend/index.html")


# Mount static files
try:
    app.mount("/static", StaticFiles(directory="paladin/dashboard/frontend"), name="static")
except Exception:
    pass  # Frontend directory may not exist yet
