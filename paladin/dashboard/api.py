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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from paladin.dashboard.auth import (
    check_credentials, create_access_token, login_locked, record_login_failure,
    reset_login_failures, verify_token, verify_ws_token,
)

log = structlog.get_logger(__name__)

app = FastAPI(title="Paladin Security Dashboard", version="2.1.0")

WS_AUTH_TIMEOUT_SECONDS = 10

# ── Global references (set by main.py at startup) ────────────────────────────
_neo4j = None
_event_bus: asyncio.Queue | None = None
_connected_ws: list[WebSocket] = []
_auto_exec = None
_forensic_plan_mgr = None
_hallucination_tracker = None
_approval_broker = None
_demo_started = False


def init_dashboard(neo4j_client, event_bus: asyncio.Queue, auto_exec=None,
                   forensic_plan_mgr=None, hallucination_tracker=None,
                   approval_broker=None):
    global _neo4j, _event_bus, _auto_exec, _forensic_plan_mgr, _hallucination_tracker
    global _approval_broker
    _neo4j = neo4j_client
    _event_bus = event_bus
    _auto_exec = auto_exec
    _forensic_plan_mgr = forensic_plan_mgr
    _hallucination_tracker = hallucination_tracker
    _approval_broker = approval_broker


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
async def login(req: LoginRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if login_locked(client):
        log.warning("login_locked", client=client)
        raise HTTPException(status_code=429, detail="Too many failed attempts, try again later")
    if check_credentials(req.username, req.password):
        reset_login_failures(client)
        token = create_access_token({"sub": req.username})
        return {"access_token": token, "token_type": "bearer"}
    record_login_failure(client)
    log.warning("login_failed", client=client, username=req.username)
    raise HTTPException(status_code=401, detail="Incorrect username or password")


# ── Incidents ─────────────────────────────────────────────────────────────────

# Action states in which the proposed action has not been enforced yet
_UNEXECUTED_STATES = {"pending", "awaiting_operator"}


@app.get("/api/incidents")
async def get_incidents(
    status: Optional[str] = Query(None, description="Filter by status or action_status"),
    limit: int = Query(50, le=200),
    user: dict = Depends(verify_token),
):
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    incidents = await _neo4j.get_open_incidents(limit=limit)
    if status:
        incidents = [i for i in incidents
                     if status in (i.get("status"), i.get("action_status"))]
    return {"incidents": incidents, "count": len(incidents)}


@app.post("/api/incidents/action")
async def handle_incident_action(action: IncidentAction, user: dict = Depends(verify_token)):
    """
    approve → the proposed action is EXECUTED now (if it hasn't been already)
    reject  → the proposed action is cancelled and never executed
    """
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    if action.decision not in ("approve", "reject"):
        raise HTTPException(400, "Decision must be 'approve' or 'reject'")

    incident = await _neo4j.get_incident_for_action(action.incident_id)
    if not incident:
        raise HTTPException(404, f"Incident {action.incident_id} not found")

    operator = user.get("sub", "operator")
    execution_note = None
    if action.decision == "approve":
        if incident.get("action_status") in _UNEXECUTED_STATES:
            if not _auto_exec:
                raise HTTPException(503, "AutoExecutor not available")
            execution_note = await _auto_exec.execute(incident, by_operator=operator)
        new_status = "resolved"
        updates = {"status": new_status,
                   "operator_note": f"[{operator}] approved: {action.reason}"
                                    + (f" | {execution_note}" if execution_note else "")}
    else:
        new_status = "rejected"
        updates = {"status": new_status,
                   "operator_note": f"[{operator}] rejected: {action.reason}"}
        if incident.get("action_status") in _UNEXECUTED_STATES:
            updates["action_status"] = "rejected"

    await _neo4j.update_incident(action.incident_id, updates)
    log.info("operator_decision", incident_id=action.incident_id,
             decision=action.decision, operator=operator, executed=execution_note is not None)

    # Broadcast to WebSocket clients
    await _broadcast({
        "type": "incident_update",
        "incident_id": action.incident_id,
        "status": new_status,
        "decision": action.decision,
    })

    return {"ok": True, "incident_id": action.incident_id, "status": new_status,
            "executed": execution_note is not None, "execution_note": execution_note}


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

SCENARIOS = {
    "logs": {"brute_force", "data_exfiltration", "insider_threat", "privilege_escalation"},
    "emails": {"phishing", "data_leak_email", "social_engineering", "external_exfil"},
    "messages": {"insider_chat", "credential_sharing", "competitor_contact"},
    "calls": {"data_theft_call", "insider_recruitment", "bribery_call"},
}


@app.post("/api/scenario")
async def trigger_scenario(req: ScenarioRequest, user: dict = Depends(verify_token)):
    if not _event_bus:
        raise HTTPException(503, "Event bus not initialized")
    if req.scenario not in SCENARIOS.get(req.source, set()):
        raise HTTPException(400, f"Scenario '{req.scenario}' does not exist for source '{req.source}'")
    # Put scenario request on the event bus for the orchestrator to pick up
    await _event_bus.put({
        "type": "scenario_trigger",
        "scenario": req.scenario,
        "source": req.source,
        "actor_uid": req.actor_uid,
    })
    return {"ok": True, "scenario": req.scenario}


# ── Demo Start Trigger ────────────────────────────────────────────────────────

@app.post("/api/demo/start")
async def start_demo(user: dict = Depends(verify_token)):
    global _demo_started
    _demo_started = True
    # Broadcast to websocket that demo started
    await _broadcast({
        "type": "demo_started",
        "message": "The showcase demo has been triggered."
    })
    return {"ok": True, "demo_started": True}


# ── Mode Toggle ───────────────────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str

@app.get("/api/config/mode")
async def get_mode(user: dict = Depends(verify_token)):
    if not _auto_exec:
        raise HTTPException(503, "AutoExecutor not available")
    return {"mode": _auto_exec.mode, "timeout": _auto_exec.timeout}


@app.post("/api/config/mode")
async def set_mode(req: ModeRequest, user: dict = Depends(verify_token)):
    if not _auto_exec:
        raise HTTPException(503, "AutoExecutor not available")
    try:
        _auto_exec.set_mode(req.mode)
    except ValueError:
        raise HTTPException(400, "Invalid mode")
    log.info("mode_changed", mode=req.mode, operator=user.get("sub"))
    return {"ok": True, "mode": _auto_exec.mode, "timeout": _auto_exec.timeout}


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
        "forensic_enabled": _forensic_plan_mgr is not None,
        "mode": _auto_exec.mode if _auto_exec else None,
        "pending_forensic_approvals": len(_approval_broker.pending()) if _approval_broker else 0,
        "demo_started": _demo_started,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# ── Forensic API (Paladin 2.0) ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/forensic/plan/{plan_id}")
async def get_forensic_plan(plan_id: str, user: dict = Depends(verify_token)):
    """Get forensic plan with all todo items and findings."""
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    plan = await _neo4j.get_plan_with_items(plan_id)
    if not plan:
        raise HTTPException(404, f"Plan {plan_id} not found")
    return plan


@app.get("/api/forensic/incident/{incident_id}")
async def get_forensic_plan_for_incident(incident_id: str,
                                          user: dict = Depends(verify_token)):
    """Get forensic plan for a specific incident."""
    if not _neo4j:
        raise HTTPException(503, "Neo4j not connected")
    plan = await _neo4j.get_forensic_plan_for_incident(incident_id)
    if not plan:
        return {"plan": None, "message": "No forensic plan for this incident"}
    return plan


@app.get("/api/forensic/accuracy/{plan_id}")
async def get_accuracy_report(plan_id: str, user: dict = Depends(verify_token)):
    """Generate accuracy report for a forensic plan."""
    if not _hallucination_tracker:
        raise HTTPException(503, "Hallucination tracker not available")
    report = await _hallucination_tracker.generate_accuracy_report(plan_id)
    return report


class ApprovalDecisionRequest(BaseModel):
    decision: str  # "approve" or "deny"


@app.get("/api/forensic/approvals")
async def list_forensic_approvals(user: dict = Depends(verify_token)):
    """MCP calls classified REQUIRES_APPROVAL that are waiting for an operator."""
    if not _approval_broker:
        return {"pending": []}
    return {"pending": _approval_broker.pending()}


@app.post("/api/forensic/approvals/{request_id}")
async def decide_forensic_approval(request_id: str, req: ApprovalDecisionRequest,
                                   user: dict = Depends(verify_token)):
    """Approve or deny a parked MCP call. Unanswered requests auto-deny on timeout."""
    if not _approval_broker:
        raise HTTPException(503, "Approval broker not available")
    if req.decision not in ("approve", "deny"):
        raise HTTPException(400, "Decision must be 'approve' or 'deny'")
    approved = req.decision == "approve"
    if not _approval_broker.resolve(request_id, approved, user.get("sub", "operator")):
        raise HTTPException(404, "Approval request not found or already resolved")
    await _broadcast({"type": "forensic_approval_resolved", "request_id": request_id,
                      "approved": approved, "reason": "operator"})
    return {"ok": True, "request_id": request_id, "approved": approved}


# ── WebSocket for live updates ────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    # First message must be "Bearer <token>"; unauthenticated sockets are dropped
    try:
        auth_data = await asyncio.wait_for(ws.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await _safe_close(ws)
        return

    token = auth_data[len("Bearer "):] if auth_data.startswith("Bearer ") else ""
    if not token or not verify_ws_token(token):
        await ws.send_text("error: Unauthorized")
        await _safe_close(ws)
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
        pass
    except Exception as e:
        log.warning("ws_error", error=str(e))
    finally:
        if ws in _connected_ws:
            _connected_ws.remove(ws)
        log.info("ws_disconnected", total=len(_connected_ws))


async def _safe_close(ws: WebSocket) -> None:
    try:
        await ws.close()
    except Exception:
        pass


async def _broadcast(message: dict):
    """Send message to all connected WebSocket clients."""
    text = json.dumps(message, default=str)
    disconnected = []
    for ws in list(_connected_ws):
        try:
            await ws.send_text(text)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in _connected_ws:
            _connected_ws.remove(ws)


async def broadcast_event(message: dict):
    """Public API for modules that emit typed events ({"type": ..., ...}) as-is."""
    await _broadcast(message)


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
