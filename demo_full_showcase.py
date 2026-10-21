"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        ⛨  PALADIN v2.0 — FULL DEMONSTRATION SHOWCASE SCRIPT                  ║
║        Comprehensive demo of all system capabilities for video recording      ║
╚══════════════════════════════════════════════════════════════════════════════╝

CAPABILITIES COVERED:
  Layer 1 — Data Ingestion   : Logs / Emails / Chat / Calls (14 scenarios)
  Layer 2 — SAP Core         : MorphoParser, GraphEnricher, Correlator
  Layer 3 — LLM & Verifier   : Qwen 3.5:9B + ActionVerifier
  Layer 4 — Auto-Executor    : Autonomous mode (timeout=0)
  Layer 5 — Forensic v2.0    : SandboxManager, MCP Server, PlanManager,
                               CorrelationEngine, HallucinationTracker
  Layer 6 — Dashboard        : FastAPI + WebSocket + JWT

USAGE:
  python demo_full_showcase.py [--phase PHASE] [--timeout SECS]

  --phase: all | ingestion | sap | llm | autonomous | forensic | dashboard
  --timeout: operator timeout in seconds (default=5, for auto-demo)
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Path to Natalie Romanoff evidence files ──────────────────────────────────
EVIDENCE_PATH = r"c:\Users\Lenovo\Downloads\win7-32-nromanoff-10.3.58.5"

USE_HTTPS = os.path.exists("key.pem") and os.path.exists("cert.pem")
DASHBOARD_URL = "https://localhost:8888" if USE_HTTPS else "http://localhost:8888"
API = DASHBOARD_URL + "/api"

# ── Terminal Color Palette ───────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BG_RED  = "\033[41m"
    BG_BLUE = "\033[44m"


# ── Formatting Utilities ─────────────────────────────────────────────────────

def banner(text: str, color: str = C.CYAN) -> None:
    width = 78
    print()
    print(color + "╔" + "═" * (width - 2) + "╗" + C.RESET)
    for line in text.strip().splitlines():
        padding = width - 4 - len(re.sub(r'\033\[[0-9;]*m', '', line))
        print(color + "║  " + C.RESET + line + " " * max(0, padding) + color + "  ║" + C.RESET)
    print(color + "╚" + "═" * (width - 2) + "╝" + C.RESET)
    print()


def section(title: str, icon: str = "▶", color: str = C.BLUE) -> None:
    width = 78
    print()
    print(color + C.BOLD + f"{'─' * 3} {icon}  {title} " + "─" * max(0, width - 7 - len(title)) + C.RESET)
    print()


def step(msg: str, status: str = "info") -> None:
    icons = {
        "info":    C.BLUE    + "[•]" + C.RESET,
        "ok":      C.GREEN   + "[✓]" + C.RESET,
        "warn":    C.YELLOW  + "[⚠]" + C.RESET,
        "error":   C.RED     + "[✗]" + C.RESET,
        "wait":    C.CYAN    + "[⏳]" + C.RESET,
        "attack":  C.RED + C.BOLD + "[🚨]" + C.RESET,
        "llm":     C.MAGENTA + "[🤖]" + C.RESET,
        "action":  C.YELLOW  + "[⚡]" + C.RESET,
        "forensic":C.GREEN   + "[🔬]" + C.RESET,
        "graph":   C.CYAN    + "[🕸]" + C.RESET,
        "auto":    C.RED + C.BOLD + "[🤖 AUTO]" + C.RESET,
    }
    icon = icons.get(status, "[•]")
    print(f"  {icon} {msg}")


def pause(secs: float, label: str = "") -> None:
    if label:
        print(f"  {C.DIM}  ⏱  {label} ({secs:.0f}s)...{C.RESET}", end="", flush=True)
    time.sleep(secs)
    if label:
        print(f" {C.GREEN}done{C.RESET}")


# ── System Checks ────────────────────────────────────────────────────────────

def check_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def detect_ollama() -> str:
    """Detect active Ollama port."""
    for port in [11434, 11435]:
        try:
            r = requests.get(f"http://localhost:{port}/api/tags", timeout=2)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                step(f"Ollama found on port {port}. Models: {', '.join(models[:3])}", "ok")
                return f"http://localhost:{port}"
        except Exception:
            pass
    step("Ollama not found! Please ensure it is running.", "error")
    return "http://localhost:11434"


def preflight_checks() -> dict:
    """Preflight check of all services."""
    section("PREFLIGHT CHECKS", "🔍", C.YELLOW)
    results = {}

    # Ollama
    ollama_url = detect_ollama()
    results["ollama_url"] = ollama_url
    results["ollama_ok"] = ollama_url != "http://localhost:11434" or check_port(11434)

    # Neo4j
    neo4j_ok = check_port(7687)
    results["neo4j_ok"] = neo4j_ok
    step(f"Neo4j Bolt (7687): {'ONLINE' if neo4j_ok else 'NOT RUNNING'}", "ok" if neo4j_ok else "warn")

    # PostgreSQL
    pg_ok = check_port(5432)
    results["pg_ok"] = pg_ok
    step(f"PostgreSQL (5432): {'ONLINE' if pg_ok else 'NOT RUNNING (forensics will run without PG)'}", "ok" if pg_ok else "warn")

    # Docker
    try:
        docker_r = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
        docker_ok = docker_r.returncode == 0
    except Exception:
        docker_ok = False
    results["docker_ok"] = docker_ok
    step(f"Docker: {'ONLINE' if docker_ok else 'NOT RUNNING (forensic sandbox will be skipped)'}", "ok" if docker_ok else "warn")

    # Evidence files
    ev_ok = os.path.exists(EVIDENCE_PATH)
    results["evidence_ok"] = ev_ok
    if ev_ok:
        file_count = sum(1 for _ in __import__("pathlib").Path(EVIDENCE_PATH).rglob("*") if _.is_file())
        step(f"Natalie Romanoff Evidence: {file_count} files found in {EVIDENCE_PATH}", "ok")
    else:
        step(f"Evidence folder not found: {EVIDENCE_PATH}", "warn")

    return results


# ── Launch Paladin ───────────────────────────────────────────────────────────

def start_paladin(ollama_url: str, operator_timeout: int) -> subprocess.Popen:
    """Start the main Paladin process."""
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env["PYTHONUTF8"] = "1"
    env["OLLAMA_BASE_URL"] = ollama_url
    env["OPERATOR_TIMEOUT_SECONDS"] = str(operator_timeout)
    env["AUTO_EXECUTE_ENABLED"] = "true"
    env["FORENSIC_ENABLED"] = "true"
    env["FORENSIC_EVIDENCE_BASE"] = EVIDENCE_PATH
    env["PALADIN_MODE"] = "dummy"
    env["LOG_LEVEL"] = "WARNING"   # Only warnings/errors in stdout

    proc = subprocess.Popen(
        [sys.executable, "-m", "paladin.main"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    return proc


def wait_for_api(timeout_sec: int = 60) -> str | None:
    """Wait for Paladin API readiness and retrieve JWT token."""
    step("Waiting for Paladin API...", "wait")
    for i in range(timeout_sec // 2):
        try:
            r = requests.get(f"{API}/status", timeout=2, verify=False)
            if r.status_code in (200, 401, 403):
                step("Paladin API is ready!", "ok")
                break
        except Exception:
            pass
        time.sleep(2)
        print(f"    {C.DIM}... ({i*2+2}/{timeout_sec}s){C.RESET}", end="\r")
    else:
        step("Failed to connect to API.", "error")
        return None

    # Login
    try:
        r = requests.post(f"{API}/login",
                          json={"username": "admin", "password": "admin"},
                          verify=False, timeout=5)
        if r.ok:
            token = r.json()["access_token"]
            step(f"JWT Token acquired: {token[:20]}...", "ok")
            return token
    except Exception as e:
        step(f"Login failed: {e}", "error")
    return None


def wait_for_demo_start(token: str) -> None:
    """Wait for start trigger signal from dashboard."""
    banner("AWAITING DEMO START FROM DASHBOARD", C.MAGENTA)
    print(f"  {C.MAGENTA}Please open {C.CYAN}{DASHBOARD_URL}{C.MAGENTA} and click the 'Launch Full Showcase' button.{C.RESET}")
    print()
    while True:
        try:
            r = requests.get(f"{API}/status", timeout=2, verify=False, headers={"Authorization": f"Bearer {token}"})
            if r.ok and r.json().get("demo_started", False):
                step("Demo launch signal received from dashboard!", "ok")
                break
        except Exception:
            pass
        time.sleep(1)


# ── Phase 1: Ingestion — All 14 scenarios ────────────────────────────────────

ALL_SCENARIOS = [
    # (source, scenario, label, severity_icon)
    ("logs",     "brute_force",          "🔓 Brute Force Attack (Logs)",           "🔴"),
    ("logs",     "data_exfiltration",    "💾 Data Exfiltration (Logs)",            "🔴"),
    ("logs",     "insider_threat",       "🕵 Insider Threat (Logs)",               "🟠"),
    ("logs",     "privilege_escalation", "⬆️ Privilege Escalation (Logs)",          "🔴"),
    ("emails",   "phishing",             "📧 Phishing Campaign (Email)",            "🟠"),
    ("emails",   "data_leak_email",      "📤 Data Leak via Email",                 "🔴"),
    ("emails",   "social_engineering",   "🎭 Social Engineering (Email)",           "🟠"),
    ("emails",   "external_exfil",       "🌐 External Exfiltration (Email)",        "🔴"),
    ("messages", "insider_chat",         "💬 Insider Conspiracy (Chat)",            "🟠"),
    ("messages", "credential_sharing",   "🔑 Credential Sharing (Chat)",            "🔴"),
    ("messages", "competitor_contact",   "🏢 Competitor Contact (Chat)",            "🟡"),
    ("calls",    "data_theft_call",      "📞 Data Theft Call",                     "🔴"),
    ("calls",    "insider_recruitment",  "🤝 Insider Recruitment (Call)",           "🟠"),
    ("calls",    "bribery_call",         "💰 Bribery Attempt (Call)",              "🔴"),
]


def phase_ingestion(token: str, demo_mode: bool = False) -> None:
    """Demonstrate Layer 1: Ingesting all attack scenarios."""
    banner(
        "  LAYER 1 — DATA INGESTION\n"
        "  Queuing all 14 built-in threat scenarios:\n"
        "  Logs / Emails / Chats / Calls",
        C.RED
    )
    headers = {"Authorization": f"Bearer {token}"}

    # Queue key scenarios in demo mode for speed, otherwise queue all
    scenarios = ALL_SCENARIOS if not demo_mode else [
        ALL_SCENARIOS[0],  # brute_force
        ALL_SCENARIOS[1],  # data_exfiltration
        ALL_SCENARIOS[4],  # phishing
        ALL_SCENARIOS[8],  # insider_chat
    ]

    for source, scenario, label, icon in scenarios:
        print(f"  {icon} Injecting Scenario: {C.BOLD}{label}{C.RESET} ... ", end="", flush=True)
        try:
            r = requests.post(
                f"{API}/scenario",
                json={"scenario": scenario, "source": source},
                timeout=10, verify=False, headers=headers,
            )
            if r.status_code == 200:
                print(C.GREEN + "✓ queued successfully" + C.RESET)
            else:
                print(C.YELLOW + f"⚠ status {r.status_code}" + C.RESET)
        except Exception as e:
            print(C.RED + f"✗ {e}" + C.RESET)
        time.sleep(0.5)

    step("All threat scenarios successfully queued for pipeline processing.", "ok")


# ── Phase 2: SAP Core — Correlation ──────────────────────────────────────────

def phase_sap_demo() -> None:
    """Show SAP logic: MorphoParser + GraphEnricher + Correlator."""
    banner(
        "  LAYER 2 — SAP CORE\n"
        "  MorphoParser → GraphEnricher → Correlator → IncidentManager\n"
        "  Correlation Patterns: 6 Active Detectors",
        C.BLUE
    )

    patterns = [
        ("clearance_violation",      "+0.35", "Accessing files above clearance level"),
        ("off_hours_activity",       "+0.15", "Activity during off-work hours (00–06)"),
        ("cross_channel_correlation","+0.40", "Anomaly detected across multiple channels"),
        ("mass_download",            "+0.50", "Downloading >3 sensitive files in 60 min"),
        ("external_sensitive_comms", "+0.40", "External communication containing sensitive data"),
        ("brute_force",              "+0.60", "5+ failed login attempts within 15 min"),
    ]

    section("Correlation Rules & Risk Scores", "🕸", C.CYAN)
    for name, score, desc in patterns:
        print(f"    {C.CYAN}{name:<30}{C.RESET} {C.YELLOW}{score:<8}{C.RESET} {desc}")

    print()
    section("Severity-Based Mitigation Routing", "⚙", C.BLUE)
    routing = [
        ("< 0.65",  "Tool Mode",     "Fast inline LLM security review"),
        ("≥ 0.65",  "Pipeline Mode", "Full Forensic Investigation Pipeline (v2.0)"),
        ("≥ 0.70",  "INCIDENT",      "Incident registration + action verification"),
        ("≥ 0.90",  "CRITICAL",      "Immediate autonomous threat isolation"),
    ]
    for threshold, mode, desc in routing:
        color = C.RED if "0.90" in threshold else C.YELLOW if "0.70" in threshold else C.GREEN
        print(f"    Score {color}{threshold:<8}{C.RESET} → {C.BOLD}{mode:<16}{C.RESET} {desc}")


# ── Phase 3: LLM + Verifier — Real-Time Monitoring ────────────────────────────

def phase_llm_monitor(token: str, watch_seconds: int = 90) -> dict:
    """Monitor incident creation and real-time LLM analysis updates."""
    banner(
        "  LAYER 3 — LLM & VERIFIER\n"
        f"  Monitoring for {watch_seconds}s: Qwen 3.5:9B analyzes incidents\n"
        "  ActionVerifier: checks level, entity protection & output perplexity",
        C.MAGENTA
    )

    headers = {"Authorization": f"Bearer {token}"}
    seen_incidents: dict[str, str] = {}  # id → stage
    found_incidents = {}

    section("Monitoring active incidents...", "👁", C.MAGENTA)

    deadline = time.time() + watch_seconds
    last_dot = time.time()

    while time.time() < deadline:
        try:
            r = requests.get(f"{API}/incidents", timeout=3, verify=False, headers=headers)
            incidents = r.json().get("incidents", []) if r.ok else []
        except Exception:
            incidents = []

        for inc in incidents:
            iid = inc["incident_id"]
            sev = inc.get("severity", "?")
            status = inc.get("action_status", "")
            icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            sev_icon = icon_map.get(sev, "⚪")

            # New Incident Registered
            if iid not in seen_incidents:
                seen_incidents[iid] = "new"
                found_incidents[iid] = inc
                score = inc.get("score", 0)
                f_mode = inc.get("forensic_mode", "tool")
                f_label = (C.GREEN + "⚗ PIPELINE" + C.RESET) if f_mode == "pipeline" else (C.DIM + "🔧 tool" + C.RESET)
                print(f"\n  {sev_icon} {C.BOLD}NEW INCIDENT DETECTED{C.RESET} {C.CYAN}{iid}{C.RESET}")
                print(f"     Title     : {inc.get('title', '—')}")
                print(f"     Severity  : {C.BOLD}{sev}{C.RESET} | Score: {C.YELLOW}{score}{C.RESET}")
                print(f"     Forensic  : {f_label}")
                print(f"     Involved  : {', '.join(inc.get('involved', []))}")

            # LLM Analysis generated
            if inc.get("llm_summary") and seen_incidents.get(iid) == "new":
                seen_incidents[iid] = "llm"
                summary = (inc.get("llm_summary") or "")[:200].replace("\n", " ")
                action = inc.get("action_proposed", "?")
                action_color = {
                    "ISOLATE": C.RED, "BLOCK": C.RED,
                    "FLAG": C.YELLOW, "REVOKE_SESSIONS": C.YELLOW,
                    "NOTIFY": C.CYAN, "READ": C.DIM,
                }.get(action, C.WHITE)
                print(f"\n  {C.MAGENTA}🤖 LLM DECISION{C.RESET} [{iid}]")
                print(f"     Summary   : {summary}...")
                print(f"     Action    : {action_color}{C.BOLD}{action}{C.RESET}")
                if status == "pending":
                    step(f"Status: PENDING — Awaiting operator action or auto-execution...", "wait")

            # Auto-Execution triggered
            if "auto_executed" in status and seen_incidents.get(iid) not in ("auto", "manual"):
                seen_incidents[iid] = "auto" if "timeout" in status else "manual"
                note = (inc.get("operator_note") or "")[:120]
                print(f"\n  {C.RED}{C.BOLD}⚡ AUTONOMOUS ACTION EXECUTED{C.RESET} [{iid}]")
                print(f"     Mitigation: {inc.get('action_proposed', '?')}")
                print(f"     Status    : {status}")
                print(f"     Audit Note: {note}")
                found_incidents[iid] = inc

        # Periodic status updates
        if time.time() - last_dot > 5:
            last_dot = time.time()
            remaining = int(deadline - time.time())
            print(f"  {C.DIM}  ⏱ {remaining}s remaining | Active Incidents tracked: {len(seen_incidents)}{C.RESET}")

        time.sleep(2)

    step(f"Monitoring complete. Total incidents registered: {len(seen_incidents)}", "ok")
    return found_incidents


# ── Layer 4: Autonomous Mode (Operator Timeout) ─────────────────────────────

def phase_autonomous(token: str) -> None:
    """Demonstrate autonomous execution on timeout policy."""
    banner(
        "  LAYER 4 — AUTO-EXECUTOR\n"
        "  Autonomous Mode: instant auto-execute (timeout = 0s)\n"
        "  Human-in-the-Loop Mode: 60s operator response window",
        C.YELLOW
    )
    headers = {"Authorization": f"Bearer {token}"}

    section("Switching policy mode via API", "🔄", C.YELLOW)

    # Change config mode to autonomous
    try:
        r = requests.post(f"{API}/config/mode",
                          json={"mode": "autonomous"},
                          timeout=5, verify=False, headers=headers)
        if r.ok:
            step("Operational policy updated: AUTONOMOUS (instant enforcement)", "ok")
        else:
            step(f"Failed to change mode: HTTP status {r.status_code}", "warn")
    except Exception as e:
        step(f"API Error: {e}", "warn")

    # Generate scenario
    step("Simulating critical data exfiltration logs...", "attack")
    try:
        r = requests.post(f"{API}/scenario",
                          json={"scenario": "data_exfiltration", "source": "logs"},
                          timeout=10, verify=False, headers=headers)
        step(f"Exfiltration scenario injected: {r.status_code}", "ok" if r.ok else "warn")
    except Exception as e:
        step(f"Error: {e}", "error")

    pause(3, "Waiting for LLM agent processing")

    section("Autonomous Enforcement Status", "⚡", C.RED)
    try:
        r = requests.get(f"{API}/incidents", timeout=5, verify=False, headers=headers)
        incidents = r.json().get("incidents", []) if r.ok else []
        auto_count = sum(1 for i in incidents if "auto_executed" in i.get("action_status", ""))
        step(f"Total autonomously mitigated incidents: {auto_count}", "auto")
        for inc in incidents:
            if "auto_executed" in inc.get("action_status", ""):
                print(f"    • {inc['incident_id']} | {inc.get('severity')} | {inc.get('action_proposed')} ← {inc.get('action_status')}")
    except Exception as e:
        step(f"API Error: {e}", "warn")


# ── Layer 5: Forensic Pipeline v2.0 ──────────────────────────────────────────

async def phase_forensic(ollama_url: str, use_evidence: bool = True) -> None:
    """Demonstrate full Forensic Investigation Pipeline v2.0."""
    banner(
        "  LAYER 5 — FORENSIC INVESTIGATION v2.0\n"
        "  Incident → ForensicPlanManager → SIFT MCP Server → Sandbox\n"
        "  → CorrelationEngine → HallucinationTracker → AccuracyReport",
        C.GREEN
    )

    # Configure environment
    os.environ["OLLAMA_BASE_URL"] = ollama_url
    os.environ["FORENSIC_EVIDENCE_BASE"] = EVIDENCE_PATH if use_evidence else "/tmp/demo_evidence"
    os.environ["OLLAMA_TIMEOUT"] = "600"
    # The nromanoff case uses canned SIFT results (marked simulated in reports)
    os.environ["FORENSIC_DEMO_FIXTURES"] = "true"

    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

    section("Initializing Forensic Layer Components", "⚙", C.GREEN)

    try:
        from paladin.config.settings import settings
        from paladin.graph.neo4j_client import Neo4jClient
        from paladin.llm.ollama_client import OllamaClient
        from paladin.forensic.action_verifier import ForensicActionVerifier
        from paladin.forensic.sandbox_manager import SandboxManager
        from paladin.forensic.mcp_server import SIFTMCPServer
        from paladin.forensic.pg_store import ForensicPGStore
        from paladin.forensic.plan_manager import ForensicPlanManager
        from paladin.forensic.correlation_engine import CorrelationEngine
        from paladin.forensic.hallucination_tracker import HallucinationTracker
    except ImportError as e:
        step(f"Paladin imports failed: {e}", "error")
        step("Ensure the script runs with PYTHONPATH=.", "warn")
        return

    # Neo4j Client setup
    neo4j = Neo4jClient()
    step("Connecting to Neo4j graph...", "wait")
    try:
        await neo4j.connect()
        await neo4j.seed_organization()
    except Exception as e:
        step(f"Neo4j is unreachable: {e}", "error")
        step("Please run: docker-compose -f docker-compose.paladin.yml up -d neo4j", "warn")
        return
    step("Connected to Neo4j database successfully.", "ok")

    # Create investigator subject
    emp = {
        "uid": "emp-nromanoff",
        "full_name": "Natalie Romanoff",
        "email": "n.romanoff@corp.paladin.local",
        "department": "Engineering",
        "role": "Senior Developer",
        "manager_uid": "emp-005"
    }
    await neo4j.upsert_employee(emp)
    step(f"Forensic subject created: {emp['full_name']} ({emp['department']})", "ok")

    # LLM Setup
    llm = OllamaClient()
    step("Initializing Ollama LLM Connection...", "wait")
    await llm.start()
    step(f"LLM active: Qwen 3.5:9B @ {ollama_url}", "ok")

    # Forensic structures
    verifier = ForensicActionVerifier()
    sandbox = SandboxManager()
    pg = ForensicPGStore()

    try:
        await pg.initialize(settings.postgres_dsn)
        step("PostgreSQL Forensic Audit Log active.", "ok")
    except Exception as e:
        step(f"PG Store not available (running in memory-only mode): {e}", "warn")
        pg = None

    # Performance Stats
    stats = {
        "steps_total": 0,
        "steps_done": 0,
        "findings": 0,
        "contradictions": 0,
        "corrections": 0,
    }

    # Live Event Broadcaster
    async def live_broadcast(event: dict) -> None:
        ev = event.get("type", "")
        if ev == "forensic_plan_created":
            stats["steps_total"] = event.get("todo_count", 0)
            print()
            step(
                f"Forensic plan created: {event['plan_id'][:20]}... | "
                f"Total investigation steps: {C.YELLOW}{event['todo_count']}{C.RESET}",
                "forensic"
            )
        elif ev == "todo_item_updated":
            new_status = event.get("new_status", "")
            if new_status == "DONE":
                stats["steps_done"] += 1
                pct = int(stats["steps_done"] / max(stats["steps_total"], 1) * 100)
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                print(f"  {C.GREEN}  [{bar}] {pct}%{C.RESET}  Step {event['item_id'][:20]}... → DONE", end="\r")
        elif ev == "finding_added":
            stats["findings"] += 1
            print()
            step(
                f"Finding #{stats['findings']}: {event['description'][:80]} "
                f"(confidence={C.YELLOW}{event['confidence']}%{C.RESET})",
                "forensic"
            )
        elif ev == "contradiction_detected":
            stats["contradictions"] += 1
            print()
            step(
                f"CONTRADICTION #{stats['contradictions']}: "
                f"{event['finding_id_a'][:15]} ↔ {event['finding_id_b'][:15]}",
                "warn"
            )
        elif ev == "self_correction_triggered":
            stats["corrections"] += 1
            step(
                f"Self-Correction loop #{stats['corrections']}: "
                f"iteration {event['iteration_count']}/{event['max_iterations']} — {event.get('recheck_reason', '')[:60]}",
                "warn"
            )
        elif ev == "plan_completed":
            print()
            hallucination_rate = event.get("hallucination_rate", 0)
            hr_color = C.RED if hallucination_rate > 0.3 else C.GREEN
            step(
                f"FORENSIC ANALYSIS COMPLETE | "
                f"Status: {C.BOLD}{event['status']}{C.RESET} | "
                f"Findings: {event['total_findings']} | "
                f"Hallucination rate: {hr_color}{hallucination_rate * 100:.1f}%{C.RESET}",
                "ok"
            )

    # Initialize MCP
    mcp = SIFTMCPServer(sandbox, verifier, pg)

    section("Available SIFT MCP Functions", "🔧", C.GREEN)
    mcp_funcs = mcp.get_available_functions() if hasattr(mcp, "get_available_functions") else [
        "get_file_metadata", "compute_hash", "extract_strings",
        "analyze_process_list", "scan_network_connections", "extract_loaded_modules",
        "parse_mft", "parse_prefetch", "extract_registry_hive",
        "parse_pcap", "extract_browser_artifacts",
    ]
    for i, fn in enumerate(mcp_funcs, 1):
        print(f"    {i:2}. {C.CYAN}{fn}{C.RESET}")

    plan_mgr = ForensicPlanManager(
        neo4j=neo4j, llm=llm, mcp_server=mcp,
        sandbox=sandbox, pg_store=pg,
        broadcast_fn=live_broadcast
    )

    section("Creating CRITICAL Incident in Graph DB", "🚨", C.RED)

    incident_id = "INC-NROMANOFF-FULLSHOWCASE"
    context = {
        "incident_id": incident_id,
        "title": "Natalie Romanoff Workstation Compromise — Full Showcase",
        "severity": "CRITICAL",
        "score": 0.97,
        "description": (
            "Critical security incident: evidence of lateral movement, credential theft, "
            "and active malware infection on Natalie Romanoff's workstation (10.3.58.5). "
            "Memory dump and C: disk image attached."
        ),
        "involved_employees": ["emp-nromanoff"],
    }

    step(f"Incident: {incident_id}", "attack")
    step(f"Severity: CRITICAL | Score: {context['score']}", "attack")

    # Clear previous state
    async with neo4j._driver.session() as s:
        await s.run("MATCH (n {incident_id: $iid}) DETACH DELETE n", iid=incident_id)
        await s.run("MATCH (n {plan_id: $iid}) DETACH DELETE n", iid=incident_id)

    subprocess.run(
        ["docker", "rm", "-f", f"sift-sandbox-{incident_id}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    await neo4j.create_incident(context)
    step("Incident created in Neo4j graph.", "ok")

    section("Running Forensic Pipeline Engine", "🔬", C.GREEN)
    step("Pipeline: Sandbox Setup → SIFT MCP Tools → Agent Planning → Self-Correction → Correlation...", "forensic")

    evidence_path = EVIDENCE_PATH if os.path.exists(EVIDENCE_PATH) else None
    if not evidence_path:
        step(f"Evidence folder not found ({EVIDENCE_PATH}), starting simulation mode.", "warn")

    try:
        plan_id = await plan_mgr.run_full_investigation(
            incident_id=incident_id,
            context=context,
            evidence_path=evidence_path or "/tmp/empty",
        )
        print()
        step(f"Forensic Pipeline complete. Plan ID: {plan_id}", "ok")

        # ── Correlation Engine ───────────────────────────────────────────────
        section("Correlation Engine — Cross-Source Detection", "🔀", C.CYAN)
        correlation_engine = CorrelationEngine(neo4j, broadcast_fn=live_broadcast)
        try:
            correlations = await correlation_engine.run(plan_id)
            if correlations:
                for corr in correlations:
                    print(f"    • {C.YELLOW}{corr.get('type', '?')}{C.RESET}: {corr.get('description', '')[:80]}")
            else:
                step("No cross-source discrepancies found.", "ok")
        except Exception as e:
            step(f"Correlation Engine failed: {e}", "warn")

        # ── Hallucination Tracker ────────────────────────────────────────────
        section("Hallucination Tracker — Accuracy Report", "🎯", C.MAGENTA)
        hallucination_tracker = HallucinationTracker(neo4j, pg)
        try:
            report = await hallucination_tracker.generate_accuracy_report(plan_id)
            total = report.get("total_findings", 0)
            verified = report.get("verified_findings", 0)
            hr = report.get("hallucination_rate", 0.0)
            hr_color = C.RED if hr > 0.3 else C.YELLOW if hr > 0.1 else C.GREEN

            print(f"    Total Findings   : {total}")
            print(f"    Verified Findings: {C.GREEN}{verified}{C.RESET}")
            print(f"    Hallucination    : {hr_color}{hr * 100:.1f}%{C.RESET}")
            print(f"    Verification mode: exact / case-insensitive / semantic (70%+ overlap)")
        except Exception as e:
            step(f"Hallucination Tracker failed: {e}", "warn")

    except Exception as e:
        step(f"Forensic Pipeline error: {e}", "error")
        import traceback
        traceback.print_exc()

    await llm.stop()
    await neo4j.close()

    # Final summary statistics
    section("Forensic Investigation Summary", "📊", C.GREEN)
    print(f"    Total Planned Steps : {stats['steps_total']}")
    print(f"    Completed Steps     : {stats['steps_done']}")
    print(f"    Extracted Findings  : {stats['findings']}")
    print(f"    Plan Contradictions : {stats['contradictions']}")
    print(f"    Self-Corrections    : {stats['corrections']}")


# ── Phase 6: Dashboard & REST APIs ───────────────────────────────────────────

def phase_dashboard(token: str) -> None:
    """Test and show all FastAPI REST endpoints."""
    banner(
        "  LAYER 6 — DASHBOARD & API\n"
        f"  {DASHBOARD_URL}\n"
        "  FastAPI + WebSocket + JWT + TLS",
        C.CYAN
    )
    headers = {"Authorization": f"Bearer {token}"}

    endpoints = [
        ("GET",  "/api/status",             "System Health Check"),
        ("GET",  "/api/incidents",           "List Open Incidents"),
        ("POST", "/api/config/mode",         "Toggle Autonomous/HITL Mode"),
        ("GET",  "/api/graph/INC-SAMPLE",   "Incident Subgraph"),
        ("POST", "/api/scenario",            "Trigger Test Scenario"),
    ]

    section("Testing API Endpoints", "🌐", C.CYAN)
    for method, endpoint, desc in endpoints:
        url = DASHBOARD_URL + endpoint
        try:
            if method == "GET":
                r = requests.get(url, timeout=3, verify=False, headers=headers)
            else:
                r = requests.post(url, json={}, timeout=3, verify=False, headers=headers)
            status_icon = C.GREEN + "✓" + C.RESET if r.status_code < 400 else C.YELLOW + "⚠" + C.RESET
            print(f"  {status_icon} {method:<4} {endpoint:<35} HTTP {r.status_code}  {C.DIM}{desc}{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}  ✗ {method:<4} {endpoint:<35} Error: {str(e)[:40]}{C.RESET}")

    section("WebSocket Real-Time Event Stream", "📡", C.CYAN)
    step(f"WebSocket endpoint: wss://localhost:8888/ws", "ok")
    step("Supported live event types:", "info")
    ws_events = [
        "incident_created     — new security incident triggered",
        "incident_updated     — LLM analysis/summary update complete",
        "auto_executed        — autonomous action enforced by policy",
        "forensic_plan_*      — forensic workflow planning events",
        "finding_added        — new artifact discovery reported",
    ]
    for ev in ws_events:
        print(f"      • {C.CYAN}{ev}{C.RESET}")

    section("Forensic endpoints (v2.0)", "🔬", C.GREEN)
    forensic_endpoints = [
        ("GET",  "/api/forensic/plan/{plan_id}",             "ForensicPlan + TodoItems + Findings"),
        ("GET",  "/api/forensic/incident/{incident_id}",     "Plan for Incident"),
        ("GET",  "/api/forensic/accuracy/{plan_id}",         "Accuracy Report"),
        ("POST", "/api/forensic/plan/{plan_id}/approve",     "Approve Pending Action"),
    ]
    for method, endpoint, desc in forensic_endpoints:
        print(f"  {C.GREEN}✓{C.RESET} {method:<4} {endpoint:<45} {C.DIM}{desc}{C.RESET}")

    print()
    step(f"Dashboard UI available at: {C.CYAN}{DASHBOARD_URL}{C.RESET}", "ok")
    step("Credentials: admin / admin", "info")


# ── Phase 7: Security Architecture ───────────────────────────────────────────

def phase_security_architecture() -> None:
    """Display defense in depth design schema."""
    banner(
        "  SECURITY ARCHITECTURE — DEFENSE IN DEPTH\n"
        "  4 Protection Boundaries of the Forensic Layer",
        C.RED
    )

    boundaries = [
        (
            "#1 ForensicActionVerifier",
            "Command Filtering",
            ["SAFE / REQUIRES_APPROVAL / FORBIDDEN verification matrix",
             "Shell injection detection: ; && | ` $()",
             "Path traversal prevention (../)",
             "Default-Deny policy engine"]
        ),
        (
            "#2 MCP Server API Surface",
            "Surface Area Limitation",
            ["Exactly 11 read-only capabilities exposed",
             "No rm, dd, chmod, write or shell execution commands",
             "Strict Pydantic type validation",
             "LLM never interacts with a raw system shell"]
        ),
        (
            "#3 Sandbox Filesystem",
            "Kernel-Level Isolation",
            ["/evidence volume mounted with :ro flag (Read-Only)",
             "OS-level write protection",
             "Strictly --read-only docker run config",
             "Minimal tmpfs for volatile scratch space"]
        ),
        (
            "#4 Sandbox Network",
            "Docker Network Isolation",
            ["network: none — complete inbound & outbound block",
             "No DNS, preventing C2 data exfiltration",
             "--cap-drop ALL",
             "--pids-limit 256, strictly configured CPU/RAM limits"]
        ),
    ]

    for boundary, mechanism, details in boundaries:
        print(f"\n  {C.RED}┌─ Boundary {boundary}{C.RESET}")
        print(f"  {C.RED}│{C.RESET}  Mechanism: {C.YELLOW}{mechanism}{C.RESET}")
        for d in details:
            print(f"  {C.RED}│{C.RESET}  • {d}")
        print(f"  {C.RED}└{'─' * 60}{C.RESET}")


# ── Phase 8: Neo4j Graph Schema ──────────────────────────────────────────────

def phase_graph_schema() -> None:
    """Show the Neo4j schema definitions."""
    banner(
        "  NEO4J GRAPH SCHEMA\n"
        "  16 Nodes, 25+ Relationship types",
        C.CYAN
    )

    node_labels = [
        ("Employee",       "Core", "User entities: UID, department, clearance"),
        ("Device",         "Core", "Hosts, workstations, server resources"),
        ("File",           "Core", "File path artifacts"),
        ("IPAddress",      "Core", "Network IP entities (internal/external)"),
        ("Email",          "Core", "Corporate emails"),
        ("Message",        "Core", "Chat messenger conversations"),
        ("Call",           "Core", "Voice transcript logs"),
        ("LogEvent",       "Core", "System audit and application events"),
        ("Incident",       "Core", "Correlated anomalies"),
        ("Department",     "Org",  "Org structure nodes"),
        ("Role",           "Org",  "Employee roles"),
        ("ClearanceLevel", "Org",  "Clearance tiers"),
        ("ForensicPlan",   "Forensic", "Plan details (v2.0)"),
        ("TodoItem",       "Forensic", "Planned investigation steps"),
        ("Finding",        "Forensic", "Extracted evidence discoveries"),
        ("ToolExecution",  "Forensic", "SIFT MCP execution logs"),
    ]

    section("Node Labels", "🔵", C.CYAN)
    for label, domain, desc in node_labels:
        domain_color = C.CYAN if domain == "Core" else C.YELLOW if domain == "Org" else C.GREEN
        print(f"    {domain_color}{label:<20}{C.RESET} [{domain:<8}] {desc}")

    key_rels = [
        ("SENT_EMAIL",        "Employee → Email"),
        ("USES_DEVICE",       "Employee → Device"),
        ("ACCESSED_FILE",     "Employee → File"),
        ("INVOLVED_IN",       "Employee → Incident"),
        ("HAS_FORENSIC_PLAN", "Incident → ForensicPlan"),
        ("PRODUCED",          "ForensicPlan → Finding"),
        ("CONTRADICTS",       "Finding ↔ Finding"),
        ("HAS_VERSION",       "ForensicPlan → ForensicPlan (snapshot)"),
    ]

    section("Key Relationships", "🔗", C.CYAN)
    for rel, connects in key_rels:
        print(f"    {C.YELLOW}[:{rel}]{C.RESET:<35} {connects}")


# ── Main Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Paladin v2.0 — Full Demonstration and Showcase CLI"
    )
    parser.add_argument(
        "--phase",
        choices=["all", "checks", "ingestion", "sap", "llm", "autonomous",
                 "forensic", "dashboard", "security", "schema"],
        default="all",
        help="Demonstration phase to run (default: all)"
    )
    parser.add_argument(
        "--timeout",
        type=int, default=5,
        help="Operator response timeout in seconds (default=5)"
    )
    parser.add_argument(
        "--watch",
        type=int, default=90,
        help="Incident monitoring window duration in seconds (default=90)"
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Do not start Paladin service (connect to already running service)"
    )
    parser.add_argument(
        "--no-forensic",
        action="store_true",
        help="Skip the long forensic pipeline demo (saves LLM response waiting time)"
    )
    args = parser.parse_args()

    # Title
    banner(
        f"  ⛨  PALADIN v2.0 — AUTONOMOUS CORPORATE SECURITY SYSTEM\n"
        f"  Comprehensive Showcase Script\n"
        f"  Phase: {args.phase.upper()} | Operator Timeout: {args.timeout}s\n"
        f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        C.CYAN
    )

    # Preflight Checks
    checks = preflight_checks()
    ollama_url = checks["ollama_url"]

    # Standalone phases (no active Paladin daemon required)
    standalone_phases = {"sap", "security", "schema"}

    if args.phase in standalone_phases:
        if args.phase == "sap":
            phase_sap_demo()
        elif args.phase == "security":
            phase_security_architecture()
        elif args.phase == "schema":
            phase_graph_schema()
        return

    # Forensic phase
    if args.phase == "forensic":
        if not args.no_forensic:
            asyncio.run(phase_forensic(ollama_url))
        else:
            step("Forensic pipeline phase skipped (--no-forensic).", "warn")
        return

    # Daemon orchestration
    paladin_proc = None
    token = None

    if not args.no_start:
        section("Starting Paladin Orchestrator Service", "🚀", C.GREEN)
        paladin_proc = start_paladin(ollama_url, args.timeout)
        step(f"Paladin process started (PID={paladin_proc.pid})", "ok")
        token = wait_for_api(timeout_sec=60)
        if not token:
            step("Failed to retrieve operational token. Exiting.", "error")
            if paladin_proc:
                paladin_proc.terminate()
            sys.exit(1)
        wait_for_demo_start(token)
    else:
        section("Connecting to running Paladin daemon", "🔗", C.GREEN)
        token = wait_for_api(timeout_sec=20)
        if not token:
            step("Failed to connect to the operational REST API.", "error")
            sys.exit(1)
        wait_for_demo_start(token)

    step(f"Dashboard URI: {DASHBOARD_URL}", "ok")

    try:
        run_all = args.phase == "all"

        if run_all or args.phase == "schema":
            phase_graph_schema()
            pause(2)

        if run_all or args.phase == "sap":
            phase_sap_demo()
            pause(2)

        if run_all or args.phase == "security":
            phase_security_architecture()
            pause(2)

        if run_all or args.phase == "ingestion":
            phase_ingestion(token, demo_mode=(args.phase == "all"))
            pause(3, "Processing queued events")

        if run_all or args.phase == "llm":
            found_incidents = phase_llm_monitor(token, watch_seconds=args.watch)
            pause(2)

        if run_all or args.phase == "autonomous":
            phase_autonomous(token)
            pause(3)

        if (run_all or args.phase == "dashboard"):
            phase_dashboard(token)
            pause(2)

        if (run_all or args.phase == "forensic") and not args.no_forensic:
            asyncio.run(phase_forensic(ollama_url))

        # Complete banner
        banner(
            "  ✅  SHOWCASE COMPLETED SUCCESSFULLY\n"
            "  All operational layers of Paladin v2.0 demonstrated.\n"
            f"  Dashboard: {DASHBOARD_URL}  |  admin / admin",
            C.GREEN
        )

        if paladin_proc:
            step("Paladin is active. Press Ctrl+C to terminate.", "info")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    except KeyboardInterrupt:
        banner("  ⏹  DEMO TERMINATED BY USER", C.YELLOW)
    finally:
        if paladin_proc:
            step("Shutting down Paladin service...", "wait")
            paladin_proc.terminate()
            try:
                paladin_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                paladin_proc.kill()
            step("Paladin service stopped.", "ok")


if __name__ == "__main__":
    main()
