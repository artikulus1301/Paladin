"""
Paladin — Natalie Romanoff Workstation Forensic Investigation Demo.
Runs the complete forensic pipeline (v2.0) on the actual nromanoff evidence files.
Auto-detects active Ollama instance (Windows vs Docker) and configures ports dynamically.
"""
import asyncio
import os
import sys
import time
import requests
import socket
import urllib3
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure path is set
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Target evidence path
EVIDENCE_PATH = r"c:\Users\Lenovo\Downloads\win7-32-nromanoff-10.3.58.5"

def check_port(port):
    """Check if a port is listening on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(('127.0.0.1', port)) == 0

def detect_ollama():
    """Detect which port Ollama is running on."""
    print("[*] Detecting active Ollama instance...")
    for port in [11434, 11435]:
        url = f"http://localhost:{port}"
        try:
            r = requests.get(f"{url}/api/tags", timeout=2)
            if r.status_code == 200:
                print(f"[+] Found active Ollama instance on {url}")
                return url
        except Exception:
            pass
    print("[!] Warning: No running Ollama instance found on port 11434 or 11435.")
    print("    Make sure Ollama is running (Ollama Windows or Docker).")
    return "http://localhost:11434"

async def ensure_model_pulled(ollama_url):
    """Ensure qwen3.5:9b model is pulled on Ollama."""
    print("[*] Verifying qwen3.5:9b model exists...")
    try:
        r = requests.get(f"{ollama_url}/api/tags")
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            if any("qwen3.5" in m for m in models):
                print("[+] Model qwen3.5:9b is already pulled.")
                return
    except Exception as e:
        print(f"[!] Error checking model: {e}")

    print("[*] Pulling qwen3.5:9b (this may take several minutes)...")
    try:
        r = requests.post(f"{ollama_url}/api/pull", json={"name": "qwen3.5:9b"}, stream=True)
        for line in r.iter_lines():
            if line:
                print(line.decode('utf-8', errors='replace'))
    except Exception as e:
        print(f"[!] Error pulling model: {e}")

def ensure_dbs_running():
    """Ensure Neo4j and PostgreSQL are running via docker-compose."""
    print("[*] Checking databases...")
    db_running = check_port(7687) and check_port(5432)
    if not db_running:
        print("[*] Databases not listening. Starting Neo4j and PostgreSQL via docker-compose...")
        try:
            subprocess.run(["docker-compose", "-f", "docker-compose.paladin.yml", "up", "-d", "neo4j", "postgres"], check=True)
            print("[*] Waiting 15s for databases to boot...")
            time.sleep(15)
        except Exception as e:
            print(f"[!] Failed to start databases: {e}")
    else:
        print("[+] Databases are already running and listening.")

async def run_forensics(ollama_url):
    print("\n" + "=" * 80)
    print("  🛡️  PALADIN — FORENSIC PIPELINE DEMO: NATALIE ROMANOFF WORKSTATION")
    print("=" * 80 + "\n")

    # Set up environment variables
    os.environ["OLLAMA_BASE_URL"] = ollama_url
    os.environ["FORENSIC_EVIDENCE_BASE"] = EVIDENCE_PATH
    os.environ["PALADIN_MODE"] = "production"
    os.environ["OLLAMA_TIMEOUT"] = "600"
    
    # Import Paladin modules
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

    # Connect to Neo4j
    neo4j = Neo4jClient()
    print("[*] Connecting to Neo4j...")
    await neo4j.connect()
    await neo4j.seed_organization()

    # Seed Natalie Romanoff employee
    emp = {
        "uid": "emp-nromanoff",
        "full_name": "Natalie Romanoff",
        "email": "n.romanoff@corp.paladin.local",
        "department": "Engineering",
        "role": "Senior Developer",
        "manager_uid": "emp-005"
    }
    await neo4j.upsert_employee(emp)
    print(f"[+] Seeded employee: {emp['full_name']}")

    # Setup LLM client
    llm = OllamaClient()
    await llm.start()

    # Setup Forensic Layer
    verifier = ForensicActionVerifier()
    sandbox = SandboxManager()
    pg = ForensicPGStore()
    
    try:
        await pg.initialize(settings.postgres_dsn)
        print("[+] PostgreSQL Forensic Store initialized.")
    except Exception as e:
        print(f"[!] PG Store unavailable (running in memory-only mode): {e}")
        pg = None

    # Custom broadcast function to print real-time events to console
    async def console_broadcast(event):
        ev_type = event.get("type")
        if ev_type == "forensic_plan_created":
            print(f"\n[🤖 PlanManager] Plan {event['plan_id']} created for incident {event['incident_id']}.")
            print(f"                Total investigation steps generated: {event['todo_count']}")
        elif ev_type == "todo_item_updated":
            print(f"\n[🔄 Step Update] Item {event['item_id']}: {event['old_status']} -> {event['new_status']}")
        elif ev_type == "finding_added":
            print(f"[✅ Finding Added] ID: {event['finding_id']}")
            print(f"                  Description: {event['description']}")
            print(f"                  Confidence: {event['confidence']}%")
        elif ev_type == "contradiction_detected":
            print(f"\n[⚠️ CONTRADICTION] Contradiction detected between {event['finding_id_a']} and {event['finding_id_b']}!")
        elif ev_type == "self_correction_triggered":
            print(f"[🔄 Self-Correction] Iteration: {event['iteration_count']}/{event['max_iterations']}. Reason: {event['recheck_reason']}")
        elif ev_type == "plan_completed":
            print(f"\n[🏁 Investigation Completed]")
            print(f"    Status: {event['status']}")
            print(f"    Total findings: {event['total_findings']}")
            print(f"    Hallucination rate: {event['hallucination_rate'] * 100:.1f}%\n")

    mcp = SIFTMCPServer(sandbox, verifier, pg)
    plan_mgr = ForensicPlanManager(
        neo4j=neo4j, llm=llm, mcp_server=mcp,
        sandbox=sandbox, pg_store=pg,
        broadcast_fn=console_broadcast
    )

    # 1. Create a security Incident
    incident_id = "INC-NROMANOFF-COMPROMISE"
    context = {
        "incident_id": incident_id,
        "title": "Natalie Romanoff Workstation Compromise",
        "severity": "CRITICAL",
        "score": 0.95,
        "description": "Evidence of lateral movement, credential access, or malware on workstation belonging to Natalie Romanoff (10.3.58.5). Memory dump and C: drive files are attached as evidence.",
        "involved_employees": ["emp-nromanoff"]
    }

    # Clean up any existing plan/incident with this ID
    async with neo4j._driver.session() as s:
        await s.run("MATCH (n {incident_id: $iid}) DETACH DELETE n", iid=incident_id)
        await s.run("MATCH (n {plan_id: $iid}) DETACH DELETE n", iid=incident_id)

    # Clean up stale Docker containers
    subprocess.run(["docker", "rm", "-f", f"sift-sandbox-{incident_id}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    await neo4j.create_incident(context)
    print(f"\n[+] Created Incident {incident_id} in Neo4j.")

    # 2. Run Forensic Pipeline
    print(f"[*] Starting end-to-end investigation on {EVIDENCE_PATH}...")
    try:
        plan_id = await plan_mgr.run_full_investigation(
            incident_id=incident_id,
            context=context,
            evidence_path=EVIDENCE_PATH
        )
        print(f"[+] Forensic analysis complete. Plan ID: {plan_id}")
    except Exception as e:
        print(f"[!] Error during forensic investigation: {e}")
        import traceback
        traceback.print_exc()

    await llm.stop()
    await neo4j.close()

def main():
    ollama_url = detect_ollama()
    asyncio.run(ensure_model_pulled(ollama_url))
    ensure_dbs_running()
    asyncio.run(run_forensics(ollama_url))

if __name__ == "__main__":
    main()
