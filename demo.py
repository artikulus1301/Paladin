"""
Paladin — Full Local Launch & Demonstration Script.
Demonstrates the AUTONOMOUS mode: if the operator doesn't respond
within 60 seconds, the system auto-executes the proposed action.
"""
import subprocess
import time
import sys
import os
import requests

DASHBOARD_URL = "https://localhost:8888"
API = DASHBOARD_URL + "/api"

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCENARIOS = [
    {"scenario": "brute_force",       "source": "logs",     "label": "🚨 Brute Force Attack"},
    {"scenario": "data_exfiltration", "source": "logs",     "label": "💾 Data Exfiltration"},
    {"scenario": "phishing",          "source": "emails",   "label": "📧 Phishing Campaign"},
    {"scenario": "insider_chat",      "source": "messages", "label": "💬 Insider Conspiracy"},
]

def hdr(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def main():
    hdr("🛡️  PALADIN — AUTONOMOUS SECURITY SYSTEM DEMO")
    print("  Operator timeout: 0 seconds → INSTANT auto-execution\n")

    # ── 1. Start Paladin ──────────────────────────────────────────────
    print("[*] Starting Paladin orchestrator...")
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    proc = subprocess.Popen(
        [sys.executable, "-m", "paladin.main"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )

    # ── 2. Wait for ready ─────────────────────────────────────────────
    print("[*] Waiting for services...")
    for i in range(30):
        try:
            r = requests.get(f"{API}/status", timeout=2, verify=False)
            if r.status_code in [200, 401]: # 401 means API is up but needs auth
                break
        except Exception:
            pass
        time.sleep(2)
        print(f"    ... ({i+1}/30)")
    else:
        print("[!] Failed to connect. Exiting.")
        proc.terminate()
        return

    print("[+] Paladin is ONLINE.")
    
    # ── 2.5 Login to get token ────────────────────────────────────────
    print("[*] Logging in...")
    r = requests.post(f"{API}/login", json={"username": "admin", "password": "admin"}, verify=False)
    if not r.ok:
        print("[!] Failed to login. Exiting.")
        proc.terminate()
        return
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"[+] Dashboard: {DASHBOARD_URL}\n")

    # ── 3. Trigger scenarios ──────────────────────────────────────────
    hdr("🧪  TRIGGERING ATTACK SCENARIOS")
    for s in SCENARIOS:
        print(f"  ▶ {s['label']} ... ", end="", flush=True)
        try:
            r = requests.post(f"{API}/scenario", json={
                "scenario": s["scenario"], "source": s["source"],
            }, timeout=5, verify=False, headers=headers)
            print("✅" if r.status_code == 200 else f"❌ {r.status_code}")
        except Exception as e:
            print(f"❌ {e}")
        time.sleep(1)

    # ── 4. Monitor ────────────────────────────────────────────────────
    hdr("🕵️  MONITORING (Ctrl+C to stop)")
    print("  All incidents will now AUTO-EXECUTE INSTANTLY")
    print("  without requiring operator confirmation.\n")

    seen = set()
    try:
        while True:
            try:
                r = requests.get(f"{API}/incidents", timeout=3, verify=False, headers=headers)
                incidents = r.json().get("incidents", []) if r.ok else []
            except Exception:
                incidents = []

            for inc in incidents:
                iid = inc["incident_id"]
                status = inc.get("action_status", "")

                # New incident
                if iid not in seen:
                    seen.add(iid)
                    sev = inc["severity"]
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "🟢")
                    print(f"  {icon} NEW  {iid}")
                    print(f"        {inc['title']} | {sev} | Score: {inc['score']}")
                    print(f"        Involved: {', '.join(inc.get('involved', []))}")
                    if inc.get("action_proposed"):
                        print(f"        Action: {inc['action_proposed']} ({status})")
                    print()

                # LLM summary appeared
                skey = f"llm_{iid}"
                if inc.get("llm_summary") and skey not in seen:
                    seen.add(skey)
                    summary = (inc.get("llm_summary") or "")[:150].replace("\r", "").replace("\n", " ")
                    print(f"  🤖 LLM  {iid}")
                    print(f"        {summary}...")
                    print(f"        → {inc['action_proposed']} ({status})")
                    if status == "pending":
                        print(f"        ⏳ Executing autonomously...")
                    print()

                # Auto-executed!
                akey = f"auto_{iid}"
                if "auto_executed_timeout" in status and akey not in seen:
                    seen.add(akey)
                    note = (inc.get("operator_note") or "").replace("\r", "").replace("\n", " ")[:120]
                    print(f"  ⚡ AUTO-EXECUTED  {iid}")
                    print(f"        Action: {inc['action_proposed']}")
                    print(f"        Note: {note}")
                    print()

            time.sleep(3)

    except KeyboardInterrupt:
        hdr("🛑  DEMO STOPPED")
    finally:
        proc.terminate()
        print("[+] Paladin terminated. Goodbye!\n")

if __name__ == "__main__":
    main()
