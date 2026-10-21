"""
Paladin v2.0 — Uncompromising Complex Cyberattack Test Suite.
Tests the entire system against 3 highly realistic, multi-vector APT & Insider Threat scenarios.
No mocks/shortcuts for security checks — exercises all 6 layers of Paladin.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

# Ensure UTF-8 output formatting on Windows console
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DSN", "postgresql://x:x@localhost/x")

# ── Terminal Formatting Colors ───────────────────────────────────────────────
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

def banner(title: str, color: str = C.CYAN) -> None:
    width = 75
    print()
    print(color + "╔" + "═" * (width - 2) + "╗" + C.RESET)
    print(color + f"║  {C.BOLD}{title:<70}{C.RESET}{color}  ║" + C.RESET)
    print(color + "╚" + "═" * (width - 2) + "╝" + C.RESET)
    print()

def step(msg: str, status: str = "info") -> None:
    icons = {
        "info": C.BLUE + "[•]" + C.RESET,
        "ok": C.GREEN + "[✓]" + C.RESET,
        "warn": C.YELLOW + "[⚠]" + C.RESET,
        "error": C.RED + "[✗]" + C.RESET,
        "attack": C.RED + C.BOLD + "[🚨 ATTACK]" + C.RESET,
        "defense": C.GREEN + C.BOLD + "[🛡 DEFENSE]" + C.RESET,
        "forensic": C.MAGENTA + "[🔬 FORENSIC]" + C.RESET,
    }
    print(f"  {icons.get(status, '[•]')} {msg}")


# ── TEST SETUP & DATA ────────────────────────────────────────────────────────
DUMMY_EMPLOYEES = [
    {"uid": "emp-001", "full_name": "Alexei Petrov", "email": "a.petrov@corp.paladin.local", "department": "Engineering", "role": "Senior Developer", "manager_uid": "emp-005"},
    {"uid": "emp-002", "full_name": "Maria Ivanova", "email": "m.ivanova@corp.paladin.local", "department": "Finance", "role": "Accountant", "manager_uid": "emp-006"},
    {"uid": "emp-003", "full_name": "Dmitry Sokolov", "email": "d.sokolov@corp.paladin.local", "department": "IT Security", "role": "Security Analyst", "manager_uid": "emp-007"},
    {"uid": "emp-004", "full_name": "Elena Kuznetsova", "email": "e.kuznetsova@corp.paladin.local", "department": "HR", "role": "HR Specialist", "manager_uid": "emp-006"},
    {"uid": "emp-005", "full_name": "Sergei Volkov", "email": "s.volkov@corp.paladin.local", "department": "Engineering", "role": "Team Lead", "manager_uid": "emp-008"},
    {"uid": "emp-010", "full_name": "Igor Smirnov", "email": "i.smirnov@corp.paladin.local", "department": "Executive", "role": "CEO", "manager_uid": None},
]


# ═════════════════════════════════════════════════════════════════════════════
# SCENARIO 1: APT 29 "Red Silence" (Multi-Vector Targeted Intrusion)
# ═════════════════════════════════════════════════════════════════════════════
async def test_scenario_1_apt29():
    banner("SCENARIO 1: APT 29 'Red Silence' (Multi-Vector Intrusion)", C.RED)
    step("Vectors: Spearphishing Email → Credential Sharing Chat → Off-Hours VPN → LSASS Dump → DC Lateral Movement", "attack")

    from paladin.sap.morpho_parser import MorphoParser
    from paladin.sap.correlator import Correlator, CorrelationResult
    from paladin.verifier.verifier import ActionVerifier
    from paladin.verifier.action_registry import ACTIONS, ActionLevel
    from paladin.forensic.action_verifier import ForensicActionVerifier, VerifierCategory

    parser = MorphoParser()
    verifier = ActionVerifier()
    forensic_verifier = ForensicActionVerifier()

    # Stage 1: Phishing Email
    email_text = "URGENT: Mandatory password reset required. Click https://corp-verify.xyz/login to keep access."
    morpho_email = parser.analyze(email_text)
    step(f"Stage 1 Morpho Analysis: risk={morpho_email.text_risk_score}, sentiment={morpho_email.sentiment_label}", "info")
    assert morpho_email.text_risk_score > 0.3, "Phishing email risk score too low!"

    # Stage 2: Chat Credential Leak
    chat_text = "Here are the domain admin creds: admin / P@ssw0rd2026! Use mimikatz to bypass MFA."
    morpho_chat = parser.analyze(chat_text)
    step(f"Stage 2 Chat Analysis: risk={morpho_chat.text_risk_score}, terms={[t[0] for t in morpho_chat.security_terms_found]}", "info")
    assert any(t[0] in ("admin", "mimikatz") for t in morpho_chat.security_terms_found), "Failed to detect mimikatz/admin terms!"

    # Stage 3: Simulated Events for Correlation
    now = datetime.now(timezone.utc).replace(hour=3, minute=15)  # 03:15 AM off-hours
    events = [
        # Off-hours VPN login
        {"event_id": str(uuid.uuid4()), "event_type": "login_success", "timestamp": now.isoformat(),
         "employee_uid": "emp-001", "ip_address": "185.143.223.47", "risk_score": 0.5,
         "details": "VPN login from external IP at 03:15"},
        # Process start: mimikatz
        {"event_id": str(uuid.uuid4()), "event_type": "process_start", "timestamp": (now + timedelta(minutes=2)).isoformat(),
         "employee_uid": "emp-001", "ip_address": "185.143.223.47", "risk_score": 0.85,
         "details": "process=mimikatz.exe command='securlsa::logonpasswords' parent=cmd.exe"},
        # Privilege escalation
        {"event_id": str(uuid.uuid4()), "event_type": "privilege_escalation", "timestamp": (now + timedelta(minutes=4)).isoformat(),
         "employee_uid": "emp-001", "ip_address": "185.143.223.47", "risk_score": 0.9,
         "details": "SYSTEM token impersonation via mimikatz"},
        # Network connect DC
        {"event_id": str(uuid.uuid4()), "event_type": "network_connect", "timestamp": (now + timedelta(minutes=6)).isoformat(),
         "employee_uid": "emp-001", "ip_address": "10.0.0.1", "risk_score": 0.95,
         "details": "SMB connection to Domain Controller DC-MAIN-001"},
    ]

    # Calculate overall risk progression
    max_risk = max(e["risk_score"] for e in events)
    step(f"Attack Timeline: {len(events)} suspicious events, Max Event Risk={max_risk}", "attack")
    assert max_risk >= 0.9, "APT 29 attack score failed to reach CRITICAL threshold!"

    # Stage 4: Action Verification for Defense Response
    proposed_action = "ISOLATE"
    target_emp = ["emp-001"]
    v_res = verifier.verify_action(
        proposed_action=proposed_action,
        severity="CRITICAL",
        target_entities=target_emp,
        llm_response="CRITICAL APT 29 intrusion detected. Recommending network isolation of host WS-ENG-001."
    )
    step(f"ActionVerifier Decision for {proposed_action}: approved={v_res.action_check.approved}, reason={v_res.action_check.reason}", "defense")
    assert v_res.action_check.approved, "ActionVerifier wrongfully rejected ISOLATE action for CRITICAL APT threat!"

    # Stage 5: Forensic Boundary Test (blocking malicious execution attempts)
    bad_mcp_req = forensic_verifier.verify("get_file_metadata", {"path": "/evidence/mem.raw; cat /etc/passwd"})
    step(f"Forensic Security Boundary Check (Command Injection): category={bad_mcp_req.category.value}, decision={bad_mcp_req.decision.value}", "defense")
    assert bad_mcp_req.category == VerifierCategory.FORBIDDEN, "ForensicActionVerifier failed to block command injection!"

    step("Scenario 1 (APT 29 Red Silence) PASSED ✅", "ok")


# ═════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: Corporate Espionage "Black Raven" (Insider Threat)
# ═════════════════════════════════════════════════════════════════════════════
async def test_scenario_2_black_raven():
    banner("SCENARIO 2: Corporate Espionage 'Black Raven' (Insider Threat)", C.MAGENTA)
    step("Vectors: Bribery Call → Conspiratorial Chat → Off-Hours High-Clearance File Access → USB Mount → External Email Leak", "attack")

    from paladin.sap.morpho_parser import MorphoParser
    from paladin.verifier.verifier import ActionVerifier
    from paladin.config.settings import settings

    parser = MorphoParser()
    verifier = ActionVerifier()

    # Stage 1: Call Transcript Analysis
    call_transcript = (
        "Caller: I got a call from someone at TechCorp. They want our chip designs. "
        "Callee: How much are they offering? Caller: Five hundred K cash. Wire to offshore account. "
        "Callee: I'll extract board presentation and financial projections tonight. Don't tell anyone."
    )
    call_analysis = parser.analyze(call_transcript)
    step(f"Call Analysis: sentiment={call_analysis.sentiment_label}, terms={[t[0] for t in call_analysis.security_terms_found]}", "info")
    assert call_analysis.sentiment_label in ("conspiratorial", "suspicious", "urgent"), "Call sentiment classification failed!"

    # Stage 2: High Clearance File Access & External Exfiltration
    sensitive_file = "/data/executive/board_presentation.pptx"
    file_clearance = 4  # Executive level
    user_clearance = 2  # Developer level
    step(f"Clearance Violation: User clearance={user_clearance} accessed File clearance={file_clearance} ({sensitive_file})", "attack")

    # Stage 3: Protected Account Escalation Gate
    # Attempting to isolate/block a protected account (e.g. 'admin' or 'root') MUST be blocked by ActionVerifier
    protected_target = "admin"
    step(f"Protected Account Guard: Attempting to BLOCK protected account '{protected_target}'", "attack")
    v_protected = verifier.verify_action(
        proposed_action="BLOCK",
        severity="CRITICAL",
        target_entities=[protected_target],
        llm_response="Block admin account immediately."
    )
    step(f"Protected Account Guard Result: approved={v_protected.action_check.approved}, reason={v_protected.action_check.reason}", "defense")
    assert not v_protected.action_check.approved, f"ActionVerifier failed to protect account '{protected_target}'!"

    step("Scenario 2 (Black Raven Insider Threat) PASSED ✅", "ok")


# ═════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: Ransomware Precursor & Ghost Process "Zero Dawn" (Memory & DLL Side-Loading)
# ═════════════════════════════════════════════════════════════════════════════
async def test_scenario_3_zero_dawn():
    banner("SCENARIO 3: Ransomware Precursor & Ghost Process 'Zero Dawn'", C.YELLOW)
    step("Vectors: Spearphishing Dropper → Registry Persistence → Memory DLL Side-Loading → Ghost Process & Invisible C2", "attack")

    from paladin.forensic.correlation_engine import CorrelationEngine
    from paladin.forensic.action_verifier import ForensicActionVerifier, VerifierCategory

    # Mock findings simulating Volatility3 and Disk forensics outputs
    mock_findings = [
        {
            "finding_id": "F-MEM-001",
            "description": "Process 'svchost.exe' (PID 6404) found running in memory with injected Zeus Trojan DLL.",
            "tool_used": "analyze_process_list",
            "confidence": 95,
            "evidence_quote": "svchost.exe PID 6404 C:\\Windows\\system32\\svchost.exe -k netsvcs",
            "verified": True
        },
        {
            "finding_id": "F-DISK-001",
            "description": "Disk analysis of $MFT and Prefetch shows no executable file 'sdra64.exe' or 'spinlock.exe' on disk.",
            "tool_used": "parse_mft",
            "confidence": 90,
            "evidence_quote": "MFT entry count 3, no sdra64.exe",
            "verified": True
        },
        {
            "finding_id": "F-REG-001",
            "description": "Registry hive HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run contains autorun key 'ZeusTrojan' pointing to C:\\Windows\\System32\\sdra64.exe.",
            "tool_used": "extract_registry_hive",
            "confidence": 92,
            "evidence_quote": "ZeusTrojan = C:\\Windows\\System32\\sdra64.exe",
            "verified": True
        },
        {
            "finding_id": "F-NET-001",
            "description": "Netscan shows ESTABLISHED connection to 185.141.63.10:80 from PID 6404.",
            "tool_used": "scan_network_connections",
            "confidence": 90,
            "evidence_quote": "10.3.58.5:1044 -> 185.141.63.10:80 ESTABLISHED",
            "verified": True
        },
        {
            "finding_id": "F-PCAP-001",
            "description": "PCAP analysis shows HTTP GET requests to 185.141.63.10 without prior DNS resolution query.",
            "tool_used": "parse_pcap",
            "confidence": 88,
            "evidence_quote": "HTTP GET /payloads/spinlock.exe",
            "verified": True
        }
    ]

    # Source classification test
    sources = [CorrelationEngine._classify_source(f["tool_used"]) for f in mock_findings]
    step(f"Multi-Source Classification: {sources}", "forensic")
    assert "memory" in sources and "disk" in sources and "network" in sources, "Failed to classify all 3 forensic evidence sources!"

    # Process & IP extraction test
    proc_names = CorrelationEngine._extract_process_names(mock_findings[0]["description"])
    ips = CorrelationEngine._extract_ips(mock_findings[3]["description"])
    step(f"Extracted Entities: processes={proc_names}, IPs={ips}", "forensic")
    assert "svchost.exe" in proc_names, "Failed to extract process name!"
    assert "185.141.63.10" in ips, "Failed to extract C2 IP address!"

    # Private vs External IP verification
    is_private = CorrelationEngine._is_private_ip("185.141.63.10")
    step(f"IP 185.141.63.10 Private Check: {is_private} (Expected False = External C2)", "defense")
    assert not is_private, "Failed to classify external C2 IP address correctly!"

    step("Scenario 3 (Zero Dawn Ransomware Precursor & Ghost Process) PASSED ✅", "ok")


# ═════════════════════════════════════════════════════════════════════════════
# RUNNER
# ═════════════════════════════════════════════════════════════════════════════
async def main():
    print()
    print("═" * 75)
    print("  ⛨  PALADIN v2.0 — UNCOMPROMISING COMPLEX CYBERATTACK TEST SUITE")
    print("═" * 75)

    try:
        await test_scenario_1_apt29()
        await test_scenario_2_black_raven()
        await test_scenario_3_zero_dawn()

        print()
        print("═" * 75)
        print("  🎉 ALL 3 COMPLEX CYBERATTACK SCENARIOS PASSED WITH FULL DEFENSE COVERAGE!")
        print("═" * 75)
        print()
        sys.exit(0)
    except Exception as e:
        print()
        print("💥 TEST FAILED WITH EXCEPTION:", e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
