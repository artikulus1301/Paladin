"""
Dummy Enterprise — Log Generator.
Produces realistic system events: logins, file ops, network connections,
process launches with time-of-day distribution and injected anomalies.
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Optional

import structlog

from paladin.config.settings import settings

log = structlog.get_logger(__name__)

# ── Realistic data pools ──────────────────────────────────────────────────────

EVENT_TYPES = [
    "login_success", "login_failed", "logout",
    "file_read", "file_write", "file_delete", "file_download", "file_copy",
    "process_start", "process_stop",
    "network_connect", "network_disconnect",
    "usb_mount", "usb_unmount",
    "vpn_connect", "vpn_disconnect",
    "privilege_escalation", "password_change", "account_lockout",
]

NORMAL_EVENTS = [
    "login_success", "logout", "file_read", "file_write",
    "process_start", "process_stop", "network_connect", "network_disconnect",
]

SUSPICIOUS_EVENTS = [
    "login_failed", "file_delete", "file_download", "file_copy",
    "usb_mount", "privilege_escalation", "account_lockout",
]

INTERNAL_IPS = [f"10.0.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(30)]
EXTERNAL_IPS = [
    "185.143.223.47", "91.234.99.12", "45.33.32.156",
    "104.16.85.20", "203.0.113.42", "198.51.100.17",
    "78.46.209.11", "95.217.163.88", "172.67.182.31",
]

DEVICES = [f"WS-{dept}-{i:03d}" for dept in ["ENG", "FIN", "HR", "LEGAL", "OPS", "IT", "EXEC"] for i in range(1, 5)]

SENSITIVE_FILES = [
    "/data/finance/Q4_report_2025.xlsx",
    "/data/finance/salary_grid_2025.csv",
    "/data/legal/merger_contract_draft.pdf",
    "/data/hr/performance_reviews_2025.xlsx",
    "/data/engineering/source_code_audit.zip",
    "/data/executive/board_presentation.pptx",
    "/data/security/incident_reports.db",
    "/data/finance/bank_credentials.kdbx",
    "/data/legal/patent_application_v3.docx",
    "/data/hr/employee_ssn_list.csv",
]

NORMAL_FILES = [
    "/docs/readme.md", "/docs/onboarding_guide.pdf",
    "/shared/meeting_notes_2025.docx", "/shared/team_photo.jpg",
    "/projects/frontend/index.html", "/projects/api/swagger.json",
    "/temp/download.tmp", "/logs/app.log",
]

FILE_CLEARANCE = {
    "/data/finance/": 3,
    "/data/legal/": 3,
    "/data/hr/": 2,
    "/data/engineering/": 2,
    "/data/executive/": 4,
    "/data/security/": 3,
}

PROCESSES = [
    "chrome.exe", "outlook.exe", "vscode.exe", "python.exe",
    "powershell.exe", "cmd.exe", "ssh.exe", "scp.exe",
    "curl.exe", "wget.exe", "7z.exe", "winrar.exe",
    "sqlcmd.exe", "psql.exe", "neo4j.exe",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe", "nmap.exe", "wireshark.exe", "netcat.exe",
    "psexec.exe", "procdump.exe", "rawcopy.exe",
]


def _get_file_clearance(path: str) -> int:
    """Determine clearance level from file path prefix."""
    for prefix, level in FILE_CLEARANCE.items():
        if path.startswith(prefix):
            return level
    return 0


def _time_weight(hour: int) -> float:
    """Higher weight for work hours (9-18), lower for night."""
    if 9 <= hour <= 18:
        return 1.0
    elif 7 <= hour <= 21:
        return 0.4
    else:
        return 0.05


class LogGenerator:
    """
    Generates system log events in two modes:
    - Normal: background traffic with realistic time distribution
    - Incident: parametrized anomaly scenarios
    """

    def __init__(self, employee_uids: list[str]) -> None:
        self._employees = employee_uids
        self._running = False

    async def generate_normal(
        self, queue: asyncio.Queue, rate_per_min: int | None = None
    ) -> None:
        """Continuous normal traffic generation."""
        rate = rate_per_min or settings.dummy_events_per_minute
        self._running = True
        log.info("log_generator_start", mode="normal", rate=rate)

        while self._running:
            now = datetime.now(timezone.utc)
            hour = now.hour

            # Skip most events at night
            if random.random() > _time_weight(hour):
                await asyncio.sleep(1)
                continue

            event = self._make_normal_event(now)

            # Random low-level anomaly injection
            if random.random() < settings.dummy_anomaly_probability:
                event = self._inject_minor_anomaly(event, now)

            await queue.put(("logs", event))
            await asyncio.sleep(60 / rate)

    async def generate_scenario(
        self, queue: asyncio.Queue, scenario: str, **params
    ) -> list[dict]:
        """
        Generate a specific incident scenario.
        Returns list of generated events for reference.
        """
        generators = {
            "brute_force": self._scenario_brute_force,
            "data_exfiltration": self._scenario_data_exfiltration,
            "insider_threat": self._scenario_insider_threat,
            "privilege_escalation": self._scenario_privilege_escalation,
        }
        gen = generators.get(scenario)
        if not gen:
            raise ValueError(f"Unknown scenario: {scenario}. Available: {list(generators)}")

        events = await gen(queue, **params)
        log.info("scenario_generated", scenario=scenario, n_events=len(events))
        return events

    def stop(self) -> None:
        self._running = False

    # ── Normal event generation ───────────────────────────────────────────────
    def _make_normal_event(self, now: datetime) -> dict:
        emp = random.choice(self._employees)
        event_type = random.choice(NORMAL_EVENTS)
        device = random.choice(DEVICES)
        ip = random.choice(INTERNAL_IPS)

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "timestamp": now.isoformat(),
            "source": "syslog",
            "employee_uid": emp,
            "device_hostname": device,
            "ip_address": ip,
            "risk_score": round(random.uniform(0.0, 0.15), 3),
            "details": "",
            "raw_path": "",
        }

        if "file" in event_type:
            f = random.choice(NORMAL_FILES)
            event["details"] = f"path={f}"
            event["file_path"] = f
            event["file_clearance"] = _get_file_clearance(f)

        if event_type == "process_start":
            proc = random.choice(PROCESSES)
            event["details"] = f"process={proc}"

        return event

    def _inject_minor_anomaly(self, event: dict, now: datetime) -> dict:
        """Inject a small anomaly into a normal event."""
        anomaly = random.choice([
            "off_hours", "external_ip", "sensitive_file", "suspicious_process",
        ])

        if anomaly == "off_hours":
            # Shift timestamp to 2-5 AM
            shifted = now.replace(hour=random.randint(2, 5), minute=random.randint(0, 59))
            event["timestamp"] = shifted.isoformat()
            event["risk_score"] = round(random.uniform(0.2, 0.4), 3)
            event["details"] += " [off-hours activity]"

        elif anomaly == "external_ip":
            event["ip_address"] = random.choice(EXTERNAL_IPS)
            event["risk_score"] = round(random.uniform(0.3, 0.5), 3)
            event["details"] += " [external IP]"

        elif anomaly == "sensitive_file":
            f = random.choice(SENSITIVE_FILES)
            event["event_type"] = random.choice(["file_read", "file_download"])
            event["details"] = f"path={f} [sensitive file access]"
            event["file_path"] = f
            event["file_clearance"] = _get_file_clearance(f)
            event["risk_score"] = round(random.uniform(0.4, 0.7), 3)

        elif anomaly == "suspicious_process":
            proc = random.choice(SUSPICIOUS_PROCESSES)
            event["event_type"] = "process_start"
            event["details"] = f"process={proc} [suspicious process]"
            event["risk_score"] = round(random.uniform(0.5, 0.8), 3)

        return event

    # ── Scenarios ─────────────────────────────────────────────────────────────
    async def _scenario_brute_force(
        self, queue: asyncio.Queue, target_uid: str | None = None, attempts: int = 20,
        **_,
    ) -> list[dict]:
        """Rapid login failures from multiple IPs against one account."""
        target = target_uid or random.choice(self._employees)
        events = []
        now = datetime.now(timezone.utc)

        for i in range(attempts):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_type": "login_failed",
                "timestamp": (now + timedelta(seconds=i * random.randint(2, 8))).isoformat(),
                "source": "auth_service",
                "employee_uid": target,
                "device_hostname": random.choice(DEVICES),
                "ip_address": random.choice(EXTERNAL_IPS),
                "risk_score": round(0.3 + (i / attempts) * 0.5, 3),
                "details": f"attempt={i+1}/{attempts} password_mismatch",
                "raw_path": "",
            }
            events.append(event)
            await queue.put(("logs", event))

        # Final lockout
        lockout = {
            "event_id": str(uuid.uuid4()),
            "event_type": "account_lockout",
            "timestamp": (now + timedelta(seconds=attempts * 8 + 5)).isoformat(),
            "source": "auth_service",
            "employee_uid": target,
            "device_hostname": "DC-MAIN-001",
            "ip_address": "10.0.0.1",
            "risk_score": 0.9,
            "details": f"auto_lockout after {attempts} failed attempts",
            "raw_path": "",
        }
        events.append(lockout)
        await queue.put(("logs", lockout))
        return events

    async def _scenario_data_exfiltration(
        self, queue: asyncio.Queue, actor_uid: str | None = None, **_,
    ) -> list[dict]:
        """Mass download of sensitive files followed by external connection."""
        actor = actor_uid or random.choice(self._employees)
        events = []
        now = datetime.now(timezone.utc)

        # Step 1: multiple sensitive file downloads
        for i, f in enumerate(random.sample(SENSITIVE_FILES, min(6, len(SENSITIVE_FILES)))):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_type": "file_download",
                "timestamp": (now + timedelta(minutes=i * 2)).isoformat(),
                "source": "file_server",
                "employee_uid": actor,
                "device_hostname": random.choice(DEVICES),
                "ip_address": random.choice(INTERNAL_IPS),
                "risk_score": round(0.5 + i * 0.05, 3),
                "details": f"path={f} size=15MB",
                "raw_path": "",
                "file_path": f,
                "file_clearance": _get_file_clearance(f),
            }
            events.append(event)
            await queue.put(("logs", event))

        # Step 2: USB mount
        usb = {
            "event_id": str(uuid.uuid4()),
            "event_type": "usb_mount",
            "timestamp": (now + timedelta(minutes=15)).isoformat(),
            "source": "endpoint_agent",
            "employee_uid": actor,
            "device_hostname": random.choice(DEVICES),
            "ip_address": random.choice(INTERNAL_IPS),
            "risk_score": 0.6,
            "details": "USB storage device mounted vendor=SanDisk model=Ultra",
            "raw_path": "",
        }
        events.append(usb)
        await queue.put(("logs", usb))

        # Step 3: External network connection
        ext_conn = {
            "event_id": str(uuid.uuid4()),
            "event_type": "network_connect",
            "timestamp": (now + timedelta(minutes=18)).isoformat(),
            "source": "firewall",
            "employee_uid": actor,
            "device_hostname": random.choice(DEVICES),
            "ip_address": random.choice(EXTERNAL_IPS),
            "risk_score": 0.8,
            "details": "outbound HTTPS to external IP, 450MB transferred",
            "raw_path": "",
        }
        events.append(ext_conn)
        await queue.put(("logs", ext_conn))
        return events

    async def _scenario_insider_threat(
        self, queue: asyncio.Queue, actor_uid: str | None = None, **_,
    ) -> list[dict]:
        """After-hours access to files above clearance + external communication."""
        actor = actor_uid or random.choice(self._employees)
        events = []
        now = datetime.now(timezone.utc).replace(hour=2, minute=30)

        # Late night login
        login = {
            "event_id": str(uuid.uuid4()),
            "event_type": "login_success",
            "timestamp": now.isoformat(),
            "source": "vpn_gateway",
            "employee_uid": actor,
            "device_hostname": "PERSONAL-LAPTOP",
            "ip_address": random.choice(EXTERNAL_IPS),
            "risk_score": 0.5,
            "details": "VPN login from personal device at 02:30",
            "raw_path": "",
        }
        events.append(login)
        await queue.put(("logs", login))

        # Access sensitive files
        for i, f in enumerate(random.sample(SENSITIVE_FILES, 3)):
            event = {
                "event_id": str(uuid.uuid4()),
                "event_type": "file_read",
                "timestamp": (now + timedelta(minutes=5 + i * 3)).isoformat(),
                "source": "file_server",
                "employee_uid": actor,
                "device_hostname": "PERSONAL-LAPTOP",
                "ip_address": random.choice(EXTERNAL_IPS),
                "risk_score": round(0.6 + i * 0.1, 3),
                "details": f"path={f} [off-hours, personal device, VPN]",
                "raw_path": "",
                "file_path": f,
                "file_clearance": _get_file_clearance(f),
            }
            events.append(event)
            await queue.put(("logs", event))

        return events

    async def _scenario_privilege_escalation(
        self, queue: asyncio.Queue, actor_uid: str | None = None, **_,
    ) -> list[dict]:
        """Attempt to escalate privileges and access admin resources."""
        actor = actor_uid or random.choice(self._employees)
        events = []
        now = datetime.now(timezone.utc)

        # Suspicious process
        proc = {
            "event_id": str(uuid.uuid4()),
            "event_type": "process_start",
            "timestamp": now.isoformat(),
            "source": "endpoint_agent",
            "employee_uid": actor,
            "device_hostname": random.choice(DEVICES),
            "ip_address": random.choice(INTERNAL_IPS),
            "risk_score": 0.7,
            "details": "process=mimikatz.exe pid=4521 parent=cmd.exe",
            "raw_path": "",
        }
        events.append(proc)
        await queue.put(("logs", proc))

        # Privilege escalation attempt
        priv = {
            "event_id": str(uuid.uuid4()),
            "event_type": "privilege_escalation",
            "timestamp": (now + timedelta(seconds=30)).isoformat(),
            "source": "endpoint_agent",
            "employee_uid": actor,
            "device_hostname": random.choice(DEVICES),
            "ip_address": random.choice(INTERNAL_IPS),
            "risk_score": 0.85,
            "details": "local admin token obtained via token impersonation",
            "raw_path": "",
        }
        events.append(priv)
        await queue.put(("logs", priv))

        # Attempt to access DC
        dc_access = {
            "event_id": str(uuid.uuid4()),
            "event_type": "network_connect",
            "timestamp": (now + timedelta(minutes=1)).isoformat(),
            "source": "firewall",
            "employee_uid": actor,
            "device_hostname": random.choice(DEVICES),
            "ip_address": "10.0.0.1",
            "risk_score": 0.9,
            "details": "attempted SMB connection to domain controller DC-MAIN-001",
            "raw_path": "",
        }
        events.append(dc_access)
        await queue.put(("logs", dc_access))
        return events
