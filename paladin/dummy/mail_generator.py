"""
Dummy Enterprise — Mail Generator.
Simulates SMTP/IMAP traffic between virtual employees.
Includes normal correspondence and suspicious emails (phishing, data leak, social engineering).
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

import structlog

from paladin.config.settings import settings

log = structlog.get_logger(__name__)

# ── Content templates ─────────────────────────────────────────────────────────

NORMAL_SUBJECTS = [
    "Re: Meeting tomorrow at 10",
    "Updated project timeline",
    "Lunch plans?",
    "Q4 quarterly review slides",
    "Team standup notes — {date}",
    "FYI: Office maintenance this weekend",
    "New onboarding docs",
    "RE: Client feedback on proposal",
    "Vacation request — {date}",
    "Happy birthday!",
    "Shared: Design mockups v2",
    "Action items from today's sync",
    "RE: Parking lot changes",
    "Jenkins build #1847 — PASSED",
    "Weekly digest — Engineering",
]

NORMAL_BODIES = [
    "Hi team,\n\nPlease review the attached document and send your feedback by EOD Friday.\n\nBest regards",
    "Hey,\n\nJust wanted to check in on the progress. Let me know if you need anything.\n\nThanks!",
    "Hi all,\n\nReminder that the deadline for Q4 reports is next Monday. Please ensure everything is submitted.\n\nCheers",
    "Good morning,\n\nThe meeting has been rescheduled to 2 PM. Same conference room.\n\nRegards",
    "Hello,\n\nAttached are the updated slides for tomorrow's presentation. Please review.\n\nBest",
    "Hi,\n\nI'll be out of office next week. Please contact {name} for urgent matters.\n\nThanks",
]

SUSPICIOUS_SUBJECTS = [
    "URGENT: Wire transfer needed immediately",
    "Confidential: Salary data — DO NOT FORWARD",
    "RE: External audit — leaked documents",
    "Password reset required — click here",
    "FW: Client database export",
    "Private: Merger details — eyes only",
    "Job offer — strictly confidential",
    "RE: Sending you the files you requested via personal email",
    "Invoice #38291 — payment overdue",
    "Action required: verify your credentials",
]

SUSPICIOUS_BODIES = [
    "Hi,\n\nI need you to process this wire transfer urgently. The CEO approved it verbally.\nAccount: CH93 0076 2011 6238 5295 7\nAmount: $45,000\n\nPlease do this ASAP before the deadline.\n\nThanks",
    "Hey,\n\nAs discussed, here's the salary data for all departments. I've exported it to CSV.\nPlease don't share this with anyone outside our group.\n\nI've attached it to my personal Dropbox: https://dropbox.com/s/fake-link/salaries.csv",
    "Hi,\n\nI found some concerning documents during the audit. Attaching the leaked files.\nWe should discuss this privately, not through official channels.\n\nLet's meet outside the office.",
    "Dear user,\n\nYour corporate account password will expire in 24 hours.\nPlease click the link below to verify your credentials:\nhttps://corp-login.secure-verify.xyz/reset\n\nIT Department",
    "Hi,\n\nI've exported the client database as requested. Sending via personal email since\nthe file is too large for our corporate system.\n\nFile: clients_full_export_2025.sql.gz (340MB)\nPassword: company2025\n\nPlease delete after downloading.",
    "Strictly Confidential\n\nThe merger with TechCorp is proceeding. Target acquisition price: $2.3B.\nBoard vote scheduled for next Thursday.\n\nDO NOT discuss on corporate channels. Use Signal.",
]

ATTACHMENT_NAMES = [
    "report.pdf", "data.xlsx", "presentation.pptx",
    "invoice.pdf", "contract.docx", "export.csv",
    "backup.zip", "credentials.kdbx", "schema.sql",
    "employee_list.csv", "financial_model.xlsx",
]

EXTERNAL_DOMAINS = [
    "gmail.com", "yahoo.com", "protonmail.com",
    "outlook.com", "hotmail.com", "tutanota.com",
]


class MailGenerator:
    """
    Generates email traffic between virtual employees.
    Modes: normal (routine correspondence) and incident (suspicious emails).
    """

    def __init__(self, employees: list[dict]) -> None:
        """employees: list of dicts with uid, full_name, email keys."""
        self._employees = employees
        self._running = False

    async def generate_normal(self, queue: asyncio.Queue, rate_per_min: int = 3) -> None:
        """Continuous normal email traffic."""
        self._running = True
        log.info("mail_generator_start", mode="normal", rate=rate_per_min)

        while self._running:
            email = self._make_normal_email()
            await queue.put(("emails", email))
            # Emails are less frequent than logs
            jitter = random.uniform(0.7, 1.5)
            await asyncio.sleep((60 / rate_per_min) * jitter)

    async def generate_scenario(
        self, queue: asyncio.Queue, scenario: str, **params
    ) -> list[dict]:
        """Generate email-based incident scenarios."""
        generators = {
            "phishing": self._scenario_phishing,
            "data_leak_email": self._scenario_data_leak,
            "social_engineering": self._scenario_social_engineering,
            "external_exfil": self._scenario_external_exfil,
        }
        gen = generators.get(scenario)
        if not gen:
            raise ValueError(f"Unknown scenario: {scenario}. Available: {list(generators)}")

        events = await gen(queue, **params)
        log.info("mail_scenario_generated", scenario=scenario, n_events=len(events))
        return events

    def stop(self) -> None:
        self._running = False

    # ── Normal email ──────────────────────────────────────────────────────────
    def _make_normal_email(self) -> dict:
        sender = random.choice(self._employees)
        recipients = random.sample(
            [e for e in self._employees if e["uid"] != sender["uid"]],
            k=min(random.randint(1, 3), len(self._employees) - 1),
        )
        now = datetime.now(timezone.utc)
        subject = random.choice(NORMAL_SUBJECTS).replace("{date}", now.strftime("%Y-%m-%d"))
        body = random.choice(NORMAL_BODIES).replace(
            "{name}", random.choice(self._employees)["full_name"]
        )
        has_attachment = random.random() < 0.2

        return {
            "message_id": f"<{uuid.uuid4()}@corp.paladin.local>",
            "subject": subject,
            "body": body,
            "timestamp": now.isoformat(),
            "sender_uid": sender["uid"],
            "sender_email": sender["email"],
            "recipient_uids": [r["uid"] for r in recipients],
            "recipient_emails": [r["email"] for r in recipients],
            "has_attachment": has_attachment,
            "attachment_name": random.choice(ATTACHMENT_NAMES) if has_attachment else "",
            "risk_score": round(random.uniform(0.0, 0.1), 3),
            "raw_path": f"/data/raw/emails/{uuid.uuid4()}.eml",
            "entities": [],
            "sentiment": "neutral",
            "is_external": False,
        }

    # ── Scenarios ─────────────────────────────────────────────────────────────
    async def _scenario_phishing(
        self, queue: asyncio.Queue, target_uid: str | None = None, **_,
    ) -> list[dict]:
        """Phishing email from spoofed/external address."""
        target = None
        if target_uid:
            target = next((e for e in self._employees if e["uid"] == target_uid), None)
        if not target:
            target = random.choice(self._employees)

        now = datetime.now(timezone.utc)
        email = {
            "message_id": f"<{uuid.uuid4()}@{random.choice(EXTERNAL_DOMAINS)}>",
            "subject": "Action required: verify your credentials",
            "body": SUSPICIOUS_BODIES[3],  # Credential phishing
            "timestamp": now.isoformat(),
            "sender_uid": "__external__",
            "sender_email": f"it-support@{random.choice(EXTERNAL_DOMAINS)}",
            "recipient_uids": [target["uid"]],
            "recipient_emails": [target["email"]],
            "has_attachment": False,
            "attachment_name": "",
            "risk_score": 0.85,
            "raw_path": f"/data/raw/emails/{uuid.uuid4()}.eml",
            "entities": ["password", "credentials", "verify"],
            "sentiment": "urgent",
            "is_external": True,
        }
        await queue.put(("emails", email))
        return [email]

    async def _scenario_data_leak(
        self, queue: asyncio.Queue, actor_uid: str | None = None, **_,
    ) -> list[dict]:
        """Employee sends sensitive data to external address."""
        actor = None
        if actor_uid:
            actor = next((e for e in self._employees if e["uid"] == actor_uid), None)
        if not actor:
            actor = random.choice(self._employees)

        now = datetime.now(timezone.utc)
        events = []

        # Step 1: internal email discussing confidential data
        internal = self._make_normal_email()
        internal["sender_uid"] = actor["uid"]
        internal["subject"] = "RE: Confidential project data"
        internal["body"] = "Here's the data you asked about. Let's discuss offline."
        internal["risk_score"] = 0.3
        internal["timestamp"] = now.isoformat()
        events.append(internal)
        await queue.put(("emails", internal))

        # Step 2: forward to personal email
        leak = {
            "message_id": f"<{uuid.uuid4()}@corp.paladin.local>",
            "subject": "FW: Confidential project data",
            "body": SUSPICIOUS_BODIES[4],  # Database export
            "timestamp": (now + timedelta(minutes=5)).isoformat(),
            "sender_uid": actor["uid"],
            "sender_email": actor["email"],
            "recipient_uids": ["__external__"],
            "recipient_emails": [f"{actor['full_name'].split()[0].lower()}@gmail.com"],
            "has_attachment": True,
            "attachment_name": "clients_full_export_2025.sql.gz",
            "risk_score": 0.9,
            "raw_path": f"/data/raw/emails/{uuid.uuid4()}.eml",
            "entities": ["database", "export", "clients", "password"],
            "sentiment": "secretive",
            "is_external": True,
        }
        events.append(leak)
        await queue.put(("emails", leak))
        return events

    async def _scenario_social_engineering(
        self, queue: asyncio.Queue, target_uid: str | None = None, **_,
    ) -> list[dict]:
        """CEO fraud / BEC attack — fake urgent wire transfer request."""
        target = None
        if target_uid:
            target = next((e for e in self._employees if e["uid"] == target_uid), None)
        if not target:
            # Target someone in Finance
            finance = [e for e in self._employees if "fin" in e.get("department", "").lower()]
            target = random.choice(finance) if finance else random.choice(self._employees)

        # Find a "CEO" or executive to impersonate
        execs = [e for e in self._employees if "exec" in e.get("department", "").lower() or "ceo" in e.get("role", "").lower()]
        impersonated = random.choice(execs) if execs else random.choice(self._employees)

        now = datetime.now(timezone.utc)
        email = {
            "message_id": f"<{uuid.uuid4()}@{random.choice(EXTERNAL_DOMAINS)}>",
            "subject": "URGENT: Wire transfer needed immediately",
            "body": SUSPICIOUS_BODIES[0],  # Wire transfer scam
            "timestamp": now.isoformat(),
            "sender_uid": "__external__",
            "sender_email": f"{impersonated['full_name'].replace(' ', '.').lower()}@{random.choice(EXTERNAL_DOMAINS)}",
            "recipient_uids": [target["uid"]],
            "recipient_emails": [target["email"]],
            "has_attachment": False,
            "attachment_name": "",
            "risk_score": 0.92,
            "raw_path": f"/data/raw/emails/{uuid.uuid4()}.eml",
            "entities": ["wire transfer", "CEO", "urgent", "bank account"],
            "sentiment": "urgent_pressure",
            "is_external": True,
        }
        await queue.put(("emails", email))
        return [email]

    async def _scenario_external_exfil(
        self, queue: asyncio.Queue, actor_uid: str | None = None, **_,
    ) -> list[dict]:
        """Multiple emails with attachments to external domains over time."""
        actor = None
        if actor_uid:
            actor = next((e for e in self._employees if e["uid"] == actor_uid), None)
        if not actor:
            actor = random.choice(self._employees)

        now = datetime.now(timezone.utc)
        events = []
        ext_email = f"contact.{random.randint(100,999)}@protonmail.com"

        for i in range(4):
            email = {
                "message_id": f"<{uuid.uuid4()}@corp.paladin.local>",
                "subject": f"Files part {i+1}/4",
                "body": f"Part {i+1} attached. Password same as before.",
                "timestamp": (now + timedelta(minutes=i * 10)).isoformat(),
                "sender_uid": actor["uid"],
                "sender_email": actor["email"],
                "recipient_uids": ["__external__"],
                "recipient_emails": [ext_email],
                "has_attachment": True,
                "attachment_name": f"archive_part{i+1}.7z",
                "risk_score": round(0.6 + i * 0.1, 3),
                "raw_path": f"/data/raw/emails/{uuid.uuid4()}.eml",
                "entities": ["archive", "password", "encrypted"],
                "sentiment": "secretive",
                "is_external": True,
            }
            events.append(email)
            await queue.put(("emails", email))

        return events
