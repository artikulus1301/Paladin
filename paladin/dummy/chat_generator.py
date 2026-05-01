"""
Dummy Enterprise — Chat Generator.
Simulates corporate messenger (Slack/Teams-like) with channels and DMs.
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from paladin.config.settings import settings

log = structlog.get_logger(__name__)

CHANNELS = [
    "#general", "#engineering", "#finance", "#hr", "#random",
    "#project-alpha", "#project-beta", "#devops", "#security", "#sales",
]

NORMAL_MESSAGES = [
    "Hey, has anyone seen the latest build results?",
    "The deploy to staging went fine, pushing to prod at 3pm",
    "Can someone review my PR? Link in #engineering",
    "Lunch at the usual place? 12:30?",
    "Meeting in 5 minutes, room 4B",
    "Thanks for fixing that bug, great work!",
    "Updated the wiki with the new API docs",
    "Anyone else having issues with VPN today?",
    "Don't forget to submit your timesheets by Friday",
    "Happy Friday everyone!",
    "CI/CD pipeline is green, all tests passing",
    "Can we reschedule the 1:1 to Thursday?",
    "Heads up: server maintenance tonight 11pm-2am",
    "Quick question about the database migration...",
]

SUSPICIOUS_DM_CONVOS = {
    "insider_chat": [
        ("A", "Hey, are you alone?"),
        ("B", "Yeah, what's up?"),
        ("A", "I've copied the files to my personal drive, will send them tonight"),
        ("B", "Which files?"),
        ("A", "The Q4 financial projections and the merger docs"),
        ("B", "Don't mention this on email, they monitor everything"),
        ("A", "Let's use Signal instead of corporate chat"),
        ("B", "OK. Delete your messages after reading this."),
    ],
    "credential_sharing": [
        ("A", "Hey, I need access to the production database"),
        ("B", "Sure, use these creds: admin / Pr0d_DB_2025!"),
        ("A", "Thanks, I'll use them from home tonight"),
        ("B", "Just don't tell IT, they'll make us go through the ticket system"),
    ],
    "competitor_contact": [
        ("A", "I've been approached by a recruiter from the competitor"),
        ("B", "What did you tell them?"),
        ("A", "Nothing yet, but they're offering 2x if I bring product specs"),
        ("B", "That's industrial espionage..."),
        ("A", "The merger info is worth a lot to them"),
        ("B", "I don't want any part of this"),
        ("A", "Fine, don't tell anyone. I'll handle it myself."),
    ],
}


class ChatGenerator:
    def __init__(self, employees: list[dict]) -> None:
        self._employees = employees
        self._running = False

    async def generate_normal(self, queue: asyncio.Queue, rate_per_min: int = 5) -> None:
        self._running = True
        log.info("chat_generator_start", mode="normal", rate=rate_per_min)
        while self._running:
            msg = self._make_channel_message() if random.random() < 0.7 else self._make_dm()
            await queue.put(("messages", msg))
            await asyncio.sleep((60 / rate_per_min) * random.uniform(0.5, 2.0))

    async def generate_scenario(self, queue: asyncio.Queue, scenario: str, **params) -> list[dict]:
        if scenario not in SUSPICIOUS_DM_CONVOS:
            raise ValueError(f"Unknown scenario: {scenario}")
        events = await self._play_conversation(queue, scenario, **params)
        log.info("chat_scenario_generated", scenario=scenario, n_events=len(events))
        return events

    def stop(self) -> None:
        self._running = False

    def _make_channel_message(self) -> dict:
        sender = random.choice(self._employees)
        others = [e for e in self._employees if e["uid"] != sender["uid"]]
        recipients = random.sample(others, k=min(random.randint(2, 6), len(others)))
        return {
            "msg_id": str(uuid.uuid4()),
            "channel": random.choice(CHANNELS),
            "text": random.choice(NORMAL_MESSAGES),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sender_uid": sender["uid"],
            "recipient_uids": [r["uid"] for r in recipients],
            "is_dm": False,
            "risk_score": round(random.uniform(0.0, 0.05), 3),
            "raw_path": f"/data/raw/messages/{uuid.uuid4()}.json",
            "entities": [],
            "sentiment": "neutral",
        }

    def _make_dm(self) -> dict:
        pair = random.sample(self._employees, 2)
        return {
            "msg_id": str(uuid.uuid4()),
            "channel": f"dm:{pair[0]['uid']}:{pair[1]['uid']}",
            "text": random.choice(NORMAL_MESSAGES[:8]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sender_uid": pair[0]["uid"],
            "recipient_uids": [pair[1]["uid"]],
            "is_dm": True,
            "risk_score": round(random.uniform(0.0, 0.05), 3),
            "raw_path": f"/data/raw/messages/{uuid.uuid4()}.json",
            "entities": [],
            "sentiment": "neutral",
        }

    async def _play_conversation(self, queue: asyncio.Queue, scenario: str, actor_uid: str | None = None, **_) -> list[dict]:
        actors = random.sample(self._employees, 2)
        if actor_uid:
            a = next((e for e in self._employees if e["uid"] == actor_uid), None)
            if a:
                actors[0] = a

        role_map = {"A": actors[0], "B": actors[1]}
        now = datetime.now(timezone.utc)
        events = []

        for i, (role, text) in enumerate(SUSPICIOUS_DM_CONVOS[scenario]):
            sender = role_map[role]
            other = role_map["B" if role == "A" else "A"]
            risk_keywords = {
                "insider_chat": ["files", "merger", "Signal", "delete"],
                "credential_sharing": ["password", "credentials", "admin", "database"],
                "competitor_contact": ["competitor", "recruiter", "specs", "merger"],
            }
            msg = {
                "msg_id": str(uuid.uuid4()),
                "channel": f"dm:{actors[0]['uid']}:{actors[1]['uid']}",
                "text": text,
                "timestamp": (now + timedelta(seconds=i * 18)).isoformat(),
                "sender_uid": sender["uid"],
                "recipient_uids": [other["uid"]],
                "is_dm": True,
                "risk_score": round(0.35 + i * 0.09, 3),
                "raw_path": f"/data/raw/messages/{uuid.uuid4()}.json",
                "entities": risk_keywords.get(scenario, []),
                "sentiment": "secretive",
            }
            events.append(msg)
            await queue.put(("messages", msg))

        return events
