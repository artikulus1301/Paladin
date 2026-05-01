"""
Dummy Enterprise — Call Generator.
Produces text transcripts of phone calls between employees.
STT stage skipped in dummy mode (pre-generated transcripts).
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from paladin.config.settings import settings

log = structlog.get_logger(__name__)

NORMAL_TRANSCRIPTS = [
    "Hi, this is {caller}. Just calling about the project timeline. Can we push the deadline to Friday? OK great, thanks.",
    "Hey {callee}, quick question about the budget allocation for Q4. I think we need to increase the marketing spend. Let me send you the numbers.",
    "{caller}: Good morning. I wanted to discuss the team restructuring. {callee}: Sure, what are you thinking? {caller}: We need two more engineers on project Alpha.",
    "{caller}: Did you get my email about the client meeting? {callee}: Yes, I'll prepare the slides by tomorrow. {caller}: Perfect, let's sync before the call.",
    "{caller}: Hi, calling about the vendor contract renewal. {callee}: Right, we need to negotiate better terms this year. {caller}: Agreed, I'll set up a meeting with procurement.",
]

SUSPICIOUS_TRANSCRIPTS = {
    "data_theft_call": [
        "{caller}: Listen, I've got the financial projections. All of them. {callee}: The ones from the board meeting? {caller}: Yes. I'm going to copy them to an encrypted drive tonight. {callee}: Be careful, they've been monitoring file access. {caller}: I know, I'll use my personal laptop on the guest WiFi. {callee}: OK, I'll have the buyer ready. What's the price? {caller}: Two hundred thousand. Non-negotiable.",
    ],
    "insider_recruitment": [
        "{caller}: I got a call from someone at TechCorp. They want our chip designs. {callee}: How much are they offering? {caller}: Five hundred K if we deliver the full schematics. {callee}: That's a lot of money... {caller}: I know. I need someone from engineering to help me extract the files. Are you in? {callee}: I... I need to think about it. {caller}: Don't take too long. And don't tell anyone.",
    ],
    "bribery_call": [
        "{caller}: About the procurement contract — I can make sure your company gets selected. {callee}: What do you need from us? {caller}: Ten percent of the contract value. Cash. {callee}: That's a lot... {caller}: Consider it a consulting fee. Wire it to this offshore account. I'll send you the details on Signal. {callee}: OK, let me discuss with my team.",
    ],
}


class CallGenerator:
    def __init__(self, employees: list[dict]) -> None:
        self._employees = employees
        self._running = False

    async def generate_normal(self, queue: asyncio.Queue, rate_per_min: float = 1.0) -> None:
        self._running = True
        log.info("call_generator_start", mode="normal", rate=rate_per_min)
        while self._running:
            call = self._make_normal_call()
            await queue.put(("calls", call))
            await asyncio.sleep((60 / rate_per_min) * random.uniform(0.5, 3.0))

    async def generate_scenario(self, queue: asyncio.Queue, scenario: str, **params) -> list[dict]:
        if scenario not in SUSPICIOUS_TRANSCRIPTS:
            raise ValueError(f"Unknown scenario: {scenario}. Available: {list(SUSPICIOUS_TRANSCRIPTS)}")
        events = await self._make_suspicious_call(queue, scenario, **params)
        log.info("call_scenario_generated", scenario=scenario, n_events=len(events))
        return events

    def stop(self) -> None:
        self._running = False

    def _make_normal_call(self) -> dict:
        pair = random.sample(self._employees, 2)
        caller, callee = pair[0], pair[1]
        transcript = random.choice(NORMAL_TRANSCRIPTS).format(
            caller=caller["full_name"], callee=callee["full_name"],
        )
        duration = random.randint(30, 600)
        return {
            "call_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "caller_uid": caller["uid"],
            "callee_uid": callee["uid"],
            "duration_s": duration,
            "transcript": transcript,
            "risk_score": round(random.uniform(0.0, 0.1), 3),
            "raw_path": f"/data/raw/calls/{uuid.uuid4()}.txt",
            "entities": [],
            "sentiment": "neutral",
        }

    async def _make_suspicious_call(self, queue: asyncio.Queue, scenario: str, actor_uid: str | None = None, **_) -> list[dict]:
        pair = random.sample(self._employees, 2)
        if actor_uid:
            a = next((e for e in self._employees if e["uid"] == actor_uid), None)
            if a:
                pair[0] = a

        caller, callee = pair[0], pair[1]
        transcript = random.choice(SUSPICIOUS_TRANSCRIPTS[scenario]).format(
            caller=caller["full_name"], callee=callee["full_name"],
        )

        risk_entities = {
            "data_theft_call": ["financial projections", "encrypted drive", "buyer", "board meeting"],
            "insider_recruitment": ["chip designs", "schematics", "TechCorp", "extract files"],
            "bribery_call": ["procurement", "contract", "offshore account", "consulting fee"],
        }

        call = {
            "call_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "caller_uid": caller["uid"],
            "callee_uid": callee["uid"],
            "duration_s": random.randint(120, 480),
            "transcript": transcript,
            "risk_score": round(random.uniform(0.7, 0.95), 3),
            "raw_path": f"/data/raw/calls/{uuid.uuid4()}.txt",
            "entities": risk_entities.get(scenario, []),
            "sentiment": "conspiratorial",
        }
        await queue.put(("calls", call))
        return [call]
