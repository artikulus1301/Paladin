"""
Ingestion Layer — Unified collector base and per-source collectors.
In dummy mode: reads from asyncio.Queue (replaces Kafka).
In production mode: would read from Kafka topics.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Awaitable

import structlog

from paladin.config.settings import settings

log = structlog.get_logger(__name__)

RAW_DATA_DIR = Path("data/raw")


class BaseCollector(ABC):
    """Base collector — reads events from a queue/topic and forwards to SAP callback."""

    def __init__(self, topic: str) -> None:
        self.topic = topic
        self._running = False

    async def start(
        self,
        queue: asyncio.Queue,
        callback: Callable[[str, dict], Awaitable[None]],
    ) -> None:
        """Read from queue and invoke callback(topic, event) for each event."""
        self._running = True
        log.info("collector_start", topic=self.topic)
        while self._running:
            try:
                topic, raw_event = await asyncio.wait_for(queue.get(), timeout=1.0)
                if topic != self.topic:
                    # Put back if wrong topic (shouldn't happen with per-topic queues)
                    await queue.put((topic, raw_event))
                    continue
                event = self.preprocess(raw_event)
                await self._save_raw(event)
                await callback(self.topic, event)
                queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error("collector_error", topic=self.topic, error=str(e))

    def stop(self) -> None:
        self._running = False

    @abstractmethod
    def preprocess(self, raw: dict) -> dict:
        """Transform raw generator output into normalized event dict."""
        ...

    async def _save_raw(self, event: dict) -> None:
        """Save raw event data to filesystem. In Neo4j we only store the path."""
        raw_path = event.get("raw_path", "")
        if not raw_path:
            return
        path = RAW_DATA_DIR / raw_path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        # Save only text content, not binary
        text_fields = {k: v for k, v in event.items()
                       if isinstance(v, (str, int, float, bool, list))}
        path.write_text(json.dumps(text_fields, ensure_ascii=False, indent=2), encoding="utf-8")


class LogCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__("logs")

    def preprocess(self, raw: dict) -> dict:
        raw.setdefault("event_id", str(uuid.uuid4()))
        raw.setdefault("risk_score", 0.0)
        raw.setdefault("raw_path", f"/data/raw/logs/{raw['event_id']}.json")
        return raw


class MailCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__("emails")

    def preprocess(self, raw: dict) -> dict:
        raw.setdefault("message_id", f"<{uuid.uuid4()}@paladin.local>")
        raw.setdefault("risk_score", 0.0)
        raw.setdefault("entities", [])
        raw.setdefault("sentiment", "neutral")
        raw.setdefault("raw_path", f"/data/raw/emails/{uuid.uuid4()}.eml")
        return raw


class ChatCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__("messages")

    def preprocess(self, raw: dict) -> dict:
        raw.setdefault("msg_id", str(uuid.uuid4()))
        raw.setdefault("risk_score", 0.0)
        raw.setdefault("entities", [])
        raw.setdefault("sentiment", "neutral")
        raw.setdefault("raw_path", f"/data/raw/messages/{raw['msg_id']}.json")
        return raw


class CallCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__("calls")

    def preprocess(self, raw: dict) -> dict:
        raw.setdefault("call_id", str(uuid.uuid4()))
        raw.setdefault("risk_score", 0.0)
        raw.setdefault("entities", [])
        raw.setdefault("sentiment", "neutral")
        raw.setdefault("raw_path", f"/data/raw/calls/{raw['call_id']}.txt")
        return raw
