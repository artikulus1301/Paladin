"""
LLM Module — Ollama client reused from Richter (unchanged).
Supports streaming and non-streaming via Qwen3:8B.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import aiohttp
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from paladin.config.settings import settings

log = structlog.get_logger(__name__)


class OllamaClient:
    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        timeout = aiohttp.ClientTimeout(total=settings.ollama_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=2, max=10))
    async def generate(self, prompt: str, system: str | None = None) -> str:
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "repeat_penalty": 1.1,
                "num_ctx": 8192,
            },
        }
        url = f"{settings.ollama_base_url}/api/generate"
        async with self._session.post(url, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return data.get("response", "")

    async def stream(self, prompt: str, system: str | None = None) -> AsyncIterator[str]:
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system or "",
            "stream": True,
            "options": {"temperature": 0.3, "top_p": 0.9, "num_ctx": 8192},
        }
        url = f"{settings.ollama_base_url}/api/generate"
        async with self._session.post(url, json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.content:
                line = line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue
