"""
Ollama client for Qwen 3.5:9B.
Supports both streaming and non-streaming completions.
"""
from __future__ import annotations

import json
from typing import AsyncIterator

import aiohttp
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import settings

log = structlog.get_logger(__name__)

_SYSTEM_PROMPT = """You are a knowledgeable assistant with access to a knowledge graph and recent internet search results.
Answer clearly, accurately, and concisely. 
- Cite information sources when available.
- If information is uncertain, say so explicitly.
- Prefer structured responses for complex topics.
- Respond in the same language as the user's question.
"""


class OllamaClient:
    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        timeout = aiohttp.ClientTimeout(total=settings.ollama_timeout)
        self._session = aiohttp.ClientSession(timeout=timeout)

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    # ── non-streaming ──────────────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=2, max=10))
    async def generate(self, prompt: str, system: str | None = None) -> str:
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system or _SYSTEM_PROMPT,
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

    # ── streaming ──────────────────────────────────────────────────────────────
    async def stream(
        self, prompt: str, system: str | None = None
    ) -> AsyncIterator[str]:
        payload = {
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system or _SYSTEM_PROMPT,
            "stream": True,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "num_ctx": 8192,
            },
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

    # ── prompt builders ────────────────────────────────────────────────────────
    @staticmethod
    def build_rag_prompt(
        question: str,
        graph_context: str,
        web_context: str,
    ) -> str:
        sections = [f"User question: {question}\n"]
        if graph_context:
            sections.append(f"=== Knowledge Graph ===\n{graph_context}\n")
        if web_context:
            sections.append(f"=== Web Search Results ===\n{web_context}\n")
        sections.append("Please provide a comprehensive answer based on the above context.")
        return "\n".join(sections)

    @staticmethod
    def build_reformat_prompt(question: str, raw_web_text: str) -> str:
        return (
            f"User question: {question}\n\n"
            f"=== Raw web content ===\n{raw_web_text[:6000]}\n\n"
            "Extract and present the relevant information clearly and concisely. "
            "Do not add information not present in the source text."
        )
