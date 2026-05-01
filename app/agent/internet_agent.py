"""
Internet Agent.
1. Queries SearXNG (self-hosted) or falls back to DuckDuckGo lite.
2. Fetches top pages and extracts clean text via trafilatura.
3. Returns structured SearchResult objects.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.parse import quote_plus

import aiohttp
import structlog
import trafilatura
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import settings

log = structlog.get_logger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "ru,en;q=0.9",
}


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    content: str   # full extracted text


@dataclass
class AgentResponse:
    query: str
    results: list[SearchResult]

    @property
    def combined_text(self) -> str:
        parts = []
        for r in self.results:
            body = r.content or r.snippet
            if body:
                parts.append(f"[{r.title}]\n{body[:1500]}")
        return "\n\n".join(parts)


class InternetAgent:
    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        self._session = aiohttp.ClientSession(
            headers=HEADERS, timeout=timeout, connector=connector
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    # ── main entry ─────────────────────────────────────────────────────────────
    async def search(self, query: str, n: int | None = None) -> AgentResponse:
        n = n or settings.max_search_results
        urls = await self._searxng(query, n)
        if not urls:
            urls = await self._ddg_fallback(query, n)

        tasks = [self._fetch_page(url, title, snippet) for url, title, snippet in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in results if isinstance(r, SearchResult) and r.content]
        log.info("agent_search_done", query=query, n_results=len(valid))
        return AgentResponse(query=query, results=valid)

    # ── SearXNG ────────────────────────────────────────────────────────────────
    async def _searxng(self, query: str, n: int) -> list[tuple[str, str, str]]:
        try:
            url = (
                f"{settings.searxng_url}/search"
                f"?q={quote_plus(query)}&format=json&language=ru-RU&engines=google,bing,duckduckgo"
            )
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
            results = data.get("results", [])[:n]
            return [(r["url"], r.get("title", ""), r.get("content", "")) for r in results]
        except Exception as exc:
            log.warning("searxng_failed", error=str(exc))
            return []

    # ── DuckDuckGo lite fallback ───────────────────────────────────────────────
    async def _ddg_fallback(self, query: str, n: int) -> list[tuple[str, str, str]]:
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            async with self._session.get(url) as resp:
                html = await resp.text()
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
            items: list[tuple[str, str, str]] = []
            for a in soup.select("a.result__url")[:n]:
                href = a.get("href", "")
                title_tag = a.find_next("a", class_="result__a")
                title = title_tag.get_text(strip=True) if title_tag else ""
                snippet_tag = a.find_next("a", class_="result__snippet")
                snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
                if href.startswith("http"):
                    items.append((href, title, snippet))
            return items
        except Exception as exc:
            log.warning("ddg_fallback_failed", error=str(exc))
            return []

    # ── page fetch + extraction ────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(2), wait=wait_exponential(min=0.5, max=3))
    async def _fetch_page(
        self, url: str, title: str, snippet: str
    ) -> SearchResult:
        try:
            async with self._session.get(url, allow_redirects=True) as resp:
                if resp.status != 200:
                    return SearchResult(title=title, url=url, snippet=snippet, content="")
                html = await resp.text(errors="replace")

            text = trafilatura.extract(
                html,
                include_comments=False,
                include_tables=True,
                favor_precision=True,
                deduplicate=True,
            ) or ""

            return SearchResult(title=title, url=url, snippet=snippet, content=text[:4000])
        except Exception as exc:
            log.debug("page_fetch_error", url=url, error=str(exc))
            return SearchResult(title=title, url=url, snippet=snippet, content="")
