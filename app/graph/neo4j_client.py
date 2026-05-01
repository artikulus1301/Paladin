"""
Neo4j graph client.
- search_relevant: find nodes/edges matching keywords from SpaCy
- save_concepts: persist extracted concepts and relations from web content
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from neo4j import AsyncGraphDatabase, AsyncDriver
from tenacity import retry, stop_after_attempt, wait_exponential

from config.settings import settings
from app.pipeline.spacy_analyzer import AnalysisResult, Triplet

log = structlog.get_logger(__name__)


# ── Cypher queries ─────────────────────────────────────────────────────────────
_SEARCH_QUERY = """
UNWIND $keywords AS kw
MATCH (c:Concept)
WHERE toLower(c.name) CONTAINS toLower(kw)
   OR ANY(alias IN c.aliases WHERE toLower(alias) CONTAINS toLower(kw))
WITH c, count(*) AS score
ORDER BY score DESC
LIMIT $limit
OPTIONAL MATCH (c)-[r]->(related:Concept)
RETURN c.name AS concept,
       c.description AS description,
       c.source AS source,
       collect(DISTINCT {rel: type(r), target: related.name}) AS relations,
       score
"""

_UPSERT_CONCEPT = """
MERGE (c:Concept {name: $name})
ON CREATE SET
    c.name        = $name,
    c.description = $description,
    c.source      = $source,
    c.created_at  = datetime()
ON MATCH SET
    c.description = CASE WHEN $description <> '' THEN $description ELSE c.description END,
    c.updated_at  = datetime()
RETURN c
"""

_UPSERT_RELATION = """
MATCH (a:Concept {name: $subject}), (b:Concept {name: $obj})
MERGE (a)-[r:RELATED {predicate: $predicate}]->(b)
ON CREATE SET r.created_at = datetime(), r.weight = 1
ON MATCH  SET r.weight = r.weight + 1
RETURN r
"""

_INIT_CONSTRAINTS = [
    "CREATE CONSTRAINT concept_name IF NOT EXISTS FOR (c:Concept) REQUIRE c.name IS UNIQUE",
    "CREATE INDEX concept_desc IF NOT EXISTS FOR (c:Concept) ON (c.description)",
]


class Neo4jClient:
    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=20,
        )
        await self._driver.verify_connectivity()
        await self._init_schema()
        log.info("neo4j_connected", uri=settings.neo4j_uri)

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()

    async def _init_schema(self) -> None:
        async with self._driver.session() as session:
            for cql in _INIT_CONSTRAINTS:
                try:
                    await session.run(cql)
                except Exception as e:
                    log.warning("constraint_already_exists", error=str(e))

    # ── public API ─────────────────────────────────────────────────────────────
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def search_relevant(
        self, analysis: AnalysisResult, limit: int | None = None
    ) -> list[dict]:
        """Return a list of relevant concept dicts from the graph."""
        limit = limit or settings.max_neo4j_results
        keywords = analysis.keywords + [e.lemma for e in analysis.entities]
        if not keywords:
            return []

        async with self._driver.session() as session:
            result = await session.run(
                _SEARCH_QUERY,
                keywords=list(set(keywords)),
                limit=limit,
            )
            records = await result.data()

        log.debug("neo4j_search", n_keywords=len(keywords), n_results=len(records))
        return records

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def save_concepts(
        self,
        triplets: list[Triplet],
        descriptions: dict[str, str],  # concept_name -> description text
        source: str = "internet",
    ) -> int:
        """Upsert concepts and their relations. Returns count of saved nodes."""
        saved = 0
        async with self._driver.session() as session:
            # gather all unique concept names
            concept_names: set[str] = set()
            for t in triplets:
                concept_names.add(t.subject)
                concept_names.add(t.obj)

            for name in concept_names:
                await session.run(
                    _UPSERT_CONCEPT,
                    name=name,
                    description=descriptions.get(name, ""),
                    source=source,
                )
                saved += 1

            for t in triplets:
                await session.run(
                    _UPSERT_RELATION,
                    subject=t.subject,
                    predicate=t.predicate,
                    obj=t.obj,
                )

        log.info("neo4j_saved", concepts=saved, relations=len(triplets))
        return saved

    def format_context(self, records: list[dict]) -> str:
        """Convert Neo4j records to a compact context string for the LLM."""
        if not records:
            return ""
        lines = ["[Graph Knowledge Base]"]
        for r in records:
            lines.append(f"• {r['concept']}: {r.get('description', '')}")
            for rel in (r.get("relations") or []):
                if rel.get("target"):
                    lines.append(f"  → {rel['rel']} → {rel['target']}")
        return "\n".join(lines)
