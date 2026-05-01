"""
PostgreSQL client for the cold archive.
Stores JSONB snapshots of archived nodes, incident graphs, and LLM summaries.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)

# In production, use asyncpg. For now, interface-only with optional sync fallback.
try:
    import asyncpg
    HAS_ASYNCPG = True
except ImportError:
    HAS_ASYNCPG = False
    log.warning("asyncpg_not_installed", msg="Archive will be disabled")


INIT_SQL = """
CREATE TABLE IF NOT EXISTS archived_nodes (
    id              SERIAL PRIMARY KEY,
    node_type       VARCHAR(50) NOT NULL,
    node_id         VARCHAR(200) NOT NULL,
    data            JSONB NOT NULL,
    relationships   JSONB DEFAULT '[]',
    archived_at     TIMESTAMPTZ DEFAULT NOW(),
    original_created TIMESTAMPTZ,
    risk_score      FLOAT DEFAULT 0.0,
    incident_id     VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS archived_incidents (
    id              SERIAL PRIMARY KEY,
    incident_id     VARCHAR(100) UNIQUE NOT NULL,
    title           VARCHAR(500),
    severity        VARCHAR(20),
    score           FLOAT,
    graph_snapshot   JSONB NOT NULL,
    llm_summary     TEXT,
    status          VARCHAR(50),
    created_at      TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    archived_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nodes_type ON archived_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_archived ON archived_nodes(archived_at);
CREATE INDEX IF NOT EXISTS idx_nodes_data ON archived_nodes USING GIN(data);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON archived_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_data ON archived_incidents USING GIN(graph_snapshot);
"""


class PostgresClient:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool = None

    async def connect(self) -> None:
        if not HAS_ASYNCPG:
            log.warning("postgres_disabled", reason="asyncpg not installed")
            return
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)
        async with self._pool.acquire() as conn:
            await conn.execute(INIT_SQL)
        log.info("postgres_connected", dsn=self._dsn[:40])

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def archive_node(
        self,
        node_type: str,
        node_id: str,
        data: dict,
        relationships: list[dict] | None = None,
        risk_score: float = 0.0,
        incident_id: str | None = None,
        original_created: str | None = None,
    ) -> None:
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO archived_nodes (node_type, node_id, data, relationships,
                    risk_score, incident_id, original_created)
                VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7)
                ON CONFLICT DO NOTHING
                """,
                node_type, node_id,
                json.dumps(data, default=str),
                json.dumps(relationships or [], default=str),
                risk_score,
                incident_id,
                datetime.fromisoformat(original_created) if original_created else None,
            )

    async def archive_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        score: float,
        graph_snapshot: dict,
        llm_summary: str,
        status: str,
        created_at: str | None = None,
        closed_at: str | None = None,
    ) -> None:
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO archived_incidents
                    (incident_id, title, severity, score, graph_snapshot,
                     llm_summary, status, created_at, closed_at)
                VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)
                ON CONFLICT (incident_id) DO UPDATE SET
                    graph_snapshot = EXCLUDED.graph_snapshot,
                    llm_summary = EXCLUDED.llm_summary,
                    status = EXCLUDED.status,
                    closed_at = EXCLUDED.closed_at,
                    archived_at = NOW()
                """,
                incident_id, title, severity, score,
                json.dumps(graph_snapshot, default=str),
                llm_summary, status,
                datetime.fromisoformat(created_at) if created_at else None,
                datetime.fromisoformat(closed_at) if closed_at else None,
            )

    async def search_archive(self, query: dict, limit: int = 50) -> list[dict]:
        """Search archived nodes using JSONB containment (@>)."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT node_type, node_id, data, archived_at, risk_score
                FROM archived_nodes
                WHERE data @> $1::jsonb
                ORDER BY archived_at DESC
                LIMIT $2
                """,
                json.dumps(query, default=str), limit,
            )
            return [dict(r) for r in rows]
