"""
Archiver — cron-style service that transfers old data from Neo4j to PostgreSQL.

Policies:
- LogEvent older than 30 days NOT linked to incident → archive
- Email/Message/Call older than 90 days with risk_score < 0.2 → archive
- Closed Incidents older than 180 days → archive
- Archived nodes get flagged archived=true in Neo4j (NOT deleted)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog

from paladin.config.settings import settings
from paladin.graph.neo4j_client import Neo4jClient
from paladin.archive.postgres_client import PostgresClient

log = structlog.get_logger(__name__)


class Archiver:
    def __init__(self, neo4j: Neo4jClient, postgres: PostgresClient) -> None:
        self._neo4j = neo4j
        self._pg = postgres

    async def run_archive_cycle(self) -> dict:
        """Execute one full archive cycle. Returns stats."""
        stats = {"logs": 0, "comms": 0, "incidents": 0}

        stats["logs"] = await self._archive_old_logs()
        stats["comms"] = await self._archive_old_comms()
        stats["incidents"] = await self._archive_closed_incidents()

        log.info("archive_cycle_done", **stats)
        return stats

    async def _archive_old_logs(self) -> int:
        """Archive LogEvents older than archive_log_days not linked to incidents."""
        days = settings.archive_log_days
        async with self._neo4j._driver.session() as session:
            result = await session.run(
                """
                MATCH (l:LogEvent)
                WHERE l.archived = false
                  AND l.timestamp < datetime() - duration({days: $days})
                  AND NOT (l)-[:TRIGGERED_BY]->(:Incident)
                RETURN l.event_id AS eid, properties(l) AS props
                LIMIT 500
                """,
                days=days,
            )
            records = await result.data()

        count = 0
        for rec in records:
            await self._pg.archive_node(
                node_type="LogEvent",
                node_id=rec["eid"],
                data=rec["props"],
                risk_score=rec["props"].get("risk_score", 0),
            )
            # Mark as archived in Neo4j
            async with self._neo4j._driver.session() as session:
                await session.run(
                    "MATCH (l:LogEvent {event_id: $eid}) SET l.archived = true",
                    eid=rec["eid"],
                )
            count += 1

        return count

    async def _archive_old_comms(self) -> int:
        """Archive Email/Message/Call older than archive_comms_days with low risk."""
        days = settings.archive_comms_days
        cutoff = settings.archive_risk_score_cutoff
        count = 0

        for label, id_field in [("Email", "message_id"), ("Message", "msg_id"), ("Call", "call_id")]:
            async with self._neo4j._driver.session() as session:
                result = await session.run(
                    f"""
                    MATCH (n:{label})
                    WHERE n.archived = false
                      AND n.timestamp < datetime() - duration({{days: $days}})
                      AND n.risk_score < $cutoff
                      AND NOT (n)-[:TRIGGERED_BY]->(:Incident)
                    RETURN n.{id_field} AS nid, properties(n) AS props
                    LIMIT 200
                    """,
                    days=days, cutoff=cutoff,
                )
                records = await result.data()

            for rec in records:
                await self._pg.archive_node(
                    node_type=label,
                    node_id=rec["nid"],
                    data=rec["props"],
                    risk_score=rec["props"].get("risk_score", 0),
                )
                async with self._neo4j._driver.session() as session:
                    await session.run(
                        f"MATCH (n:{label} {{{id_field}: $nid}}) SET n.archived = true",
                        nid=rec["nid"],
                    )
                count += 1

        return count

    async def _archive_closed_incidents(self) -> int:
        """Archive closed incidents older than archive_incident_days."""
        days = settings.archive_incident_days
        async with self._neo4j._driver.session() as session:
            result = await session.run(
                """
                MATCH (i:Incident)
                WHERE i.status = "closed"
                  AND i.updated_at < datetime() - duration({days: $days})
                RETURN i.incident_id AS iid, properties(i) AS props
                LIMIT 50
                """,
                days=days,
            )
            records = await result.data()

        count = 0
        for rec in records:
            # Get incident subgraph for snapshot
            subgraph = await self._neo4j.get_incident_subgraph(rec["iid"])

            await self._pg.archive_incident(
                incident_id=rec["iid"],
                title=rec["props"].get("title", ""),
                severity=rec["props"].get("severity", ""),
                score=rec["props"].get("score", 0),
                graph_snapshot=subgraph,
                llm_summary=rec["props"].get("llm_summary", ""),
                status="archived",
                created_at=str(rec["props"].get("created_at", "")),
                closed_at=str(rec["props"].get("updated_at", "")),
            )
            count += 1

        return count


async def run_archiver_loop(neo4j: Neo4jClient, postgres: PostgresClient) -> None:
    """Run archiver every 24 hours."""
    archiver = Archiver(neo4j, postgres)
    while True:
        try:
            await archiver.run_archive_cycle()
        except Exception as e:
            log.error("archiver_error", error=str(e))
        await asyncio.sleep(86400)  # 24 hours
