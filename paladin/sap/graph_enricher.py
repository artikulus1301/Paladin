"""
SAP Stage 2 — Graph Enricher.
Writes events with metadata into Neo4j. Raw data stays on filesystem.
"""
from __future__ import annotations

import asyncio
import structlog

from paladin.graph.neo4j_client import Neo4jClient
from paladin.sap.morpho_parser import SecurityAnalysis

log = structlog.get_logger(__name__)


class GraphEnricher:
    """Takes parsed events and writes them into the Neo4j security graph."""

    def __init__(self, neo4j: Neo4jClient) -> None:
        self._neo4j = neo4j

    async def enrich(self, topic: str, event: dict, analysis: SecurityAnalysis | None = None) -> str:
        """
        Write event to graph, applying NLP enrichment if available.
        Returns the Neo4j node ID of the created node.
        """
        # Override risk_score with NLP-derived score if higher
        if analysis and analysis.text_risk_score > event.get("risk_score", 0):
            event["risk_score"] = analysis.text_risk_score

        if analysis:
            event["entities"] = [t[0] for t in analysis.security_terms_found[:10]]
            event["sentiment"] = analysis.sentiment_label

        try:
            if topic == "logs":
                node_id = await self._neo4j.write_log_event(event)
                # Track file access separately for clearance checks
                if event.get("file_path"):
                    await self._neo4j.write_file_access({
                        "path": event["file_path"],
                        "clearance_level": event.get("file_clearance", 0),
                        "employee_uid": event["employee_uid"],
                        "timestamp": event["timestamp"],
                        "operation": event["event_type"].upper().replace("FILE_", ""),
                    })

            elif topic == "emails":
                node_id = await self._neo4j.write_email(event)

            elif topic == "messages":
                node_id = await self._neo4j.write_message(event)

            elif topic == "calls":
                node_id = await self._neo4j.write_call(event)

            else:
                log.warning("unknown_topic", topic=topic)
                return "unknown"

            log.debug("graph_enriched", topic=topic, node_id=node_id,
                       risk=event.get("risk_score", 0))
            return node_id

        except Exception as e:
            log.error("graph_enrich_error", topic=topic, error=str(e))
            return "error"
