"""
SAP Stage 4 — Incident Manager.
Creates Incident nodes when correlation score exceeds threshold.
Passes context to LLM module for human-readable notification.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog

from paladin.config.settings import settings
from paladin.graph.neo4j_client import Neo4jClient
from paladin.sap.correlator import CorrelationResult, CorrelationHit

log = structlog.get_logger(__name__)


class IncidentManager:
    """
    Creates and manages Incident lifecycle.
    When correlation triggers, creates Incident node and prepares
    structured context for LLM.

    Paladin 2.0: Routes to Pipeline Mode (ForensicPlan + Sandbox) when
    severity_score >= threshold, otherwise stays in Tool Mode.
    """

    def __init__(self, neo4j: Neo4jClient) -> None:
        self._neo4j = neo4j
        self._forensic_plan_manager = None  # Set by main.py after init

    def set_forensic_plan_manager(self, fpm) -> None:
        """Inject ForensicPlanManager (avoids circular import)."""
        self._forensic_plan_manager = fpm

    async def maybe_create_incident(
        self, topic: str, event: dict, correlation: CorrelationResult
    ) -> dict | None:
        """
        If correlation triggered, create incident and return context dict
        for the LLM module. Otherwise returns None.
        """
        if not correlation.triggered:
            return None

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Collect involved employees from all hits
        employees = set()
        event_ids = set()
        for hit in correlation.hits:
            employees.update(hit.involved_employees)
            event_ids.update(hit.event_ids)

        # Add event's own employee
        emp = self._extract_employee(topic, event)
        if emp and emp != "__external__":
            employees.add(emp)

        # Add the triggering event's ID
        eid = event.get("event_id") or event.get("message_id") or event.get("msg_id") or event.get("call_id", "")
        if eid:
            event_ids.add(eid)

        title = self._build_title(correlation)

        # Check for existing open incident to aggregate
        existing_id = await self._neo4j.find_similar_open_incident(title, list(employees))
        if existing_id:
            log.info("incident_aggregated", incident_id=existing_id, new_score=correlation.total_score)
            await self._neo4j.add_events_to_incident(
                existing_id, list(event_ids), correlation.total_score, correlation.severity
            )
            # Notify the dashboard of the updated severity without creating a whole new LLM request
            return None # Do not trigger LLM again to prevent spam

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

        description = self._build_description(topic, event, correlation)

        incident = {
            "incident_id": incident_id,
            "title": title,
            "description": description,
            "severity": correlation.severity,
            "score": correlation.total_score,
            "involved_employees": list(employees),
            "trigger_event_ids": list(event_ids),
        }

        await self._neo4j.create_incident(incident)
        log.warning(
            "incident_created",
            incident_id=incident_id,
            severity=correlation.severity,
            score=correlation.total_score,
            patterns=[h.pattern_name for h in correlation.hits],
        )

        # Build LLM context
        llm_context = self._build_llm_context(incident, topic, event, correlation)

        # ── Paladin 2.0: Mode routing based on severity score ─────────
        if (settings.forensic_enabled and
                self._forensic_plan_manager and
                correlation.total_score >= settings.severity_pipeline_threshold):
            llm_context["forensic_mode"] = "pipeline"
            log.info("forensic_pipeline_mode",
                     incident_id=incident_id,
                     score=correlation.total_score,
                     threshold=settings.severity_pipeline_threshold)
        else:
            llm_context["forensic_mode"] = "tool"

        return llm_context

    def _extract_employee(self, topic: str, event: dict) -> str | None:
        if topic == "logs":
            return event.get("employee_uid")
        elif topic in ("emails", "messages"):
            return event.get("sender_uid")
        elif topic == "calls":
            return event.get("caller_uid")
        return None

    def _build_title(self, correlation: CorrelationResult) -> str:
        """Generate incident title from the most significant pattern."""
        if not correlation.hits:
            return "Anomalous activity detected"

        top_hit = max(correlation.hits, key=lambda h: h.score)
        titles = {
            "clearance_violation": "Clearance Level Violation",
            "off_hours_activity": "Suspicious Off-Hours Activity",
            "cross_channel_correlation": "Cross-Channel Anomaly",
            "mass_download": "Mass File Download Detected",
            "external_sensitive_comms": "Sensitive Data in External Communication",
            "brute_force": "Brute Force Attack Detected",
        }
        return titles.get(top_hit.pattern_name, f"Security Alert: {top_hit.pattern_name}")

    def _build_description(
        self, topic: str, event: dict, correlation: CorrelationResult
    ) -> str:
        lines = [f"Source channel: {topic}"]
        lines.append(f"Total score: {correlation.total_score}")
        lines.append(f"Severity: {correlation.severity}")
        lines.append("")
        lines.append("Triggered patterns:")
        for hit in correlation.hits:
            lines.append(f"  - {hit.pattern_name} (score={hit.score}): {hit.description}")
        return "\n".join(lines)

    def _build_llm_context(
        self,
        incident: dict,
        topic: str,
        event: dict,
        correlation: CorrelationResult,
    ) -> dict:
        """Structure context for the LLM module."""
        timeline = []
        for hit in correlation.hits:
            timeline.append({
                "pattern": hit.pattern_name,
                "score": hit.score,
                "description": hit.description,
                "involved": hit.involved_employees,
                "event_ids": hit.event_ids,
            })

        # Map severity to suggested action level
        action_levels = {
            "CRITICAL": "ISOLATE",
            "HIGH": "FLAG",
            "MEDIUM": "NOTIFY",
            "LOW": "READ",
        }

        return {
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "severity": incident["severity"],
            "score": incident["score"],
            "source_channel": topic,
            "involved_employees": incident["involved_employees"],
            "timeline": timeline,
            "event_summary": {
                "type": event.get("event_type", topic),
                "details": event.get("details", event.get("subject", event.get("text", "")[:200])),
                "risk_score": event.get("risk_score", 0),
                "timestamp": event.get("timestamp", ""),
            },
            "suggested_action_level": action_levels.get(correlation.severity, "NOTIFY"),
        }
