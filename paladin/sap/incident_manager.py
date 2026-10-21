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
from paladin.sap.correlator import CorrelationResult, CorrelationHit, event_employee

log = structlog.get_logger(__name__)

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


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
        # Both sides of a private conversation are part of it (e.g. one shares
        # credentials, the other asked for them and uses them)
        if topic == "messages" and event.get("is_dm"):
            employees.update(u for u in event.get("recipient_uids", []) if u and u != "__external__")

        # Add the triggering event's ID
        eid = event.get("event_id") or event.get("message_id") or event.get("msg_id") or event.get("call_id", "")
        if eid:
            event_ids.add(eid)

        title = self._build_title(correlation)

        # Check for existing open incident to aggregate
        existing_id = await self._neo4j.find_similar_open_incident(title, list(employees))
        if existing_id:
            return await self._aggregate(existing_id, title, topic, event,
                                         correlation, employees, event_ids)

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

        llm_context["forensic_mode"] = self._route_mode(incident_id, correlation.total_score)
        return llm_context

    async def _aggregate(self, existing_id: str, title: str, topic: str, event: dict,
                         correlation: CorrelationResult, employees: set,
                         event_ids: set) -> dict | None:
        """
        Attach new evidence to an open incident. The LLM is re-run only when
        severity escalates — otherwise repeated events would spam the model.
        """
        before = await self._neo4j.get_incident_brief(existing_id) or {}
        await self._neo4j.add_events_to_incident(
            existing_id, list(event_ids), correlation.total_score, correlation.severity
        )
        prev_sev = before.get("severity") or "LOW"
        escalated = _SEVERITY_RANK.get(correlation.severity, 0) > _SEVERITY_RANK.get(prev_sev, 0)
        log.info("incident_aggregated", incident_id=existing_id,
                 new_score=correlation.total_score, escalated=escalated,
                 severity_before=prev_sev, severity_now=correlation.severity)
        if not escalated:
            return None

        incident = {
            "incident_id": existing_id,
            "title": title,
            "severity": correlation.severity,
            "score": max(correlation.total_score, before.get("score") or 0),
            "involved_employees": list(employees),
        }
        llm_context = self._build_llm_context(incident, topic, event, correlation)
        llm_context["escalated_from"] = prev_sev
        # Start a forensic investigation only if one isn't already attached
        llm_context["forensic_mode"] = (
            "tool" if before.get("has_plan")
            else self._route_mode(existing_id, incident["score"])
        )
        log.warning("incident_escalated", incident_id=existing_id,
                    from_severity=prev_sev, to_severity=correlation.severity)
        return llm_context

    def _route_mode(self, incident_id: str, score: float) -> str:
        """Paladin 2.0: Pipeline Mode for high scores, Tool Mode otherwise."""
        if (settings.forensic_enabled and
                self._forensic_plan_manager and
                score >= settings.severity_pipeline_threshold):
            log.info("forensic_pipeline_mode", incident_id=incident_id, score=score,
                     threshold=settings.severity_pipeline_threshold)
            return "pipeline"
        return "tool"

    def _extract_employee(self, topic: str, event: dict) -> str | None:
        return event_employee(topic, event)

    @staticmethod
    def _event_content(topic: str, event: dict) -> str:
        if topic == "emails":
            return f"Subject: {event.get('subject', '')}\n{event.get('body', '')}"
        if topic == "messages":
            return event.get("text", "")
        if topic == "calls":
            return event.get("transcript", "")
        return event.get("details", "")

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
                # Full content of the triggering event; the prompt builder fences
                # and truncates it as untrusted data.
                "details": self._event_content(topic, event),
                "risk_score": event.get("risk_score", 0),
                "timestamp": event.get("timestamp", ""),
            },
            "suggested_action_level": action_levels.get(correlation.severity, "NOTIFY"),
        }
