"""
SAP Stage 3 — Correlator.
Runs Cypher pattern queries against Neo4j to detect multi-event anomalies.
Accumulates score — single suspicious event doesn't trigger, but correlated ones do.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog

from paladin.config.settings import settings
from paladin.graph.neo4j_client import Neo4jClient

log = structlog.get_logger(__name__)


@dataclass
class CorrelationHit:
    """A single pattern match with its contribution to the total score."""
    pattern_name: str
    score: float
    description: str
    involved_employees: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class CorrelationResult:
    """Aggregated result of all correlation checks for an event."""
    total_score: float
    threshold: float
    triggered: bool
    hits: list[CorrelationHit] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.total_score >= 0.9:
            return "CRITICAL"
        elif self.total_score >= 0.7:
            return "HIGH"
        elif self.total_score >= 0.5:
            return "MEDIUM"
        return "LOW"


class Correlator:
    """
    Runs correlation patterns against the graph after each event.
    Non-binary: accumulates score from multiple weak signals.
    """

    def __init__(self, neo4j: Neo4jClient) -> None:
        self._neo4j = neo4j
        self._threshold = settings.sap_score_threshold
        self._window = settings.sap_correlation_window_minutes

    async def correlate(self, topic: str, event: dict) -> CorrelationResult:
        """Run all correlation patterns relevant to this event type."""
        hits: list[CorrelationHit] = []
        employee_uid = self._extract_employee(topic, event)

        if not employee_uid or employee_uid == "__external__":
            return CorrelationResult(
                total_score=event.get("risk_score", 0),
                threshold=self._threshold,
                triggered=False,
            )

        # Run all pattern checks in parallel
        checks = [
            self._check_clearance_violation(employee_uid, event, topic),
            self._check_off_hours_activity(employee_uid, event),
            self._check_cross_channel(employee_uid),
            self._check_mass_download(employee_uid),
            self._check_external_comms(employee_uid, event, topic),
            self._check_brute_force(employee_uid, event, topic),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, CorrelationHit):
                hits.append(r)
            elif isinstance(r, Exception):
                log.error("correlation_check_error", error=str(r))

        # Base score from the event itself
        base_score = event.get("risk_score", 0)
        # Sum correlation hits
        corr_score = sum(h.score for h in hits)
        total = min(base_score + corr_score, 1.0)

        result = CorrelationResult(
            total_score=round(total, 3),
            threshold=self._threshold,
            triggered=total >= self._threshold,
            hits=hits,
        )

        if result.triggered:
            log.warning(
                "correlation_triggered",
                employee=employee_uid,
                score=total,
                severity=result.severity,
                patterns=[h.pattern_name for h in hits],
            )

        return result

    def _extract_employee(self, topic: str, event: dict) -> str | None:
        """Extract employee UID from event depending on topic."""
        if topic == "logs":
            return event.get("employee_uid")
        elif topic == "emails":
            return event.get("sender_uid")
        elif topic == "messages":
            return event.get("sender_uid")
        elif topic == "calls":
            return event.get("caller_uid")
        return None

    # ── Pattern 1: Clearance violation ────────────────────────────────────────
    async def _check_clearance_violation(
        self, emp_uid: str, event: dict, topic: str
    ) -> CorrelationHit | None:
        if topic != "logs" or "file" not in event.get("event_type", ""):
            return None
        file_path = event.get("file_path")
        if not file_path:
            return None

        violation = await self._neo4j.check_clearance_violation(emp_uid, file_path)
        if violation:
            return CorrelationHit(
                pattern_name="clearance_violation",
                score=0.35,
                description=(
                    f"{violation['employee']} ({violation['role']}) accessed "
                    f"file with clearance {violation['file_clearance']} "
                    f"(employee clearance: {violation['emp_clearance']})"
                ),
                involved_employees=[emp_uid],
                event_ids=[event.get("event_id", "")],
                details=violation,
            )
        return None

    # ── Pattern 2: Off-hours activity ─────────────────────────────────────────
    async def _check_off_hours_activity(
        self, emp_uid: str, event: dict
    ) -> CorrelationHit | None:
        ts = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
        except (ValueError, AttributeError):
            return None

        if 6 <= hour <= 22:
            return None  # Within normal range

        risk = event.get("risk_score", 0)
        if risk < 0.2:
            return None  # Low-risk off-hours activity is OK

        return CorrelationHit(
            pattern_name="off_hours_activity",
            score=0.15,
            description=f"Activity at {hour:02d}:00 with risk_score={risk}",
            involved_employees=[emp_uid],
            event_ids=[event.get("event_id", event.get("message_id", event.get("msg_id", "")))],
        )

    # ── Pattern 3: Cross-channel correlation ──────────────────────────────────
    async def _check_cross_channel(self, emp_uid: str) -> CorrelationHit | None:
        channels = await self._neo4j.get_cross_channel_events(emp_uid, self._window)
        if len(channels) < 2:
            return None

        # Check if multiple channels have elevated risk
        risky_channels = [c for c in channels if c.get("avg_risk", 0) > 0.3]
        if len(risky_channels) < 2:
            return None

        total_events = sum(c.get("cnt", 0) for c in risky_channels)
        max_risk = max(c.get("max_risk", 0) for c in risky_channels)

        return CorrelationHit(
            pattern_name="cross_channel_correlation",
            score=min(0.25 + max_risk * 0.1, 0.4),
            description=(
                f"Suspicious activity across {len(risky_channels)} channels: "
                f"{', '.join(c['channel'] for c in risky_channels)} "
                f"({total_events} events in {self._window}min)"
            ),
            involved_employees=[emp_uid],
        )

    # ── Pattern 4: Mass file download ─────────────────────────────────────────
    async def _check_mass_download(self, emp_uid: str) -> CorrelationHit | None:
        events = await self._neo4j.get_recent_events_for_employee(emp_uid, self._window)
        downloads = [
            e for e in events
            if e.get("event_type") == "LogEvent"
            and "download" in str(e.get("props", {}).get("event_type", "")).lower()
        ]
        if len(downloads) < 3:
            return None

        return CorrelationHit(
            pattern_name="mass_download",
            score=min(0.2 + len(downloads) * 0.05, 0.5),
            description=f"{len(downloads)} file downloads in {self._window} minutes",
            involved_employees=[emp_uid],
            event_ids=[d.get("props", {}).get("event_id", "") for d in downloads],
        )

    # ── Pattern 5: External communication with sensitive content ──────────────
    async def _check_external_comms(
        self, emp_uid: str, event: dict, topic: str
    ) -> CorrelationHit | None:
        if topic not in ("emails", "messages"):
            return None
        if not event.get("is_external", False):
            return None
        risk = event.get("risk_score", 0)
        if risk < 0.3:
            return None

        entities = event.get("entities", [])
        sensitive_terms = [e for e in entities if isinstance(e, str) and len(e) > 3]

        return CorrelationHit(
            pattern_name="external_sensitive_comms",
            score=min(0.2 + risk * 0.2, 0.4),
            description=(
                f"External communication with risk={risk}, "
                f"sensitive terms: {sensitive_terms[:5]}"
            ),
            involved_employees=[emp_uid],
            event_ids=[event.get("message_id", event.get("msg_id", ""))],
        )

    # ── Pattern 6: Brute force detection ──────────────────────────────────────
    async def _check_brute_force(
        self, emp_uid: str, event: dict, topic: str
    ) -> CorrelationHit | None:
        if topic != "logs" or event.get("event_type") != "login_failed":
            return None

        events = await self._neo4j.get_recent_events_for_employee(emp_uid, 15)
        failures = [
            e for e in events
            if e.get("event_type") == "LogEvent"
            and "login_failed" in str(e.get("props", {}).get("event_type", ""))
        ]

        if len(failures) < 5:
            return None

        return CorrelationHit(
            pattern_name="brute_force",
            score=min(0.3 + len(failures) * 0.03, 0.6),
            description=f"{len(failures)} failed login attempts in 15 minutes",
            involved_employees=[emp_uid],
        )
