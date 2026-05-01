"""
Paladin Auto-Executor — Autonomous Action Enforcement.

When the operator does not respond to a pending incident within
`operator_timeout_seconds` (default 60s), the system auto-executes
the proposed action.

Logic:
1. Every `check_interval` seconds, query Neo4j for stale pending incidents.
2. For each stale incident:
   a. Log a WARNING that operator timeout has been exceeded.
   b. Execute the proposed action (FLAG → mark entity, ISOLATE → lock account).
   c. Update incident status to "auto_executed_timeout".
   d. Broadcast the update to the dashboard via WebSocket.
3. All auto-executed actions are logged with full audit trail.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog

from paladin.config.settings import settings
from paladin.graph.neo4j_client import Neo4jClient

log = structlog.get_logger(__name__)


class AutoExecutor:
    """
    Background service that enforces operator timeout policy.
    If a pending incident goes unanswered for `timeout` seconds,
    the system auto-executes the LLM-proposed action.
    """

    def __init__(
        self,
        neo4j: Neo4jClient,
        broadcast_fn=None,
    ) -> None:
        self._neo4j = neo4j
        self._broadcast = broadcast_fn
        self._timeout = settings.operator_timeout_seconds
        self._interval = settings.auto_execute_check_interval
        self._enabled = settings.auto_execute_enabled
        self._stats = {"auto_executed": 0, "cycles": 0}

    def set_timeout(self, new_timeout: int) -> None:
        self._timeout = new_timeout
        log.info("auto_executor_timeout_changed", new_timeout=new_timeout)

    async def run(self) -> None:
        """Main loop — runs until cancelled."""
        if not self._enabled:
            log.info("auto_executor_disabled")
            return

        log.info(
            "auto_executor_started",
            timeout_s=self._timeout,
            check_interval_s=self._interval,
        )

        while True:
            try:
                await self._check_cycle()
            except Exception as e:
                log.error("auto_executor_error", error=str(e))
            await asyncio.sleep(self._interval)

    async def _check_cycle(self) -> None:
        """One scan cycle: find stale incidents and auto-execute."""
        self._stats["cycles"] += 1

        stale = await self._neo4j.get_stale_pending_incidents(self._timeout)
        if not stale:
            return

        log.warning(
            "stale_incidents_found",
            count=len(stale),
            timeout=self._timeout,
        )

        for incident in stale:
            await self._auto_execute(incident)

    async def _auto_execute(self, incident: dict) -> None:
        """Execute the proposed action autonomously."""
        iid = incident["incident_id"]
        action = incident.get("action_proposed", "NOTIFY")
        severity = incident.get("severity", "MEDIUM")
        involved = incident.get("involved_names", [])
        involved_uids = incident.get("involved_uids", [])

        log.warning(
            "auto_executing",
            incident_id=iid,
            action=action,
            severity=severity,
            reason=f"operator_timeout ({self._timeout}s)",
            involved=involved,
        )

        # ── Execute action based on type ──────────────────────────────────────
        execution_note = await self._perform_action(action, iid, involved_uids, severity)

        # ── Update incident in graph ──────────────────────────────────────────
        await self._neo4j.update_incident(iid, {
            "action_status": "auto_executed_timeout",
            "operator_note": (
                f"[AUTONOMOUS] Operator timeout ({self._timeout}s). "
                f"Action '{action}' auto-executed. {execution_note}"
            ),
        })

        self._stats["auto_executed"] += 1

        log.warning(
            "auto_executed",
            incident_id=iid,
            action=action,
            execution_note=execution_note,
            total_auto_executed=self._stats["auto_executed"],
        )

        # ── Broadcast to dashboard ────────────────────────────────────────────
        if self._broadcast:
            await self._broadcast({
                "type": "auto_executed",
                "incident_id": iid,
                "action": action,
                "severity": severity,
                "reason": f"operator_timeout_{self._timeout}s",
                "involved": involved,
                "execution_note": execution_note,
            })

    async def _perform_action(
        self,
        action: str,
        incident_id: str,
        involved_uids: list[str],
        severity: str,
    ) -> str:
        """
        Simulate or perform the actual security action.
        In production, these would call real infrastructure APIs.
        In dummy mode, we update the graph to reflect the action.
        """
        action = action.upper()

        if action == "NOTIFY":
            # Auto-send notification (already done via LLM summary)
            return "Notification sent to security channel."

        elif action == "FLAG":
            # Mark involved employees as flagged in the graph
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(uid, flagged=True, incident_id=incident_id)
            flagged_list = ", ".join(involved_uids)
            return f"Entities flagged: [{flagged_list}]. New events from them will be prioritized."

        elif action in ("ISOLATE", "BLOCK"):
            # Simulate network isolation / account lockout
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(
                    uid, flagged=True, isolated=True, incident_id=incident_id
                )
            isolated_list = ", ".join(involved_uids)
            return (
                f"ISOLATION ENFORCED for [{isolated_list}]. "
                f"Account locked, network access revoked pending investigation."
            )

        elif action == "BLOCK_IP":
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(uid, flagged=True, incident_id=incident_id)
            return f"FIREWALL UPDATED. Associated IPs for [{', '.join(involved_uids)}] blocked at perimeter."

        elif action == "QUARANTINE_FILE":
            return f"FILE QUARANTINED. File access permanently revoked for [{', '.join(involved_uids)}]."

        elif action == "REVOKE_SESSIONS":
            return f"SESSIONS REVOKED. All active tokens and sessions killed for [{', '.join(involved_uids)}]."

        elif action == "READ":
            return "Additional context gathered. No enforcement action needed."

        else:
            return f"Unknown action '{action}' — defaulted to NOTIFY."
