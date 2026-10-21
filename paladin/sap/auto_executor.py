"""
Paladin Auto-Executor — Autonomous Action Enforcement.

Two operating modes (switchable from the dashboard):

* human_in_loop (default) — a pending incident waits `operator_timeout_seconds`.
  On timeout, actions up to FLAG level are auto-executed. Actions marked
  `requires_confirmation` (ISOLATE-level, protected targets, low-quality LLM
  reasoning) are never auto-executed: they move to `awaiting_operator`.
* autonomous — every verifier-approved action is executed immediately.

The operator can approve an incident at any time; approval executes the
proposed action through the same code path (`execute`).

Every execution re-checks protected accounts, so a protected entity is never
touched even if an upstream check was bypassed.
"""
from __future__ import annotations

import asyncio

import structlog

from paladin.config.settings import settings
from paladin.graph.neo4j_client import Neo4jClient

log = structlog.get_logger(__name__)

MODE_HUMAN_IN_LOOP = "human_in_loop"
MODE_AUTONOMOUS = "autonomous"


class AutoExecutor:
    """
    Background service that enforces operator timeout policy and executes
    approved actions.
    """

    def __init__(
        self,
        neo4j: Neo4jClient,
        broadcast_fn=None,
    ) -> None:
        self._neo4j = neo4j
        self._broadcast = broadcast_fn
        self._mode = MODE_HUMAN_IN_LOOP
        self._timeout = settings.operator_timeout_seconds
        self._interval = settings.auto_execute_check_interval
        self._enabled = settings.auto_execute_enabled
        self._stats = {"auto_executed": 0, "operator_executed": 0,
                       "awaiting_operator": 0, "cycles": 0}

    # ── Mode control ──────────────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def timeout(self) -> int:
        return self._timeout

    def set_mode(self, mode: str) -> None:
        if mode == MODE_AUTONOMOUS:
            self._mode, self._timeout = MODE_AUTONOMOUS, 0
        elif mode == MODE_HUMAN_IN_LOOP:
            self._mode, self._timeout = MODE_HUMAN_IN_LOOP, settings.operator_timeout_seconds
        else:
            raise ValueError(f"Unknown mode: {mode}")
        log.info("auto_executor_mode_changed", mode=self._mode, timeout=self._timeout)

    def set_timeout(self, new_timeout: int) -> None:
        """Backward-compatible setter: 0 means autonomous mode."""
        self.set_mode(MODE_AUTONOMOUS if new_timeout <= 0 else MODE_HUMAN_IN_LOOP)
        if new_timeout > 0:
            self._timeout = new_timeout

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # ── Background loop ───────────────────────────────────────────────────────

    async def run(self) -> None:
        """Main loop — runs until cancelled."""
        if not self._enabled:
            log.info("auto_executor_disabled")
            return

        log.info(
            "auto_executor_started",
            mode=self._mode,
            timeout_s=self._timeout,
            check_interval_s=self._interval,
        )

        while True:
            try:
                await self._check_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("auto_executor_error", error=str(e))
            await asyncio.sleep(self._interval)

    async def _check_cycle(self) -> None:
        """One scan cycle: find stale incidents and auto-execute."""
        self._stats["cycles"] += 1

        stale = await self._neo4j.get_stale_pending_incidents(self._timeout)
        if not stale:
            return

        log.warning("stale_incidents_found", count=len(stale),
                    timeout=self._timeout, mode=self._mode)

        for incident in stale:
            if incident.get("requires_confirmation") and self._mode != MODE_AUTONOMOUS:
                await self._escalate_to_operator(incident)
            else:
                await self.execute(incident, by_operator=None)

    async def _escalate_to_operator(self, incident: dict) -> None:
        """Timeout expired on an action that may not run without explicit approval."""
        iid = incident["incident_id"]
        action = incident.get("action_proposed", "NOTIFY")
        await self._neo4j.update_incident(iid, {
            "action_status": "awaiting_operator",
            "operator_note": (
                f"Operator timeout ({self._timeout}s) expired. Action '{action}' "
                f"requires explicit operator approval and was NOT auto-executed."
            ),
        })
        self._stats["awaiting_operator"] += 1
        log.warning("auto_execute_withheld", incident_id=iid, action=action)
        if self._broadcast:
            await self._broadcast({
                "type": "incident_update",
                "incident_id": iid,
                "status": "awaiting_operator",
                "action": action,
            })

    # ── Execution ─────────────────────────────────────────────────────────────

    async def execute(self, incident: dict, by_operator: str | None = None) -> str:
        """
        Execute the incident's proposed action.
        `by_operator` is the approving operator's name, or None for timeout/autonomous.
        Returns the execution note.
        """
        iid = incident["incident_id"]
        action = (incident.get("action_proposed") or "NOTIFY").upper()
        severity = incident.get("severity", "MEDIUM")
        involved = incident.get("involved_names", [])
        involved_uids = incident.get("involved_uids", [])

        # Defense in depth: never enforce against protected entities.
        protected = [u for u in involved_uids if settings.is_protected(u)]
        targets = [u for u in involved_uids if not settings.is_protected(u)]

        log.warning(
            "executing_action",
            incident_id=iid,
            action=action,
            severity=severity,
            by=by_operator or f"auto ({self._mode}, timeout={self._timeout}s)",
            targets=targets,
            skipped_protected=protected,
        )

        execution_note = await self._perform_action(action, iid, targets)
        if protected:
            execution_note += f" Protected entities skipped: [{', '.join(protected)}]."

        if by_operator:
            status = "executed_by_operator"
            note = f"[OPERATOR {by_operator}] Action '{action}' executed. {execution_note}"
            self._stats["operator_executed"] += 1
        else:
            status = "auto_executed_timeout"
            note = (f"[AUTONOMOUS] {self._mode} mode, timeout {self._timeout}s. "
                    f"Action '{action}' auto-executed. {execution_note}")
            self._stats["auto_executed"] += 1

        await self._neo4j.update_incident(iid, {
            "action_status": status,
            "operator_note": note,
        })

        log.warning("action_executed", incident_id=iid, action=action,
                    status=status, execution_note=execution_note)

        if self._broadcast:
            await self._broadcast({
                "type": "auto_executed" if not by_operator else "incident_update",
                "incident_id": iid,
                "action": action,
                "severity": severity,
                "status": status,
                "reason": f"operator:{by_operator}" if by_operator else f"{self._mode}_timeout_{self._timeout}s",
                "involved": involved,
                "execution_note": execution_note,
            })
        return execution_note

    async def _perform_action(
        self,
        action: str,
        incident_id: str,
        involved_uids: list[str],
    ) -> str:
        """
        Simulate or perform the actual security action.
        In production, these would call real infrastructure APIs.
        In dummy mode, we update the graph to reflect the action.
        """
        uids = ", ".join(involved_uids)

        if action == "NOTIFY":
            return "Notification sent to security channel."

        elif action == "FLAG":
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(uid, flagged=True, incident_id=incident_id)
            return f"Entities flagged: [{uids}]. New events from them will be prioritized."

        elif action in ("ISOLATE", "BLOCK"):
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(
                    uid, flagged=True, isolated=True, incident_id=incident_id
                )
            return (
                f"ISOLATION ENFORCED for [{uids}]. "
                f"Account locked, network access revoked pending investigation."
            )

        elif action == "BLOCK_IP":
            for uid in involved_uids:
                await self._neo4j.update_employee_flag(uid, flagged=True, incident_id=incident_id)
            return f"FIREWALL UPDATED. Associated IPs for [{uids}] blocked at perimeter."

        elif action == "QUARANTINE_FILE":
            return f"FILE QUARANTINED. File access revoked for [{uids}]."

        elif action == "REVOKE_SESSIONS":
            return f"SESSIONS REVOKED. All active tokens and sessions killed for [{uids}]."

        elif action == "READ":
            return "Additional context gathered. No enforcement action needed."

        return f"Unknown action '{action}' — nothing enforced, defaulted to NOTIFY."
