"""
Action Registry — defines allowed actions, their levels, and validation rules.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class ActionLevel(IntEnum):
    READ = 0       # Autonomous, no notification
    NOTIFY = 1     # Autonomous, logged
    FLAG = 2       # Auto-executed after operator timeout (Human-in-the-Loop mode)
    ISOLATE = 3    # Never auto-executed on timeout; needs explicit approval or Autonomous mode


@dataclass
class ActionDefinition:
    name: str
    level: ActionLevel
    description: str
    # True → in Human-in-the-Loop mode the action waits for an explicit operator
    # approval instead of being auto-executed when the operator timeout expires.
    requires_confirmation: bool
    timeout_minutes: Optional[int] = None  # For ISOLATE/BLOCK level


# ── Allowed actions registry ──────────────────────────────────────────────────

ACTIONS: dict[str, ActionDefinition] = {
    "READ": ActionDefinition(
        name="READ",
        level=ActionLevel.READ,
        description="Read additional data from the graph for context enrichment",
        requires_confirmation=False,
    ),
    "NOTIFY": ActionDefinition(
        name="NOTIFY",
        level=ActionLevel.NOTIFY,
        description="Send notification to the security operator",
        requires_confirmation=False,
    ),
    "FLAG": ActionDefinition(
        name="FLAG",
        level=ActionLevel.FLAG,
        description="Mark entity as suspicious, pause new events from it until operator review",
        requires_confirmation=False,
    ),
    "ISOLATE": ActionDefinition(
        name="ISOLATE",
        level=ActionLevel.ISOLATE,
        description="Network isolation of device or account lockout",
        requires_confirmation=True,
        timeout_minutes=30,
    ),
    "BLOCK": ActionDefinition(
        name="BLOCK",
        level=ActionLevel.ISOLATE,
        description="Block user account pending investigation",
        requires_confirmation=True,
        timeout_minutes=60,
    ),
    "BLOCK_IP": ActionDefinition(
        name="BLOCK_IP",
        level=ActionLevel.ISOLATE,
        description="Block specific IP address at the firewall level",
        requires_confirmation=True,
    ),
    "QUARANTINE_FILE": ActionDefinition(
        name="QUARANTINE_FILE",
        level=ActionLevel.ISOLATE,
        description="Isolate or lock a specific file involved in exfiltration",
        requires_confirmation=True,
    ),
    "REVOKE_SESSIONS": ActionDefinition(
        name="REVOKE_SESSIONS",
        level=ActionLevel.FLAG,
        description="Terminate active sessions for a user",
        requires_confirmation=False,
    ),
}

# ── Severity → max allowed action level ───────────────────────────────────────

SEVERITY_ACTION_LIMITS: dict[str, ActionLevel] = {
    "LOW": ActionLevel.NOTIFY,
    "MEDIUM": ActionLevel.FLAG,
    "HIGH": ActionLevel.ISOLATE,
    "CRITICAL": ActionLevel.ISOLATE,
}


def get_action(name: str) -> ActionDefinition | None:
    return ACTIONS.get(name.upper())


def get_max_action_level(severity: str) -> ActionLevel:
    return SEVERITY_ACTION_LIMITS.get(severity.upper(), ActionLevel.NOTIFY)
