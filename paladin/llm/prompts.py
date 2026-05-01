"""
LLM Module — Security-specific prompts for Paladin.
Generates human-readable incident notifications and proposed actions.
"""
from __future__ import annotations

import json


SYSTEM_PROMPT = """You are Paladin Security Analyst — an AI security officer for a corporate environment.
Your role is to analyze security incidents and produce clear, actionable notifications for the human operator.

Rules:
1. Be concise and factual. No speculation beyond what the data supports.
2. Structure every response with: SUMMARY, TIMELINE, RISK ASSESSMENT, RECOMMENDED ACTION.
3. For RECOMMENDED ACTION, choose exactly ONE from the allowed action list provided.
4. Always name the action by its exact ID (e.g., "NOTIFY", "FLAG", "ISOLATE").
5. Explain WHY you chose that action level in 1-2 sentences.
6. Respond in the same language as the incident description (Russian or English).
"""

INCIDENT_PROMPT_TEMPLATE = """
=== SECURITY INCIDENT ===

Incident ID: {incident_id}
Title: {title}
Severity: {severity}
Accumulated Score: {score}
Source Channel: {source_channel}

=== INVOLVED ENTITIES ===
Employees: {employees}

=== EVENT TIMELINE ===
{timeline}

=== TRIGGERING EVENT ===
Type: {event_type}
Details: {event_details}
Risk Score: {event_risk}
Timestamp: {event_timestamp}

=== ALLOWED ACTIONS ===
- READ: Read additional data from the graph for context. Autonomous, no notification.
- NOTIFY: Send notification to the operator. Autonomous, logged.
- FLAG: Mark entity as suspicious, block new events. Autonomous.
- REVOKE_SESSIONS: Terminate active sessions for a user without locking the account entirely. Autonomous.
- ISOLATE: Network isolation of device or full account lockout. Autonomous.
- BLOCK_IP: Block specific IP address at the firewall level. Autonomous.
- QUARANTINE_FILE: Isolate or lock a specific file involved in exfiltration. Autonomous.

Based on the severity level ({severity}) and the accumulated evidence, the suggested action level is: {suggested_action}

Analyze this incident and produce a human-readable notification with your recommended action.
"""


def build_incident_prompt(context: dict) -> str:
    """Build the LLM prompt from incident context dict."""
    timeline_lines = []
    for i, entry in enumerate(context.get("timeline", []), 1):
        timeline_lines.append(
            f"{i}. [{entry['pattern']}] score={entry['score']} — {entry['description']}"
        )

    event = context.get("event_summary", {})

    return INCIDENT_PROMPT_TEMPLATE.format(
        incident_id=context.get("incident_id", "?"),
        title=context.get("title", "Unknown"),
        severity=context.get("severity", "MEDIUM"),
        score=context.get("score", 0),
        source_channel=context.get("source_channel", "?"),
        employees=", ".join(context.get("involved_employees", [])),
        timeline="\n".join(timeline_lines) or "No timeline data",
        event_type=event.get("type", "?"),
        event_details=event.get("details", "")[:500],
        event_risk=event.get("risk_score", 0),
        event_timestamp=event.get("timestamp", "?"),
        suggested_action=context.get("suggested_action_level", "NOTIFY"),
    )


def parse_llm_response(response: str) -> dict:
    """
    Extract action name and summary from LLM response.
    Returns dict with 'action', 'summary' keys.
    """
    action = "NOTIFY"  # default fallback
    for keyword in ["ISOLATE", "BLOCK_IP", "QUARANTINE_FILE", "REVOKE_SESSIONS", "BLOCK", "FLAG", "NOTIFY", "READ"]:
        if keyword in response.upper():
            action = keyword
            break

    # Take the full response as summary
    summary = response.strip()
    if len(summary) > 2000:
        summary = summary[:2000] + "..."

    return {
        "action": action,
        "summary": summary,
    }
