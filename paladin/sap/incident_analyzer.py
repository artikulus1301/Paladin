"""
SAP Stage 5 — Incident Analyzer.
LLM analysis + action verification for a single incident context.

1. Ask the LLM for a summary and an action (JSON mode).
2. Verify the action (registry, severity cap, protected targets, quality).
3. On rejection, retry once with the verifier's feedback.
4. Persist the outcome:
   approved          → action_status "pending" (AutoExecutor / operator take over)
   protected target  → "awaiting_operator" (a human decides)
   still rejected    → NOTIFY fallback
"""
from __future__ import annotations

from typing import Awaitable, Callable

import structlog

from paladin.llm.prompts import SYSTEM_PROMPT, build_incident_prompt, parse_llm_response
from paladin.verifier.verifier import ActionVerifier

log = structlog.get_logger(__name__)

MAX_ATTEMPTS = 2  # initial answer + one retry with verifier feedback


class IncidentAnalyzer:
    def __init__(self, neo4j, llm, verifier: ActionVerifier | None = None,
                 broadcast_fn: Callable[[dict], Awaitable[None]] | None = None) -> None:
        self._neo4j = neo4j
        self._llm = llm
        self._verifier = verifier or ActionVerifier()
        self._broadcast = broadcast_fn

    async def analyze(self, llm_context: dict) -> dict:
        """Analyze one incident context. Returns the persisted outcome."""
        iid = llm_context["incident_id"]
        try:
            feedback = None
            for attempt in range(MAX_ATTEMPTS):
                prompt = build_incident_prompt(llm_context, feedback=feedback)
                llm_response = await self._llm.generate(prompt, system=SYSTEM_PROMPT, json_mode=True)
                parsed = parse_llm_response(llm_response)
                verification = self._verifier.verify_action(
                    proposed_action=parsed["action"],
                    severity=llm_context["severity"],
                    target_entities=llm_context["involved_employees"],
                    llm_response=llm_response,
                )
                check = verification.action_check
                # A protected target won't change on retry — that's for a human to decide
                if check.approved or verification.reason == "protected_entity":
                    break
                feedback = check.reason
                log.warning("action_rejected", incident_id=iid, attempt=attempt + 1,
                            action=parsed["action"], reason=check.reason)

            summary = parsed["summary"]
            if not parsed["parsed"]:
                summary = "[LLM output was not valid JSON — action defaulted to NOTIFY]\n\n" + summary
            if llm_context.get("escalated_from"):
                summary = (f"[ESCALATED {llm_context['escalated_from']} → "
                           f"{llm_context['severity']}]\n\n" + summary)

            if check.approved:
                action, action_status = check.action, "pending"
                requires_confirmation = check.requires_confirmation
            elif verification.reason == "protected_entity":
                action, action_status, requires_confirmation = parsed["action"], "awaiting_operator", True
                summary += f"\n\n[VERIFIER: {check.reason} — operator decision required]"
            else:
                action, action_status, requires_confirmation = "NOTIFY", "auto_executed", False
                summary += f"\n\n[VERIFIER REJECTED: {check.reason}] Fallback action: NOTIFY"

            outcome = {
                "llm_summary": summary,
                "action_proposed": action,
                "action_status": action_status,
                "requires_confirmation": requires_confirmation,
                "forensic_mode": llm_context.get("forensic_mode", "tool"),
            }
            await self._neo4j.update_incident(iid, outcome)
            log.info("incident_processed", id=iid, action=action,
                     action_status=action_status,
                     requires_confirmation=requires_confirmation,
                     forensic_mode=llm_context.get("forensic_mode"),
                     attempts=attempt + 1, quality=verification.reason)

            if self._broadcast:
                await self._broadcast({
                    "incident_id": iid,
                    "title": llm_context["title"],
                    "severity": llm_context["severity"],
                    "score": llm_context["score"],
                    "action": action,
                    "action_status": action_status,
                    "forensic_mode": llm_context.get("forensic_mode", "tool"),
                })
            return dict(outcome, attempts=attempt + 1, verifier_reason=verification.reason)

        except Exception as e:
            log.error("llm_pipeline_error", error=str(e), incident=iid)
            outcome = {
                "llm_summary": f"LLM processing error: {e}",
                "action_proposed": "NOTIFY",
                "action_status": "error",
            }
            await self._neo4j.update_incident(iid, outcome)
            return outcome
