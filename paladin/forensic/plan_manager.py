"""
ForensicPlanManager — Orchestrates the full lifecycle of forensic investigations.
Single entry point for creating, executing, self-correcting, and finalizing plans.
Implements Persistent Planning Pattern + Self-Correction Loop.
"""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from typing import Optional
import structlog

from paladin.config.settings import settings
from paladin.forensic.mcp_types import MCPRequest
from paladin.forensic.prompts import (
    build_planning_prompt, build_execution_prompt,
    build_self_check_prompt, format_plan_for_prompt,
)

log = structlog.get_logger(__name__)


class ForensicPlanManager:
    """
    Manages ForensicPlan lifecycle: create → execute → self-correct → finalize.
    Each plan is persisted in Neo4j with full iteration history.
    """

    def __init__(self, neo4j, llm, mcp_server, sandbox, pg_store=None,
                 broadcast_fn=None) -> None:
        self._neo4j = neo4j
        self._llm = llm
        self._mcp = mcp_server
        self._sandbox = sandbox
        self._pg = pg_store
        self._broadcast = broadcast_fn

    async def create_plan(self, incident_id: str,
                          initial_context: dict) -> str:
        """Create a new ForensicPlan by asking Qwen to plan the investigation."""
        plan_id = f"FP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Get evidence listing from sandbox if available
        evidence_listing = ""
        container = self._sandbox.get_container_name(incident_id)
        if container:
            listing, _ = await self._sandbox.exec_in_sandbox(
                container, ["find", "/evidence", "-maxdepth", "3", "-type", "f"])
            evidence_listing = listing[:2000]

        # Build planning prompt
        sys_prompt, user_prompt = build_planning_prompt(
            incident_id=incident_id,
            title=initial_context.get("title", "Unknown"),
            severity=initial_context.get("severity", "MEDIUM"),
            score=initial_context.get("score", 0),
            description=initial_context.get("description", ""),
            evidence_listing=evidence_listing)

        # Ask Qwen for investigation plan
        from paladin.llm.ollama_client import OllamaClient
        response = await self._llm.generate(user_prompt, system=sys_prompt)
        plan_data = self._parse_json_response(response)

        # Create plan node in Neo4j
        await self._neo4j.create_forensic_plan({
            "plan_id": plan_id,
            "incident_id": incident_id,
            "status": "PLANNED",
            "working_plan": plan_data.get("working_plan", ""),
            "iteration_count": 0,
            "max_iterations": settings.max_forensic_iterations,
        })

        # Create TODO items
        for item in plan_data.get("todo_items", []):
            item_id = f"TODO-{uuid.uuid4().hex[:8]}"
            await self._neo4j.create_todo_item({
                "item_id": item_id,
                "plan_id": plan_id,
                "order_index": item.get("order", 0),
                "description": item.get("description", ""),
                "status": "PENDING",
                "mcp_function": item.get("mcp_function", ""),
                "expected_finding": item.get("expected_finding", ""),
                "iteration_added": 0,
            })

        # Link plan to incident
        await self._neo4j.link_plan_to_incident(incident_id, plan_id)

        # Broadcast event
        if self._broadcast:
            await self._broadcast({
                "type": "forensic_plan_created",
                "plan_id": plan_id,
                "incident_id": incident_id,
                "todo_count": len(plan_data.get("todo_items", [])),
            })

        log.info("forensic_plan_created", plan_id=plan_id,
                 incident_id=incident_id,
                 todo_count=len(plan_data.get("todo_items", [])))
        return plan_id

    async def execute_next_item(self, plan_id: str) -> dict | None:
        """Execute the next PENDING or RECHECK item in the plan."""
        plan = await self._neo4j.get_plan_with_items(plan_id)
        if not plan:
            log.error("plan_not_found", plan_id=plan_id)
            return None

        # Check iteration limit
        if await self.check_iteration_limit(plan_id):
            return None

        # Find next item to execute
        items = plan.get("todo_items", [])
        next_item = None
        for item in sorted(items, key=lambda x: x.get("order_index", 999)):
            if item.get("status") in ("PENDING", "RECHECK"):
                next_item = item
                break

        if not next_item:
            # All items done — finalize
            await self.finalize_plan(plan_id, "all_items_completed")
            return None

        item_id = next_item["item_id"]
        incident_id = plan.get("incident_id", "")

        # Update status to IN_PROGRESS
        await self._neo4j.update_todo_status(item_id, "IN_PROGRESS")
        if self._broadcast:
            await self._broadcast({
                "type": "todo_item_updated",
                "item_id": item_id,
                "old_status": next_item.get("status"),
                "new_status": "IN_PROGRESS",
            })

        # Update plan status
        await self._neo4j.update_plan_status(plan_id, "IN_PROGRESS")

        # Execute MCP function
        mcp_function = next_item.get("mcp_function", "")
        container = self._sandbox.get_container_name(incident_id)
        if not container:
            await self._neo4j.update_todo_status(
                item_id, "BLOCKED", blocked_reason="No sandbox container")
            return None

        # Build MCP request from plan item
        params = next_item.get("parameters", {})
        if not params and mcp_function:
            # Infer basic params from description
            params = self._infer_params(mcp_function, plan)

        request = MCPRequest(
            function=mcp_function,
            parameters=params,
            incident_id=incident_id,
            plan_id=plan_id)

        mcp_response = await self._mcp.execute(request, container)

        if not mcp_response.success:
            await self._neo4j.update_todo_status(
                item_id, "BLOCKED",
                blocked_reason=mcp_response.error or "MCP execution failed")
            return {"status": "blocked", "error": mcp_response.error}

        # Ask Qwen to analyze the result
        plan_context = format_plan_for_prompt(plan)
        tool_output = json.dumps(mcp_response.result, indent=2, default=str)[:4000]

        sys_prompt, user_prompt = build_execution_prompt(
            plan_context=plan_context,
            step_number=next_item.get("order_index", 0),
            step_description=next_item.get("description", ""),
            tool_name=mcp_function,
            tool_output=tool_output)

        llm_response = await self._llm.generate(user_prompt, system=sys_prompt)
        analysis = self._parse_json_response(llm_response)

        # Create Finding
        finding_id = f"F-{uuid.uuid4().hex[:8]}"
        finding_data = {
            "finding_id": finding_id,
            "plan_id": plan_id,
            "todo_item_id": item_id,
            "description": analysis.get("finding_description", ""),
            "evidence_source": mcp_function,
            "tool_used": mcp_function,
            "tool_output_hash": mcp_response.raw_output_hash,
            "confidence": analysis.get("confidence", 50),
            "verified": False,
            "evidence_quote": analysis.get("evidence_quote", ""),
            "iteration_number": plan.get("iteration_count", 0),
        }
        await self._neo4j.create_finding(finding_data)

        # Update TODO as DONE
        await self._neo4j.update_todo_status(
            item_id, "DONE",
            result_summary=analysis.get("finding_description", "")[:500])

        # Broadcast finding
        if self._broadcast:
            await self._broadcast({
                "type": "finding_added",
                "finding_id": finding_id,
                "description": analysis.get("finding_description", "")[:200],
                "confidence": analysis.get("confidence", 50),
                "verified": False,
            })

        # ── Self-Correction Loop ──────────────────────────────────────
        await self._self_check(plan_id, finding_id, finding_data, plan)

        # Handle next_action
        next_action = analysis.get("next_action", "CONTINUE")
        if next_action == "ESCALATE" and self._broadcast:
            await self._broadcast({
                "type": "approval_required",
                "action_description": f"ESCALATION: {analysis.get('finding_description', '')[:200]}",
                "timeout_seconds": 60,
            })

        log.info("forensic_step_completed", plan_id=plan_id,
                 item_id=item_id, finding_id=finding_id,
                 confidence=analysis.get("confidence"),
                 next_action=next_action)

        return {
            "status": "completed",
            "finding_id": finding_id,
            "next_action": next_action,
        }

    async def _self_check(self, plan_id: str, new_finding_id: str,
                          finding_data: dict, plan: dict) -> None:
        """Self-Correction Loop: check new finding against previous ones."""
        previous_findings = await self._neo4j.get_findings_for_plan(plan_id)
        # Exclude the current finding
        prev = [f for f in previous_findings if f.get("finding_id") != new_finding_id]
        if not prev:
            return

        sys_prompt, user_prompt = build_self_check_prompt(
            new_finding_id=new_finding_id,
            new_description=finding_data.get("description", ""),
            source_tool=finding_data.get("tool_used", ""),
            confidence=finding_data.get("confidence", 50),
            evidence_quote=finding_data.get("evidence_quote", ""),
            previous_findings=prev)

        response = await self._llm.generate(user_prompt, system=sys_prompt)
        check = self._parse_json_response(response)

        if not check.get("contradiction_detected"):
            return

        contradicted_id = check.get("contradicted_finding_id")
        log.warning("self_check_contradiction",
                    plan_id=plan_id, new=new_finding_id,
                    contradicted=contradicted_id,
                    description=check.get("contradiction_description"))

        # Create CONTRADICTS edge in Neo4j
        if contradicted_id:
            await self._neo4j.add_contradicts_edge(
                new_finding_id, contradicted_id,
                check.get("contradiction_description", ""),
                "self_check")

        # Broadcast contradiction
        if self._broadcast:
            await self._broadcast({
                "type": "contradiction_detected",
                "finding_id_a": new_finding_id,
                "finding_id_b": contradicted_id,
                "contradiction_type": "self_check",
            })

        if check.get("rerun_required"):
            if not await self.check_iteration_limit(plan_id):
                # Add RECHECK item
                recheck_id = f"TODO-{uuid.uuid4().hex[:8]}"
                await self._neo4j.create_todo_item({
                    "item_id": recheck_id,
                    "plan_id": plan_id,
                    "order_index": 999,  # Append at end
                    "description": check.get("rerun_step_description",
                                             "Recheck contradicted findings"),
                    "status": "RECHECK",
                    "recheck_reason": check.get("contradiction_description", ""),
                    "iteration_added": (plan.get("iteration_count", 0) + 1),
                })
                # Increment iteration
                await self._neo4j.increment_plan_iteration(plan_id)
                # Save version history
                await self._neo4j.create_plan_version(plan_id)

                if self._broadcast:
                    plan_data = await self._neo4j.get_plan_with_items(plan_id)
                    await self._broadcast({
                        "type": "self_correction_triggered",
                        "plan_id": plan_id,
                        "iteration_count": plan_data.get("iteration_count", 0),
                        "max_iterations": plan_data.get("max_iterations", 5),
                        "recheck_reason": check.get("contradiction_description", ""),
                    })

    async def finalize_plan(self, plan_id: str, reason: str) -> None:
        """Finalize investigation: set status, destroy sandbox, trigger report."""
        plan = await self._neo4j.get_plan_with_items(plan_id)
        if not plan:
            return

        items = plan.get("todo_items", [])
        has_gaps = any(i.get("status") in ("BLOCKED", "RECHECK", "PENDING") for i in items)
        status = "COMPLETED_WITH_GAPS" if has_gaps else "COMPLETED"

        await self._neo4j.update_plan_status(plan_id, status, completion_reason=reason)

        # Destroy sandbox
        incident_id = plan.get("incident_id", "")
        if incident_id:
            try:
                await self._sandbox.destroy_sandbox(incident_id)
            except Exception as e:
                log.warning("sandbox_destroy_failed", error=str(e))

        findings = await self._neo4j.get_findings_for_plan(plan_id)
        verified = sum(1 for f in findings if f.get("verified"))
        total = len(findings)
        h_rate = (total - verified) / total if total > 0 else 0.0

        if self._broadcast:
            await self._broadcast({
                "type": "plan_completed",
                "plan_id": plan_id,
                "status": status,
                "total_findings": total,
                "hallucination_rate": round(h_rate, 3),
            })

        log.info("forensic_plan_finalized", plan_id=plan_id,
                 status=status, reason=reason, findings=total)

    async def check_iteration_limit(self, plan_id: str) -> bool:
        """If iteration_count >= max_iterations → COMPLETED_WITH_GAPS."""
        plan = await self._neo4j.get_plan_with_items(plan_id)
        if not plan:
            return True
        if plan.get("iteration_count", 0) >= plan.get("max_iterations", 5):
            await self.finalize_plan(plan_id, "iteration_limit_reached")
            return True
        return False

    async def run_full_investigation(self, incident_id: str,
                                     context: dict, evidence_path: str) -> str:
        """Run a complete Pipeline Mode investigation end-to-end."""
        # 1. Create sandbox
        container = await self._sandbox.create_sandbox(
            incident_id, evidence_path)

        # 2. Create plan
        plan_id = await self.create_plan(incident_id, context)

        # 3. Execute all steps
        max_steps = 20  # Safety limit
        for _ in range(max_steps):
            result = await self.execute_next_item(plan_id)
            if result is None:
                break  # Plan finalized or all items done

        return plan_id

    def _infer_params(self, function: str, plan: dict) -> dict:
        """Infer basic parameters for an MCP function from plan context."""
        base = {"path": "/evidence/", "image_path": "/evidence/disk.img",
                "memory_image": "/evidence/memory.raw"}
        fn = function.lower()
        if "process" in fn or "network" in fn or "module" in fn:
            return {"memory_image": base["memory_image"]}
        if "mft" in fn or "prefetch" in fn or "registry" in fn:
            return {"image_path": base["image_path"]}
        if "pcap" in fn:
            return {"pcap_path": "/evidence/capture.pcap"}
        if "hash" in fn:
            return {"path": base["path"], "algorithm": "sha256"}
        return {"path": base["path"]}

    @staticmethod
    def _parse_json_response(response: str) -> dict:
        """Extract JSON from LLM response, handling markdown fences."""
        text = response.strip()
        # Strip markdown code fences
        if "```json" in text:
            text = text.split("```json", 1)[1]
            text = text.split("```", 1)[0]
        elif "```" in text:
            text = text.split("```", 1)[1]
            text = text.split("```", 1)[0]
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            log.warning("json_parse_failed", response=text[:200])
            return {"working_plan": text, "todo_items": []}
