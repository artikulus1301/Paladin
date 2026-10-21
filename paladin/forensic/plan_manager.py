"""
ForensicPlanManager — Orchestrates the full lifecycle of forensic investigations.
Single entry point for creating, executing, self-correcting, and finalizing plans.
Implements Persistent Planning Pattern + Self-Correction Loop.
"""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from typing import Any, Callable
import structlog

from paladin.config.settings import settings
from paladin.forensic.correlation_engine import CorrelationEngine
from paladin.forensic.mcp_types import MCPRequest
from paladin.forensic.prompts import (
    build_planning_prompt, build_execution_prompt,
    build_self_check_prompt, format_plan_for_prompt,
)
from paladin.llm.prompts import extract_json_object

# Evidence file classification for parameter inference
_MEMORY_EXT = (".raw", ".mem", ".vmem", ".dmp", ".lime", ".bin")
_DISK_EXT = (".img", ".dd", ".e01", ".raw", ".vmdk", ".001")
_PCAP_EXT = (".pcap", ".pcapng", ".cap")
_PATH_KEYS = ("path", "image_path", "memory_image", "pcap_path")

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
        # Per-plan runtime state: evidence file list and PIDs flagged by memory analysis
        self._evidence: dict[str, list[str]] = {}
        self._suspicious_pids: dict[str, list[int]] = {}

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
            self._evidence[plan_id] = [l.strip() for l in listing.splitlines() if l.strip()]

        # Build planning prompt
        sys_prompt, user_prompt = build_planning_prompt(
            incident_id=incident_id,
            title=initial_context.get("title", "Unknown"),
            severity=initial_context.get("severity", "MEDIUM"),
            score=initial_context.get("score", 0),
            description=initial_context.get("description", ""),
            evidence_listing=evidence_listing)

        # Ask Qwen for investigation plan
        response = await self._llm.generate(user_prompt, system=sys_prompt, json_mode=True)
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
                "parameters": item.get("parameters") if isinstance(item.get("parameters"), dict) else {},
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

        # Build MCP request: LLM-proposed parameters, with paths that are not in the
        # evidence listing (hallucinated files) replaced by inferred ones.
        # The ForensicActionVerifier still vets everything inside execute().
        try:
            llm_params = json.loads(next_item.get("parameters_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            llm_params = {}
        params = self._build_params(mcp_function, plan_id,
                                    llm_params if isinstance(llm_params, dict) else {})

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

        llm_response = await self._llm.generate(user_prompt, system=sys_prompt, json_mode=True)
        analysis = self._parse_json_response(llm_response)

        # Remember suspicious PIDs so later module analysis targets real processes
        if mcp_function == "analyze_process_list" and mcp_response.result:
            pids = [p.get("pid") for p in mcp_response.result.get("suspicious_processes", [])
                    if isinstance(p, dict) and p.get("pid")]
            if pids:
                self._suspicious_pids[plan_id] = pids

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
            "simulated": mcp_response.simulated,
            "iteration_number": plan.get("iteration_count", 0),
        }
        await self._neo4j.create_finding(finding_data)

        # Verify finding against tool output using HallucinationTracker
        from paladin.forensic.hallucination_tracker import HallucinationTracker
        tracker = HallucinationTracker(self._neo4j, self._pg)
        verified = await tracker.verify_finding(finding_id, mcp_response.result)
        finding_data["verified"] = verified

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
                "verified": verified,
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

        response = await self._llm.generate(user_prompt, system=sys_prompt, json_mode=True)
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

        # Run deterministic correlation before finalizing
        try:
            engine = CorrelationEngine(self._neo4j, self._broadcast)
            await engine.run(plan_id)
        except Exception as e:
            log.error("correlation_engine_failed", error=str(e))

        # Sandbox is destroyed at the end of run_full_investigation,
        # but we also keep this check just in case.
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

        # Synthesize findings using LLM
        summary_text = "Investigation completed. No findings reported."
        if findings:
            findings_text = "\n".join(f"- {f.get('description')} (confidence={f.get('confidence')}%)" for f in findings)
            prompt = (
                "You are an expert digital forensics analyst. Synthesize the following forensic findings "
                "into a concise, professional summary of the incident (3-5 sentences maximum). "
                "Specify key artifacts, files, registry values, or network targets if found. "
                "Make it read like a final forensic report summary.\n\n"
                f"Findings:\n{findings_text}\n\nSummary:"
            )
            try:
                summary_text = await self._llm.generate(prompt)
                summary_text = summary_text.strip()
            except Exception as e:
                log.error("forensic_summary_generation_failed", error=str(e))
                summary_text = "Investigation completed. Findings:\n" + findings_text

        simulated = sum(1 for f in findings if f.get("simulated"))
        if simulated:
            summary_text = (f"[DEMO FIXTURES: {simulated}/{total} findings are based on canned "
                            f"data, not real tool output]\n{summary_text}")

        if incident_id:
            await self._neo4j.update_incident(incident_id, {
                "llm_summary": summary_text
            })
            if self._broadcast:
                await self._broadcast({
                    "type": "incident_update",
                    "incident_id": incident_id,
                })

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
                                     context: dict, evidence_path: str) -> str | None:
        """Run a complete Pipeline Mode investigation end-to-end."""
        plan_id = None
        try:
            # 1. Create sandbox
            await self._sandbox.create_sandbox(incident_id, evidence_path)

            # 2. Create plan
            plan_id = await self.create_plan(incident_id, context)

            # 3. Execute all steps
            max_steps = 20  # Safety limit
            for _ in range(max_steps):
                result = await self.execute_next_item(plan_id)
                if result is None:
                    break  # Plan finalized or all items done
            else:
                await self.finalize_plan(plan_id, "step_limit_reached")
        except Exception as e:
            log.error("forensic_investigation_failed", incident_id=incident_id,
                      plan_id=plan_id, error=str(e))
            if plan_id:
                await self._neo4j.update_plan_status(plan_id, "FAILED",
                                                     completion_reason=str(e)[:300])
            raise
        finally:
            try:
                await self._sandbox.destroy_sandbox(incident_id)
            except Exception as e:
                log.error("sandbox_cleanup_failed", error=str(e))
            if plan_id:
                self._evidence.pop(plan_id, None)
                self._suspicious_pids.pop(plan_id, None)

        return plan_id

    def _build_params(self, function: str, plan_id: str, llm_params: dict) -> dict:
        """Merge LLM-proposed parameters with inferred defaults."""
        inferred = self._infer_params(function, plan_id)
        params = {**inferred, **llm_params}
        # Drop keys the target function doesn't take (e.g. "path" for parse_pcap)
        accepted = self._mcp.get_function_params(function) if self._mcp else None
        if accepted is not None:
            dropped = sorted(set(params) - accepted)
            if dropped:
                log.info("forensic_params_dropped", function=function, dropped=dropped)
            params = {k: v for k, v in params.items() if k in accepted}
        listing = self._evidence.get(plan_id)
        if listing:
            for key in _PATH_KEYS:
                value = params.get(key)
                if (key in inferred and isinstance(value, str) and value not in listing
                        and value.rstrip("/") != "/evidence"):
                    log.info("forensic_param_replaced", function=function, key=key,
                             proposed=value, used=inferred[key])
                    params[key] = inferred[key]
        return params

    def _infer_params(self, function: str, plan_id: str) -> dict:
        """Infer parameters for an MCP function from the evidence actually present."""
        files = self._evidence.get(plan_id, [])

        def pick(exts: tuple[str, ...], default: str, keywords: tuple[str, ...] = ()) -> str:
            for f in files:
                low = f.lower()
                if low.endswith(exts) and (not keywords or any(k in low for k in keywords)):
                    return f
            for f in files:
                if f.lower().endswith(exts):
                    return f
            return default

        memory = pick(_MEMORY_EXT, "/evidence/memory.raw", ("mem", "ram", "vmem"))
        disk = pick(_DISK_EXT, "/evidence/disk.img", ("disk", "img", "dd", "e01"))
        pcap = pick(_PCAP_EXT, "/evidence/capture.pcap")
        fn = function.lower()
        if "module" in fn:
            pids = self._suspicious_pids.get(plan_id) or [4]
            return {"memory_image": memory, "pid": pids[0]}
        if "process" in fn or "network" in fn:
            return {"memory_image": memory}
        if "mft" in fn or "prefetch" in fn or "registry" in fn or "browser" in fn:
            return {"image_path": disk}
        if "pcap" in fn:
            return {"pcap_path": pcap}
        if "hash" in fn:
            return {"path": files[0] if files else "/evidence/", "algorithm": "sha256"}
        return {"path": files[0] if files else "/evidence/"}

    @staticmethod
    def _parse_json_response(response: str) -> dict:
        """Extract JSON from LLM response, handling markdown fences and <think> blocks."""
        data = extract_json_object(response)
        if data is None:
            log.warning("json_parse_failed", response=(response or "")[:200])
            return {"working_plan": response, "todo_items": []}
        return data
