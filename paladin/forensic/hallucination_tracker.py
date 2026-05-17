"""
Hallucination Tracker — Verifies LLM claims against actual tool output.
Measures accuracy by comparing evidence_quote from Qwen against raw tool output.
Generates Accuracy Report for hackathon submission.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Optional
import structlog

log = structlog.get_logger(__name__)


class HallucinationTracker:
    """Tracks and verifies accuracy of LLM-generated forensic findings."""

    def __init__(self, neo4j, pg_store=None) -> None:
        self._neo4j = neo4j
        self._pg = pg_store

    async def verify_finding(self, finding_id: str,
                             tool_output: str | dict) -> bool:
        """
        Verify a finding by checking if evidence_quote exists in tool output.
        Returns True if verified, False if unverified (potential hallucination).
        """
        finding = await self._neo4j.get_finding(finding_id)
        if not finding:
            return False

        evidence_quote = finding.get("evidence_quote", "")
        if not evidence_quote:
            await self._neo4j.update_finding_verification(
                finding_id, False, "no_evidence_quote")
            return False

        # Convert tool output to searchable string
        if isinstance(tool_output, dict):
            output_text = json.dumps(tool_output, default=str)
        else:
            output_text = str(tool_output)

        # Exact match check
        if evidence_quote in output_text:
            await self._neo4j.update_finding_verification(
                finding_id, True, "exact_match")
            log.debug("finding_verified", finding_id=finding_id,
                      method="exact_match")
            return True

        # Case-insensitive match
        if evidence_quote.lower() in output_text.lower():
            await self._neo4j.update_finding_verification(
                finding_id, True, "case_insensitive_match")
            return True

        # Partial match — check if key fragments exist
        fragments = evidence_quote.split()
        if len(fragments) >= 3:
            matched = sum(1 for f in fragments if f.lower() in output_text.lower())
            ratio = matched / len(fragments)
            if ratio >= 0.7:
                await self._neo4j.update_finding_verification(
                    finding_id, True, f"semantic_match_{ratio:.0%}")
                return True

        # Not verified
        await self._neo4j.update_finding_verification(
            finding_id, False, "no_match")
        log.warning("finding_unverified", finding_id=finding_id,
                    quote_preview=evidence_quote[:100])
        return False

    async def compute_metrics(self, plan_id: str) -> dict:
        """Compute accuracy metrics for a plan."""
        findings = await self._neo4j.get_findings_for_plan(plan_id)
        total = len(findings)
        if total == 0:
            return {"total": 0, "verified": 0, "unverified": 0,
                    "hallucination_rate": 0.0, "avg_confidence": 0.0}

        verified = sum(1 for f in findings if f.get("verified"))
        unverified = total - verified
        h_rate = unverified / total
        avg_conf = sum(f.get("confidence", 0) for f in findings) / total

        # Confidence-accuracy correlation
        verified_confs = [f.get("confidence", 0) for f in findings if f.get("verified")]
        unverified_confs = [f.get("confidence", 0) for f in findings if not f.get("verified")]
        corr = 0.0
        if verified_confs and unverified_confs:
            avg_v = sum(verified_confs) / len(verified_confs)
            avg_u = sum(unverified_confs) / len(unverified_confs)
            corr = (avg_v - avg_u) / 100.0  # Positive = good calibration

        metrics = {
            "plan_id": plan_id,
            "total_findings": total,
            "verified_findings": verified,
            "unverified_findings": unverified,
            "hallucination_rate": round(h_rate, 4),
            "avg_confidence": round(avg_conf, 2),
            "confidence_accuracy_correlation": round(corr, 4),
        }

        # Persist to PostgreSQL
        if self._pg:
            plan = await self._neo4j.get_plan_with_items(plan_id)
            await self._pg.upsert_accuracy_metrics(
                plan_id=plan_id,
                incident_id=plan.get("incident_id") if plan else None,
                total=total, verified=verified, unverified=unverified,
                hallucination_rate=h_rate, avg_confidence=avg_conf)

        return metrics

    async def generate_accuracy_report(self, plan_id: str) -> dict:
        """Generate full Accuracy Report for hackathon submission."""
        metrics = await self.compute_metrics(plan_id)
        findings = await self._neo4j.get_findings_for_plan(plan_id)

        # Separate verified and unverified
        unverified_list = []
        verified_list = []
        contradictions = []

        for f in findings:
            entry = {
                "finding_id": f.get("finding_id"),
                "description": f.get("description", ""),
                "tool_used": f.get("tool_used", ""),
                "confidence": f.get("confidence", 0),
                "evidence_quote": f.get("evidence_quote", ""),
                "verification_method": f.get("verification_method", ""),
            }
            if f.get("verified"):
                verified_list.append(entry)
            else:
                entry["unverified_reason"] = f.get("verification_method", "no_match")
                unverified_list.append(entry)

        # Get CONTRADICTS edges
        contradicts = await self._neo4j.get_contradictions_for_plan(plan_id)

        # Get execution traces
        execution_traces = []
        if self._pg:
            traces = await self._pg.get_executions_for_plan(plan_id)
            for t in traces:
                execution_traces.append({
                    "execution_id": str(t.get("execution_id", "")),
                    "mcp_function": t.get("mcp_function", ""),
                    "finding_id": t.get("finding_id"),
                    "duration_ms": t.get("duration_ms", 0),
                    "timestamp": str(t.get("timestamp", "")),
                })

        report = {
            "report_type": "Paladin 2.0 Accuracy Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "plan_id": plan_id,
            "metrics": metrics,
            "verified_findings": verified_list,
            "unverified_findings": unverified_list,
            "contradictions": contradicts,
            "execution_traces": execution_traces,
            "summary": {
                "total_findings": metrics["total_findings"],
                "accuracy_rate": f"{(1 - metrics['hallucination_rate']) * 100:.1f}%",
                "hallucination_rate": f"{metrics['hallucination_rate'] * 100:.1f}%",
                "avg_confidence": metrics["avg_confidence"],
                "contradiction_count": len(contradicts),
            },
        }

        log.info("accuracy_report_generated", plan_id=plan_id,
                 accuracy=report["summary"]["accuracy_rate"])
        return report
