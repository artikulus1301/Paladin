"""
Hallucination Tracker — Verifies LLM claims against actual tool output.
Measures accuracy by comparing evidence_quote from Qwen against raw tool output.
Generates Accuracy Report for hackathon submission.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from typing import Optional
import structlog

log = structlog.get_logger(__name__)

# Quotes shorter than this ("exe", "80") match almost any output and prove nothing
_MIN_QUOTE_LEN = 6
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_PAIR_RE = re.compile(r'"(\w+)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)')
_VALUE_LIST_RE = re.compile(r'"(?:[^"\\]|\\.)*"(?:\s*,\s*"(?:[^"\\]|\\.)*")+')


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

        verified, method = self.match_quote(evidence_quote, tool_output)
        await self._neo4j.update_finding_verification(finding_id, verified, method)
        if verified:
            log.debug("finding_verified", finding_id=finding_id, method=method)
        else:
            log.warning("finding_unverified", finding_id=finding_id, reason=method,
                        quote_preview=evidence_quote[:100])
        return verified

    @classmethod
    def match_quote(cls, evidence_quote: str, tool_output: str | dict | list) -> tuple[bool, str]:
        """
        Decide whether `evidence_quote` is grounded in `tool_output`.
        Returns (verified, method).

        Values are flattened (not json.dumps'ed) so Windows paths are compared
        without JSON backslash escaping. A quote must be a contiguous substring
        of a single value or of the whitespace-normalised output; scattered word
        overlap is NOT accepted as verification.
        """
        # Models sometimes copy JSON with escapes left literal: \"path\" or a
        # backslash-n instead of a newline. Try the quote as-is first, then
        # with those escapes decoded (as-is first keeps Windows paths intact).
        variants = [evidence_quote]
        decoded = (evidence_quote.replace('\\"', '"').replace("\\n", "\n")
                   .replace("\\t", "\t").replace("\\r", ""))
        if decoded != evidence_quote:
            variants.append(decoded)
        result = (False, "no_match")
        for variant in variants:
            result = cls._match_one(variant, tool_output)
            if result[0]:
                return result
        return result

    @classmethod
    def _match_one(cls, evidence_quote: str, tool_output) -> tuple[bool, str]:
        quote = cls._norm(evidence_quote)
        if len(quote) < _MIN_QUOTE_LEN:
            return False, "quote_too_short"

        values = list(cls._flatten(tool_output))

        # A list of exact values ('"a", "b", "c"') picked out of a larger output:
        # every listed value must occur verbatim in some output value.
        if _VALUE_LIST_RE.fullmatch(evidence_quote.strip()):
            items = [i.replace("\\\\", "\\") for i in _QUOTED_RE.findall(evidence_quote)]
            if len(items) >= 2 and all(len(i) >= 3 for i in items) and \
                    all(any(i in v for v in values) for i in items):
                return True, "value_list_match"
        if any(evidence_quote in v for v in values):
            return True, "exact_match"
        if any(quote in cls._norm(v) for v in values):
            return True, "normalized_match"
        # The quote may span several fields of one record (e.g. "pid 6404 svchost.exe")
        if quote in cls._norm(" ".join(values)):
            return True, "normalized_match_multi_field"

        # The model sees tool output as indented JSON and often quotes it in that
        # form ('"hash_value": "13c9…"'), sometimes eliding parts with "...".
        # Every elided fragment must still appear contiguously, in order.
        rendered = tool_output if isinstance(tool_output, str) else \
            json.dumps(tool_output, indent=2, default=str, ensure_ascii=False)
        rendered = cls._norm(rendered.replace("\\\\", "\\"))
        fragments = [cls._norm(f).strip(" ,{}[]")
                     for f in re.split(r"\.\.\.|…", evidence_quote.replace("\\\\", "\\"))]
        fragments = [f for f in fragments if len(f) >= 3]
        if fragments and max(len(f) for f in fragments) >= _MIN_QUOTE_LEN:
            pos = 0
            for frag in fragments:
                pos = rendered.find(frag, pos)
                if pos == -1:
                    break
                pos += len(frag)
            else:
                return True, "json_render_match" if len(fragments) == 1 else "json_render_elided_match"

        # JSON-ish quote with keys reordered or elided: every "key": value pair
        # must exist in some record of the output, and the quote may contain
        # nothing but those pairs and JSON punctuation (no free-text claims).
        pairs = _PAIR_RE.findall(evidence_quote)
        leftover = _PAIR_RE.sub("", evidence_quote)
        leftover = re.sub(r'"\w+"\s*:', "", leftover)  # keys that open nested objects/lists
        leftover = re.sub(r"\.\.\.|…|[\s{}\[\],]", "", leftover)
        if len(pairs) >= 2 and not leftover:
            records = list(cls._records(tool_output))
            if all(cls._pair_in(k, v, records) for k, v in pairs):
                return True, "key_value_match"
        return False, "no_match"

    @classmethod
    def _pair_in(cls, key: str, raw_value: str, records: list[dict]) -> bool:
        value = raw_value[1:-1] if raw_value.startswith('"') else raw_value
        value = cls._norm(value.replace("\\\\", "\\"))
        for rec in records:
            if key in rec:
                actual = rec[key]
                actual = "null" if actual is None else \
                    str(actual).lower() if isinstance(actual, bool) else str(actual)
                if cls._norm(actual) == value:
                    return True
        return False

    @classmethod
    def _records(cls, obj):
        """Every dict nested anywhere in the output."""
        if isinstance(obj, dict):
            yield obj
            for v in obj.values():
                yield from cls._records(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                yield from cls._records(v)

    @staticmethod
    def _norm(text: str) -> str:
        return " ".join(str(text).replace('"', "").replace("'", "").lower().split())

    @classmethod
    def _flatten(cls, obj) -> "list[str]":
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from cls._flatten(v)
        elif isinstance(obj, (list, tuple)):
            for v in obj:
                yield from cls._flatten(v)
        elif obj is not None:
            yield str(obj)

    async def compute_metrics(self, plan_id: str) -> dict:
        """Compute accuracy metrics for a plan."""
        findings = await self._neo4j.get_findings_for_plan(plan_id)
        total = len(findings)
        if total == 0:
            return {"plan_id": plan_id, "total_findings": 0, "verified_findings": 0,
                    "unverified_findings": 0, "simulated_findings": 0,
                    "hallucination_rate": 0.0, "avg_confidence": 0.0,
                    "confidence_accuracy_correlation": 0.0}

        verified = sum(1 for f in findings if f.get("verified"))
        unverified = total - verified
        simulated = sum(1 for f in findings if f.get("simulated"))
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
            # Findings grounded in demo fixtures: their "accuracy" is measured
            # against canned data and says nothing about real tool output.
            "simulated_findings": simulated,
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
                "simulated": bool(f.get("simulated")),
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
                "simulated_findings": metrics["simulated_findings"],
                "data_source": ("demo_fixtures" if metrics["simulated_findings"] == metrics["total_findings"]
                                and metrics["total_findings"] else
                                "mixed" if metrics["simulated_findings"] else "real_tools"),
            },
        }

        log.info("accuracy_report_generated", plan_id=plan_id,
                 accuracy=report["summary"]["accuracy_rate"])
        return report
