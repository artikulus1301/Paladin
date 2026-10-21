"""
Multi-Source Correlation Engine — automatic cross-source contradiction detection.
Runs without LLM when findings exist from 2+ evidence sources.
Detects: ghost processes, temporal paradoxes, registry mismatches, invisible connections.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
import structlog

log = structlog.get_logger(__name__)

_ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
# Clock skew between evidence sources that is still considered consistent
_TEMPORAL_TOLERANCE_SECONDS = 120


# ── Contradiction types ───────────────────────────────────────────────────────

CONTRADICTION_TYPES = {
    "ghost_process": "Process in memory but no disk artifacts (rootkit/hollowing indicator)",
    "temporal_paradox": "Timeline inconsistency between sources",
    "registry_mismatch": "Execution evidence without installation record",
    "invisible_connection": "Network connection without DNS query (direct IP/tunneling)",
}


class CorrelationEngine:
    """
    Finds contradictions between findings from different evidence sources.
    Operates deterministically — no LLM involvement.
    """

    def __init__(self, neo4j, broadcast_fn=None) -> None:
        self._neo4j = neo4j
        self._broadcast = broadcast_fn

    async def run(self, plan_id: str) -> list[dict]:
        """
        Run all correlation checks on findings for a plan.
        Returns list of detected contradictions.
        """
        findings = await self._neo4j.get_findings_for_plan(plan_id)
        if len(findings) < 2:
            return []

        # Group findings by source type
        by_source = {}
        for f in findings:
            src = self._classify_source(f.get("tool_used", ""))
            by_source.setdefault(src, []).append(f)

        # Need at least 2 different source types
        if len(by_source) < 2:
            return []

        contradictions = []

        # Run each detector
        detectors = [
            self._detect_ghost_processes,
            self._detect_temporal_paradoxes,
            self._detect_registry_mismatches,
            self._detect_invisible_connections,
        ]

        for detector in detectors:
            try:
                results = await detector(by_source, findings)
                contradictions.extend(results)
            except Exception as e:
                log.error("correlation_detector_error",
                          detector=detector.__name__, error=str(e))

        # Persist contradictions
        for c in contradictions:
            await self._neo4j.add_contradicts_edge(
                c["finding_a"], c["finding_b"],
                c["description"], c["contradiction_type"])

            # Follow-up for the analyst. The engine runs while the plan is being
            # finalized, so the agent will not execute it: NEEDS_REVIEW, not PENDING.
            await self._neo4j.create_todo_item({
                "item_id": f"TODO-{uuid.uuid4().hex[:8]}",
                "plan_id": plan_id,
                "order_index": 900 + len(contradictions),
                "description": f"Investigate discrepancy: {c['description'][:200]}",
                "status": "NEEDS_REVIEW",
                "recheck_reason": c["description"],
                "iteration_added": -1,  # Added by correlation engine
            })

            if self._broadcast:
                await self._broadcast({
                    "type": "contradiction_detected",
                    "finding_id_a": c["finding_a"],
                    "finding_id_b": c["finding_b"],
                    "contradiction_type": c["contradiction_type"],
                })

        if contradictions:
            log.warning("correlations_found", plan_id=plan_id,
                        count=len(contradictions),
                        types=[c["contradiction_type"] for c in contradictions])

        return contradictions

    async def _detect_ghost_processes(self, by_source: dict,
                                      findings: list[dict]) -> list[dict]:
        """Process in memory but absent from disk findings."""
        results = []
        memory_findings = by_source.get("memory", [])
        disk_findings = by_source.get("disk", [])
        if not memory_findings or not disk_findings:
            return results

        # Extract process names from memory findings
        memory_procs = set()
        mem_finding_map = {}
        for f in memory_findings:
            desc = f.get("description", "").lower()
            # Extract process names mentioned in findings
            for proc_name in self._extract_process_names(desc):
                memory_procs.add(proc_name)
                mem_finding_map[proc_name] = f.get("finding_id", "")

        # Check if processes appear in disk findings
        disk_text = " ".join(f.get("description", "").lower() for f in disk_findings)

        for proc in memory_procs:
            if proc not in disk_text and proc not in ("system", "idle", "smss.exe"):
                results.append({
                    "finding_a": mem_finding_map.get(proc, ""),
                    "finding_b": disk_findings[0].get("finding_id", ""),
                    "contradiction_type": "ghost_process",
                    "description": (f"Process '{proc}' found in memory analysis "
                                    f"but absent from disk artifacts. "
                                    f"Possible rootkit or process hollowing."),
                })
        return results

    async def _detect_temporal_paradoxes(self, by_source: dict,
                                         findings: list[dict]) -> list[dict]:
        """
        A file that existed on disk BEFORE the network transfer that delivered it
        (disk timestamp earlier than the earliest network timestamp for the same
        entity) — a timestomping / alternative-delivery indicator.

        An entity merely appearing in several sources is corroboration, not a
        contradiction, and is NOT reported. Findings without timestamps can't
        produce a paradox.
        """
        results = []
        per_entity: dict[str, dict[str, list[tuple[datetime, dict]]]] = {}
        for f in findings:
            src = self._classify_source(f.get("tool_used", ""))
            if src not in ("disk", "network"):
                continue
            stamps = self._extract_timestamps(f.get("description", ""))
            if not stamps:
                continue
            for entity in self._extract_executables(f.get("description", "")):
                bucket = per_entity.setdefault(entity.lower(), {"disk": [], "network": []})
                bucket[src].extend((ts, f) for ts in stamps)

        for entity, by_src in per_entity.items():
            if not by_src["disk"] or not by_src["network"]:
                continue
            disk_ts, disk_f = min(by_src["disk"], key=lambda x: x[0])
            net_ts, net_f = min(by_src["network"], key=lambda x: x[0])
            if (net_ts - disk_ts).total_seconds() > _TEMPORAL_TOLERANCE_SECONDS:
                results.append({
                    "finding_a": disk_f.get("finding_id", ""),
                    "finding_b": net_f.get("finding_id", ""),
                    "contradiction_type": "temporal_paradox",
                    "description": (f"'{entity}' is on disk at {disk_ts.isoformat()} but its "
                                    f"network delivery is first seen at {net_ts.isoformat()} — "
                                    f"possible timestomping or a different delivery path."),
                })
        return results[:5]  # Cap to avoid noise

    @staticmethod
    def _extract_timestamps(text: str) -> list[datetime]:
        out = []
        for m in _ISO_TS_RE.findall(text):
            try:
                ts = datetime.fromisoformat(m.replace(" ", "T").replace("Z", "+00:00"))
            except ValueError:
                continue
            out.append(ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc))
        return out

    async def _detect_registry_mismatches(self, by_source: dict,
                                           findings: list[dict]) -> list[dict]:
        """Execution evidence (prefetch) without installation (registry)."""
        results = []
        prefetch_findings = [f for f in findings
                             if "prefetch" in f.get("tool_used", "").lower()]
        registry_findings = [f for f in findings
                             if "registry" in f.get("tool_used", "").lower()]

        if not prefetch_findings or not registry_findings:
            return results

        registry_text = " ".join(f.get("description", "").lower()
                                 for f in registry_findings)

        for pf in prefetch_findings:
            execs = self._extract_executables(pf.get("description", ""))
            for exe in execs:
                if exe.lower() not in registry_text:
                    results.append({
                        "finding_a": pf.get("finding_id", ""),
                        "finding_b": registry_findings[0].get("finding_id", ""),
                        "contradiction_type": "registry_mismatch",
                        "description": (f"'{exe}' executed (prefetch evidence) but "
                                        f"no installation record in registry. "
                                        f"Possible portable/dropped malware."),
                    })
        return results[:5]

    async def _detect_invisible_connections(self, by_source: dict,
                                             findings: list[dict]) -> list[dict]:
        """Network connections in memory but no DNS in PCAP."""
        results = []
        memory_net = [f for f in findings
                      if "network" in f.get("tool_used", "").lower() or
                      "netscan" in f.get("tool_used", "").lower()]
        pcap_findings = [f for f in findings
                         if "pcap" in f.get("tool_used", "").lower()]

        if not memory_net or not pcap_findings:
            return results

        pcap_text = " ".join(f.get("description", "").lower()
                             for f in pcap_findings)

        for mf in memory_net:
            ips = self._extract_ips(mf.get("description", ""))
            for ip in ips:
                if ip not in pcap_text and not self._is_private_ip(ip):
                    results.append({
                        "finding_a": mf.get("finding_id", ""),
                        "finding_b": pcap_findings[0].get("finding_id", ""),
                        "contradiction_type": "invisible_connection",
                        "description": (f"Connection to {ip} found in memory "
                                        f"but no corresponding DNS query in PCAP. "
                                        f"Direct IP connection or DNS tunneling."),
                    })
        return results[:5]

    # ── Entity extraction helpers ─────────────────────────────────────────────

    @staticmethod
    def _classify_source(tool: str) -> str:
        tool = tool.lower()
        if any(k in tool for k in ("process", "network", "netscan", "module", "pslist")):
            return "memory"
        if any(k in tool for k in ("mft", "prefetch", "registry", "file", "hash", "string")):
            return "disk"
        if any(k in tool for k in ("pcap", "browser")):
            return "network"
        return "other"

    @staticmethod
    def _extract_process_names(text: str) -> list[str]:
        import re
        return re.findall(r'\b[\w-]+\.exe\b', text, re.IGNORECASE)

    @staticmethod
    def _extract_executables(text: str) -> list[str]:
        import re
        return re.findall(r'\b[\w-]+\.exe\b', text, re.IGNORECASE)

    @staticmethod
    def _extract_entities(text: str) -> list[str]:
        import re
        entities = set()
        entities.update(re.findall(r'\b[\w-]+\.exe\b', text, re.IGNORECASE))
        entities.update(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text))
        return list(entities)[:20]

    @staticmethod
    def _extract_ips(text: str) -> list[str]:
        import re
        return re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return True
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                return 16 <= int(ip.split(".")[1]) <= 31
            except (IndexError, ValueError):
                pass
        return False
