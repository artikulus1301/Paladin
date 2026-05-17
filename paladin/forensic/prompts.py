"""
Forensic LLM Prompts — Planning, Execution, and Self-Correction.
"""
from __future__ import annotations
import json


# ── Planning Prompt ───────────────────────────────────────────────────────────

FORENSIC_PLANNING_SYSTEM = """You are a Senior Digital Forensic Analyst (GCFA, GCFE certified).
You receive security incident data and create structured investigation plans.

Available SIFT MCP tools:
- get_file_metadata(path) — file metadata (stat)
- compute_hash(path, algorithm) — MD5/SHA1/SHA256
- extract_strings(path, min_length) — strings + IOC patterns
- analyze_process_list(memory_image) — Volatility pslist
- scan_network_connections(memory_image) — Volatility netscan
- extract_loaded_modules(memory_image, pid) — Volatility dlllist
- parse_mft(image_path, output_format) — MFT timeline
- parse_prefetch(image_path) — Windows prefetch
- extract_registry_hive(image_path, hive) — Registry (SYSTEM/SOFTWARE/SAM/NTUSER)
- parse_pcap(pcap_path) — PCAP network analysis
- extract_browser_artifacts(image_path, browser) — Browser forensics

All tools are READ-ONLY. Evidence cannot be modified.
All paths must start with /evidence/.

Respond ONLY with valid JSON in this exact format:
{{
  "working_plan": "Your reasoning about the incident nature and investigation strategy",
  "todo_items": [
    {{
      "order": 1,
      "description": "What to do and why",
      "mcp_function": "function_name",
      "parameters": {{"key": "value"}},
      "expected_finding": "What you expect to discover"
    }}
  ]
}}"""

FORENSIC_PLANNING_USER = """
=== SECURITY INCIDENT FOR INVESTIGATION ===
Incident ID: {incident_id}
Title: {title}
Severity: {severity} (score: {score})
Description: {description}

Available evidence files in /evidence/:
{evidence_listing}

Create a forensic investigation plan with 3-8 steps.
Focus on establishing timeline, identifying artifacts, and correlating findings.
"""


# ── Execution Prompt ──────────────────────────────────────────────────────────

FORENSIC_EXECUTION_SYSTEM = """You are executing step {step_number} of a forensic investigation plan.
Review the tool output and produce a structured finding.

Respond ONLY with valid JSON:
{{
  "finding_description": "What was discovered (be specific, cite data)",
  "confidence": 85,
  "evidence_quote": "Exact string/value from the tool output that supports this finding",
  "next_action": "CONTINUE | REPLAN | ESCALATE"
}}

Rules:
- confidence: 0-100 integer. 90+ = strong evidence. Below 50 = weak/circumstantial.
- evidence_quote: MUST be an exact substring from the tool output. Not paraphrased.
- CONTINUE: proceed to next plan step
- REPLAN: findings suggest plan needs revision (add/remove steps)
- ESCALATE: critical finding requiring immediate operator attention"""

FORENSIC_EXECUTION_USER = """
=== CURRENT INVESTIGATION STATE ===
{plan_context}

=== CURRENT STEP ===
Step {step_number}: {step_description}
Tool: {tool_name}

=== TOOL OUTPUT ===
{tool_output}

Analyze this output and produce your finding.
"""


# ── Self-Check Prompt ─────────────────────────────────────────────────────────

SELF_CHECK_SYSTEM = """You are a forensic evidence reviewer checking for contradictions.
Compare the new finding against all previous findings from this investigation.

Respond ONLY with valid JSON:
{{
  "contradiction_detected": false,
  "contradicted_finding_id": null,
  "contradiction_description": null,
  "rerun_required": false,
  "rerun_step_description": null,
  "confidence_in_new_finding": 85,
  "reasoning": "Brief explanation of your assessment"
}}

A contradiction exists when:
- Two findings make mutually exclusive claims about the same entity
- Timeline data conflicts between sources (file created after network activity with its hash)
- A process exists in memory but has no disk artifacts (potential rootkit)
- Registry shows no installation but prefetch shows execution
- Network connection in memory but no DNS query in PCAP"""

SELF_CHECK_USER = """
=== NEW FINDING ===
ID: {new_finding_id}
Description: {new_finding_description}
Source tool: {source_tool}
Confidence: {confidence}
Evidence: {evidence_quote}

=== PREVIOUS FINDINGS ===
{previous_findings}

Check for contradictions between the new finding and any previous findings.
"""


# ── Builder functions ─────────────────────────────────────────────────────────

def build_planning_prompt(incident_id: str, title: str, severity: str,
                          score: float, description: str,
                          evidence_listing: str) -> tuple[str, str]:
    """Returns (system_prompt, user_prompt) for plan creation."""
    user = FORENSIC_PLANNING_USER.format(
        incident_id=incident_id, title=title, severity=severity,
        score=score, description=description,
        evidence_listing=evidence_listing or "No evidence listing available")
    return FORENSIC_PLANNING_SYSTEM, user


def build_execution_prompt(plan_context: str, step_number: int,
                           step_description: str, tool_name: str,
                           tool_output: str) -> tuple[str, str]:
    """Returns (system_prompt, user_prompt) for step execution."""
    # Truncate tool output to prevent context overflow
    max_output = 4000
    if len(tool_output) > max_output:
        tool_output = tool_output[:max_output] + f"\n... [truncated, {len(tool_output)} chars total]"

    system = FORENSIC_EXECUTION_SYSTEM.format(step_number=step_number)
    user = FORENSIC_EXECUTION_USER.format(
        plan_context=plan_context, step_number=step_number,
        step_description=step_description, tool_name=tool_name,
        tool_output=tool_output)
    return system, user


def build_self_check_prompt(new_finding_id: str, new_description: str,
                            source_tool: str, confidence: int,
                            evidence_quote: str,
                            previous_findings: list[dict]) -> tuple[str, str]:
    """Returns (system_prompt, user_prompt) for self-check."""
    prev_text = ""
    for f in previous_findings:
        prev_text += (f"  [{f.get('finding_id', '?')}] "
                      f"{f.get('description', '')} "
                      f"(tool: {f.get('tool_used', '?')}, "
                      f"confidence: {f.get('confidence', '?')})\n")
    if not prev_text:
        prev_text = "  No previous findings yet."

    user = SELF_CHECK_USER.format(
        new_finding_id=new_finding_id, new_finding_description=new_description,
        source_tool=source_tool, confidence=confidence,
        evidence_quote=evidence_quote or "N/A",
        previous_findings=prev_text)
    return SELF_CHECK_SYSTEM, user


def format_plan_for_prompt(plan: dict) -> str:
    """Format a ForensicPlan + items into a readable context string for LLM."""
    lines = [
        f"Plan ID: {plan.get('plan_id', '?')}",
        f"Status: {plan.get('status', '?')}",
        f"Iteration: {plan.get('iteration_count', 0)}/{plan.get('max_iterations', 5)}",
        f"Strategy: {plan.get('working_plan', 'N/A')[:500]}",
        "", "TODO Items:"
    ]
    for item in plan.get("todo_items", []):
        status_icon = {"DONE": "✅", "IN_PROGRESS": "🔄", "PENDING": "⬜",
                       "BLOCKED": "🚫", "RECHECK": "🔁"}.get(item.get("status", ""), "❓")
        lines.append(f"  {status_icon} [{item.get('order_index', '?')}] "
                      f"{item.get('description', '')} "
                      f"({item.get('status', '?')})")
        if item.get("result_summary"):
            lines.append(f"      Result: {item['result_summary'][:200]}")

    findings = plan.get("findings", [])
    if findings:
        lines.append("")
        lines.append(f"Findings ({len(findings)}):")
        for f in findings:
            v = "✓" if f.get("verified") else "✗"
            lines.append(f"  [{f.get('finding_id', '?')}] {v} "
                          f"{f.get('description', '')[:150]} "
                          f"(confidence: {f.get('confidence', '?')})")
    return "\n".join(lines)
