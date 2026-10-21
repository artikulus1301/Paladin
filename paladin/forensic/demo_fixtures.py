"""
Demo fixtures — canned SIFT tool results for the "nromanoff" demo evidence set
(win7-32-nromanoff-10.3.58.5, Zeus/Zbot infection).

These are NOT produced by running forensic tools. They exist so the demo can
run on machines without Volatility/RegRipper/Hindsight installed in the
sandbox image. They are served only when FORENSIC_DEMO_FIXTURES=true, and
every response built from them is marked `simulated=True` so findings and
accuracy reports never present them as real tool output.
"""
from __future__ import annotations

from pydantic import BaseModel

from paladin.config.settings import settings
from paladin.forensic.mcp_types import (
    BrowserResult, ConnectionList, MFTEntry, MFTResult, ModuleInfo, ModuleList,
    NetworkConnection, PrefetchEntry, PrefetchResult, ProcessInfo, ProcessList,
    RegistryEntry, RegistryResult,
)

_INJECTED_SVCHOST = ProcessInfo(
    pid=6404, name="svchost.exe", ppid=856,
    cmd="C:\\Windows\\system32\\svchost.exe -k netsvcs",
    create_time="2026-06-12T09:45:12Z")

_C2_CONNECTION = NetworkConnection(
    local_addr="10.3.58.5:1044", remote_addr="185.141.63.10:80",
    state="ESTABLISHED", pid=6404, process_name="svchost.exe")


def _process_list(params: dict) -> ProcessList:
    processes = [
        ProcessInfo(pid=4, name="System", ppid=0, cmd="", create_time="2026-06-12T08:00:00Z"),
        ProcessInfo(pid=268, name="smss.exe", ppid=4, cmd="\\SystemRoot\\System32\\smss.exe", create_time="2026-06-12T08:00:01Z"),
        ProcessInfo(pid=368, name="csrss.exe", ppid=268, cmd="", create_time="2026-06-12T08:00:03Z"),
        ProcessInfo(pid=416, name="wininit.exe", ppid=268, cmd="", create_time="2026-06-12T08:00:04Z"),
        ProcessInfo(pid=464, name="services.exe", ppid=416, cmd="", create_time="2026-06-12T08:00:05Z"),
        ProcessInfo(pid=476, name="lsass.exe", ppid=416, cmd="", create_time="2026-06-12T08:00:05Z"),
        ProcessInfo(pid=856, name="svchost.exe", ppid=464, cmd="C:\\Windows\\system32\\svchost.exe -k DcomLaunch", create_time="2026-06-12T08:00:06Z"),
        ProcessInfo(pid=936, name="svchost.exe", ppid=464, cmd="C:\\Windows\\system32\\svchost.exe -k rpcss", create_time="2026-06-12T08:00:06Z"),
        _INJECTED_SVCHOST,
    ]
    return ProcessList(processes=processes, suspicious_processes=[_INJECTED_SVCHOST],
                       total_count=len(processes))


def _network(params: dict) -> ConnectionList:
    connections = [
        NetworkConnection(local_addr="10.3.58.5:135", remote_addr="0.0.0.0:0", state="LISTENING", pid=856, process_name="svchost.exe"),
        NetworkConnection(local_addr="10.3.58.5:445", remote_addr="0.0.0.0:0", state="LISTENING", pid=4, process_name="System"),
        _C2_CONNECTION,
    ]
    return ConnectionList(connections=connections, external_connections=[_C2_CONNECTION],
                          total_count=len(connections))


def _modules(params: dict) -> ModuleList | None:
    if int(params.get("pid", 0)) != 6404:
        return None
    return ModuleList(modules=[
        ModuleInfo(name="svchost.exe", base_address="0x400000", size=49152, path="C:\\Windows\\System32\\svchost.exe"),
        ModuleInfo(name="ntdll.dll", base_address="0x77880000", size=1294336, path="C:\\Windows\\System32\\ntdll.dll"),
        ModuleInfo(name="kernel32.dll", base_address="0x75be0000", size=1114112, path="C:\\Windows\\System32\\kernel32.dll"),
        ModuleInfo(name="unknown_injected_module.dll", base_address="0xc30000", size=262144, path="<injected code / Zeus Trojan>"),
    ])


def _mft(params: dict) -> MFTResult:
    timeline = [
        MFTEntry(timestamp="2026-06-12T09:40:15", action="CREATED", path="C:\\Windows\\System32\\sdra64.exe", size=45056),
        MFTEntry(timestamp="2026-06-12T09:42:00", action="CREATED", path="C:\\Users\\nromanoff\\Downloads\\spinlock.exe", size=120220),
        MFTEntry(timestamp="2026-06-12T09:45:00", action="MODIFIED", path="C:\\Windows\\System32\\drivers\\etc\\hosts", size=824),
    ]
    return MFTResult(entry_count=len(timeline), timeline=timeline, anomalies=[])


def _prefetch(params: dict) -> PrefetchResult:
    return PrefetchResult(executables=[
        PrefetchEntry(name="SPINLOCK.EXE", run_count=2, last_run="2026-06-12T09:42:15"),
        PrefetchEntry(name="SDRA64.EXE", run_count=12, last_run="2026-06-12T09:45:00"),
        PrefetchEntry(name="CMD.EXE", run_count=4, last_run="2026-06-12T09:47:00"),
    ], suspicious_executables=[])


def _registry(params: dict) -> RegistryResult:
    keys = [
        RegistryEntry(key_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", value_name="Userinit",
                      value_data="C:\\Windows\\system32\\userinit.exe,C:\\Windows\\System32\\sdra64.exe"),
        RegistryEntry(key_path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", value_name="ZeusTrojan",
                      value_data="C:\\Windows\\System32\\sdra64.exe"),
    ]
    return RegistryResult(keys=keys, autorun_entries=keys)


def _browser(params: dict) -> BrowserResult:
    return BrowserResult(
        history=[
            {"url": "http://185.141.63.10/blog/index.php", "title": "Corporate Blog", "visit_time": "2026-06-12T09:35:00"},
            {"url": "http://185.141.63.10/payloads/spinlock.exe", "title": "Download Spinlock", "visit_time": "2026-06-12T09:41:00"},
        ],
        downloads=[
            {"url": "http://185.141.63.10/payloads/spinlock.exe", "path": "C:\\Users\\nromanoff\\Downloads\\spinlock.exe",
             "received_bytes": 120220, "total_bytes": 120220, "state": "COMPLETE"},
        ],
        cookies_domains=["185.141.63.10"],
        saved_credentials_count=1,
    )


_FIXTURES = {
    "analyze_process_list": _process_list,
    "scan_network_connections": _network,
    "extract_loaded_modules": _modules,
    "parse_mft": _mft,
    "parse_prefetch": _prefetch,
    "extract_registry_hive": _registry,
    "extract_browser_artifacts": _browser,
}


def lookup(function: str, container_id: str, params: dict) -> BaseModel | None:
    """
    Return a canned result if demo fixtures are enabled and the call targets the
    demo evidence set (matched by fixture key in the container name or path).
    """
    if not settings.forensic_demo_fixtures:
        return None
    builder = _FIXTURES.get(function)
    if builder is None:
        return None
    key = settings.forensic_demo_fixture_key.lower()
    haystack = " ".join([container_id, *(str(v) for v in params.values())]).lower()
    if key not in haystack:
        return None
    return builder(params)
