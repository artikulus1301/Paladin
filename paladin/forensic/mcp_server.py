"""
SIFT MCP Server — Security boundary #2.
Exposes SIFT tools as typed, validated functions.
Agent interacts ONLY with this API — never directly with shell.
No destructive functions exist. Parameters validated. Output parsed & hashed.
"""
from __future__ import annotations
import hashlib, json, re, time
from datetime import datetime, timezone
from typing import Optional
import structlog

from paladin.forensic.action_verifier import ForensicActionVerifier, VerifierCategory
from paladin.forensic.sandbox_manager import SandboxManager
from paladin.forensic.mcp_types import (
    FileMetadata, HashResult, StringsList, SuspiciousPattern,
    ProcessInfo, ProcessList, NetworkConnection, ConnectionList,
    MFTEntry, MFTAnomaly, MFTResult, PrefetchEntry, PrefetchResult,
    RegistryEntry, RegistryResult, PCAPResult, DNSQuery, HTTPRequest,
    BrowserResult, MCPRequest, MCPResponse, HashAlgorithm, ModuleInfo, ModuleList,
)

log = structlog.get_logger(__name__)


class SIFTMCPServer:
    """MCP Server exposing SIFT forensic tools as typed functions."""

    def __init__(self, sandbox: SandboxManager, verifier: ForensicActionVerifier,
                 pg_store=None) -> None:
        self._sandbox = sandbox
        self._verifier = verifier
        self._pg_store = pg_store
        self._registry: dict[str, callable] = {
            "get_file_metadata": self.get_file_metadata,
            "compute_hash": self.compute_hash,
            "extract_strings": self.extract_strings,
            "analyze_process_list": self.analyze_process_list,
            "scan_network_connections": self.scan_network_connections,
            "extract_loaded_modules": self.extract_loaded_modules,
            "parse_mft": self.parse_mft,
            "parse_prefetch": self.parse_prefetch,
            "extract_registry_hive": self.extract_registry_hive,
            "parse_pcap": self.parse_pcap,
            "extract_browser_artifacts": self.extract_browser_artifacts,
        }

    async def execute(self, request: MCPRequest, container_id: str) -> MCPResponse:
        """Execute a typed MCP function: validate → verify → execute → parse → hash."""
        start = time.monotonic()
        handler = self._registry.get(request.function)
        if not handler:
            return MCPResponse(function=request.function, success=False,
                               error=f"Unknown function: '{request.function}'. "
                                     f"Available: {list(self._registry.keys())}")

        verdict = self._verifier.verify(
            request.function, request.parameters,
            request.incident_id, request.plan_id)
        if verdict.category == VerifierCategory.FORBIDDEN:
            return MCPResponse(function=request.function, success=False,
                               error=f"BLOCKED: {verdict.reason}")

        try:
            result = await handler(container_id, **request.parameters)
            duration_ms = int((time.monotonic() - start) * 1000)
            result_dict = result.model_dump() if hasattr(result, "model_dump") else result
            raw_hash = hashlib.sha256(
                json.dumps(result_dict, sort_keys=True, default=str).encode()
            ).hexdigest()

            if self._pg_store:
                await self._pg_store.log_tool_execution(
                    incident_id=request.incident_id, plan_id=request.plan_id,
                    mcp_function=request.function, parameters=request.parameters,
                    raw_output_hash=raw_hash, duration_ms=duration_ms,
                    output_summary=self._summarize(result_dict))

            return MCPResponse(function=request.function, success=True,
                               result=result_dict, execution_time_ms=duration_ms,
                               raw_output_hash=raw_hash)
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            log.error("mcp_exec_error", function=request.function, error=str(e))
            return MCPResponse(function=request.function, success=False,
                               error=str(e), execution_time_ms=duration_ms)

    # ── File Artifacts ────────────────────────────────────────────────────────

    async def get_file_metadata(self, container_id: str, path: str) -> FileMetadata:
        out, rc = await self._sandbox.exec_in_sandbox(
            container_id, ["stat", "--format", "%n|%s|%W|%Y|%X|%A", path])
        if rc != 0: raise RuntimeError(f"stat failed: {out}")
        parts = out.strip().split("|")
        mime_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["file", "--mime-type", "-b", path])
        return FileMetadata(
            name=parts[0].split("/")[-1], size=int(parts[1]),
            created=self._epoch_iso(parts[2]), modified=self._epoch_iso(parts[3]),
            accessed=self._epoch_iso(parts[4]), permissions=parts[5],
            mime_type=mime_out.strip(), path=path)

    async def compute_hash(self, container_id: str, path: str,
                           algorithm: str = "sha256") -> HashResult:
        algo = HashAlgorithm(algorithm.lower())
        cmd = {"md5": "md5sum", "sha1": "sha1sum", "sha256": "sha256sum"}[algo.value]
        out, rc = await self._sandbox.exec_in_sandbox(container_id, [cmd, path])
        if rc != 0: raise RuntimeError(f"Hash failed: {out}")
        size_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["stat", "--format", "%s", path])
        return HashResult(path=path, algorithm=algorithm,
                          hash_value=out.strip().split()[0],
                          file_size=int(size_out.strip()))

    async def extract_strings(self, container_id: str, path: str,
                              min_length: int = 4) -> StringsList:
        out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["strings", "-n", str(min_length), path], timeout=120)
        strings = out.strip().split("\n") if out.strip() else []
        suspicious = self._detect_ioc_patterns(strings)
        return StringsList(strings=strings[:500], total_count=len(strings),
                           suspicious_patterns=suspicious)

    # ── Memory Artifacts ──────────────────────────────────────────────────────

    async def analyze_process_list(self, container_id: str,
                                   memory_image: str) -> ProcessList:
        await self._sandbox.exec_in_sandbox(container_id,
            ["vol3", "-f", memory_image, "windows.pslist.PsList",
             "--output", "json", "--output-file", "/cases/pslist.json"], timeout=300)
        json_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["cat", "/cases/pslist.json"])
        processes, suspicious = [], []
        try:
            for row in json.loads(json_out):
                p = ProcessInfo(pid=row.get("PID", 0), name=row.get("ImageFileName", ""),
                                ppid=row.get("PPID", 0), cmd=row.get("CommandLine", ""),
                                create_time=row.get("CreateTime", ""))
                processes.append(p)
                if p.name.lower() in self._SUSPICIOUS_PROCS:
                    suspicious.append(p)
        except json.JSONDecodeError:
            pass
        return ProcessList(processes=processes, suspicious_processes=suspicious,
                           total_count=len(processes))

    async def scan_network_connections(self, container_id: str,
                                       memory_image: str) -> ConnectionList:
        await self._sandbox.exec_in_sandbox(container_id,
            ["vol3", "-f", memory_image, "windows.netscan.NetScan",
             "--output", "json", "--output-file", "/cases/netscan.json"], timeout=300)
        json_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["cat", "/cases/netscan.json"])
        connections, external = [], []
        try:
            for row in json.loads(json_out):
                c = NetworkConnection(
                    local_addr=f"{row.get('LocalAddr','?')}:{row.get('LocalPort','?')}",
                    remote_addr=f"{row.get('ForeignAddr','?')}:{row.get('ForeignPort','?')}",
                    state=row.get("State", "UNKNOWN"), pid=row.get("PID", 0),
                    process_name=row.get("Owner", ""))
                connections.append(c)
                rip = row.get("ForeignAddr", "")
                if rip and not self._is_local(rip):
                    external.append(c)
        except json.JSONDecodeError:
            pass
        return ConnectionList(connections=connections, external_connections=external,
                              total_count=len(connections))

    async def extract_loaded_modules(self, container_id: str,
                                     memory_image: str, pid: int) -> ModuleList:
        await self._sandbox.exec_in_sandbox(container_id,
            ["vol3", "-f", memory_image, "windows.dlllist.DllList",
             "--pid", str(pid), "--output", "json",
             "--output-file", "/cases/dlllist.json"], timeout=300)
        json_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["cat", "/cases/dlllist.json"])
        modules = []
        try:
            for row in json.loads(json_out):
                modules.append(ModuleInfo(
                    name=row.get("Name", ""), base_address=str(row.get("Base", "")),
                    size=row.get("Size", 0), path=row.get("Path", "")))
        except json.JSONDecodeError:
            pass
        return ModuleList(modules=modules)

    # ── Disk Artifacts ────────────────────────────────────────────────────────

    async def parse_mft(self, container_id: str, image_path: str,
                        output_format: str = "timeline") -> MFTResult:
        await self._sandbox.exec_in_sandbox(container_id,
            ["analyzeMFT.py", "-f", image_path, "-o", "/cases/mft.csv", "--csv"],
            timeout=600)
        csv_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["cat", "/cases/mft.csv"])
        timeline, anomalies = [], []
        for line in csv_out.strip().split("\n")[1:]:
            parts = line.split(",")
            if len(parts) >= 4:
                e = MFTEntry(timestamp=parts[0].strip('"'), action=parts[1].strip('"'),
                             path=parts[2].strip('"'),
                             size=int(parts[3].strip('"')) if parts[3].strip('"').isdigit() else 0)
                timeline.append(e)
        return MFTResult(entry_count=len(timeline), timeline=timeline[:1000],
                         anomalies=anomalies)

    async def parse_prefetch(self, container_id: str, image_path: str) -> PrefetchResult:
        out, _ = await self._sandbox.exec_in_sandbox(container_id,
            ["prefetch_parser", "--json", image_path], timeout=120)
        execs, suspicious = [], []
        for line in out.strip().split("\n"):
            try:
                d = json.loads(line)
                e = PrefetchEntry(name=d.get("name", ""), run_count=d.get("run_count", 0),
                                  last_run=d.get("last_run"))
                execs.append(e)
            except json.JSONDecodeError:
                continue
        return PrefetchResult(executables=execs, suspicious_executables=suspicious)

    async def extract_registry_hive(self, container_id: str, image_path: str,
                                    hive: str = "SYSTEM") -> RegistryResult:
        out, _ = await self._sandbox.exec_in_sandbox(container_id,
            ["regripper", "-r", image_path, "-f", hive.lower()], timeout=180)
        keys, autorun = [], []
        current_key = ""
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("\\") or line.startswith("HKEY"):
                current_key = line
            elif "=" in line:
                p = line.split("=", 1)
                e = RegistryEntry(key_path=current_key, value_name=p[0].strip(),
                                  value_data=p[1].strip() if len(p) > 1 else "")
                keys.append(e)
                if any(kw in current_key for kw in ["Run", "Services", "Startup"]):
                    autorun.append(e)
        return RegistryResult(keys=keys[:500], autorun_entries=autorun)

    async def parse_pcap(self, container_id: str, pcap_path: str) -> PCAPResult:
        dns_out, _ = await self._sandbox.exec_in_sandbox(container_id,
            ["tshark", "-r", pcap_path, "-Y", "dns.flags.response==0",
             "-T", "fields", "-e", "dns.qry.name"], timeout=120)
        http_out, _ = await self._sandbox.exec_in_sandbox(container_id,
            ["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "fields",
             "-e", "http.request.method", "-e", "http.host",
             "-e", "http.request.uri"], timeout=120)
        dns_queries = [DNSQuery(query=l.strip()) for l in dns_out.split("\n") if l.strip()]
        http_reqs = []
        for line in http_out.strip().split("\n"):
            p = line.split("\t")
            if len(p) >= 3:
                http_reqs.append(HTTPRequest(method=p[0], host=p[1], url=p[2]))
        return PCAPResult(dns_queries=dns_queries, http_requests=http_reqs)

    async def extract_browser_artifacts(self, container_id: str,
                                        image_path: str, browser: str = "chrome") -> BrowserResult:
        await self._sandbox.exec_in_sandbox(container_id,
            ["python3", "-m", "hindsight", "-i", image_path,
             "-o", "/cases/browser", "-f", "json"], timeout=180)
        json_out, _ = await self._sandbox.exec_in_sandbox(
            container_id, ["cat", "/cases/browser.json"])
        try:
            d = json.loads(json_out)
            return BrowserResult(history=d.get("history", [])[:200],
                                 downloads=d.get("downloads", [])[:100],
                                 cookies_domains=d.get("cookies_domains", [])[:100],
                                 saved_credentials_count=d.get("saved_credentials_count", 0))
        except json.JSONDecodeError:
            return BrowserResult()

    # ── Helpers ───────────────────────────────────────────────────────────────

    _SUSPICIOUS_PROCS = frozenset([
        "cmd.exe", "powershell.exe", "psexec.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe",
        "wscript.exe", "cscript.exe", "schtasks.exe"])

    @staticmethod
    def _epoch_iso(s: str) -> str | None:
        try:
            ts = int(s)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts > 0 else None
        except (ValueError, OSError):
            return None

    @staticmethod
    def _is_local(ip: str) -> bool:
        return (not ip or ip in ("0.0.0.0", "::", "*", "::1") or
                ip.startswith("127.") or ip.startswith("10.") or
                ip.startswith("192.168.") or ip.startswith("172.16."))

    @staticmethod
    def _detect_ioc_patterns(strings: list[str]) -> list[SuspiciousPattern]:
        patterns = {"ip": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                    "url": r"https?://[^\s]+",
                    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"}
        result = []
        for cat, pat in patterns.items():
            matches = set()
            for s in strings:
                matches.update(re.findall(pat, s))
            for m in list(matches)[:20]:
                result.append(SuspiciousPattern(pattern=m, category=cat))
        return result

    @staticmethod
    def _summarize(d: dict) -> str:
        parts = []
        for k, v in d.items():
            if isinstance(v, list): parts.append(f"{k}:{len(v)}")
            elif isinstance(v, (int, float)): parts.append(f"{k}:{v}")
        return "; ".join(parts[:8])

    def get_available_functions(self) -> list[str]:
        return list(self._registry.keys())
