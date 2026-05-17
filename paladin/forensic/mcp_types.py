"""
MCP Server — Typed Pydantic models for all SIFT tool inputs and outputs.
Every MCP function accepts and returns strictly typed data.
No raw shell output ever reaches the agent directly.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class HashAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class OutputFormat(str, Enum):
    TIMELINE = "timeline"
    JSON = "json"
    CSV = "csv"


class RegistryHive(str, Enum):
    SYSTEM = "SYSTEM"
    SOFTWARE = "SOFTWARE"
    SAM = "SAM"
    NTUSER = "NTUSER"


# ── File Artifacts ────────────────────────────────────────────────────────────

class FileMetadata(BaseModel):
    """Result of get_file_metadata."""
    name: str
    size: int
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    mime_type: str = "application/octet-stream"
    permissions: str = ""
    path: str = ""


class HashResult(BaseModel):
    """Result of compute_hash."""
    path: str
    algorithm: str
    hash_value: str
    file_size: int


class SuspiciousPattern(BaseModel):
    """A suspicious string pattern found during extraction."""
    pattern: str
    category: str  # ip, url, email, registry_key, base64, etc.
    count: int = 1


class StringsList(BaseModel):
    """Result of extract_strings."""
    strings: list[str] = Field(default_factory=list)
    total_count: int = 0
    suspicious_patterns: list[SuspiciousPattern] = Field(default_factory=list)


# ── Process & Memory Artifacts ────────────────────────────────────────────────

class ProcessInfo(BaseModel):
    """Single process entry from memory analysis."""
    pid: int
    name: str
    ppid: int = 0
    cmd: str = ""
    create_time: Optional[str] = None


class ProcessList(BaseModel):
    """Result of analyze_process_list."""
    processes: list[ProcessInfo] = Field(default_factory=list)
    suspicious_processes: list[ProcessInfo] = Field(default_factory=list)
    total_count: int = 0


class NetworkConnection(BaseModel):
    """Single network connection entry."""
    local_addr: str
    remote_addr: str
    state: str
    pid: int = 0
    process_name: str = ""


class ConnectionList(BaseModel):
    """Result of scan_network_connections."""
    connections: list[NetworkConnection] = Field(default_factory=list)
    external_connections: list[NetworkConnection] = Field(default_factory=list)
    total_count: int = 0


class ModuleInfo(BaseModel):
    """Single loaded module entry."""
    name: str
    base_address: str = ""
    size: int = 0
    path: str = ""
    signed: bool = True


class ModuleList(BaseModel):
    """Result of extract_loaded_modules."""
    modules: list[ModuleInfo] = Field(default_factory=list)
    unsigned_modules: list[ModuleInfo] = Field(default_factory=list)
    hidden_modules: list[ModuleInfo] = Field(default_factory=list)


# ── Disk Artifacts ────────────────────────────────────────────────────────────

class MFTEntry(BaseModel):
    """Single MFT timeline entry."""
    timestamp: str
    action: str  # CREATED, MODIFIED, ACCESSED, DELETED
    path: str
    size: int = 0


class MFTAnomaly(BaseModel):
    """Detected MFT anomaly."""
    description: str
    entry: Optional[MFTEntry] = None
    anomaly_type: str = ""  # timestomp, orphan, hidden


class MFTResult(BaseModel):
    """Result of parse_mft."""
    entry_count: int = 0
    timeline: list[MFTEntry] = Field(default_factory=list)
    anomalies: list[MFTAnomaly] = Field(default_factory=list)


class PrefetchEntry(BaseModel):
    """Single prefetch file entry."""
    name: str
    run_count: int = 0
    last_run: Optional[str] = None
    loaded_files: list[str] = Field(default_factory=list)


class PrefetchResult(BaseModel):
    """Result of parse_prefetch."""
    executables: list[PrefetchEntry] = Field(default_factory=list)
    suspicious_executables: list[PrefetchEntry] = Field(default_factory=list)


class RegistryEntry(BaseModel):
    """Single registry key/value."""
    key_path: str
    value_name: str = ""
    value_data: str = ""
    last_modified: Optional[str] = None


class RegistryResult(BaseModel):
    """Result of extract_registry_hive."""
    keys: list[RegistryEntry] = Field(default_factory=list)
    autorun_entries: list[RegistryEntry] = Field(default_factory=list)
    recent_activity: list[RegistryEntry] = Field(default_factory=list)


# ── Network Artifacts ─────────────────────────────────────────────────────────

class PCAPConversation(BaseModel):
    """Single PCAP conversation summary."""
    src: str
    dst: str
    protocol: str
    packets: int = 0
    bytes_transferred: int = 0


class DNSQuery(BaseModel):
    """Single DNS query from PCAP."""
    query: str
    response: str = ""
    query_type: str = "A"
    timestamp: Optional[str] = None


class HTTPRequest(BaseModel):
    """Single HTTP request from PCAP."""
    method: str
    url: str
    host: str = ""
    user_agent: str = ""
    status_code: int = 0
    timestamp: Optional[str] = None


class SuspiciousTraffic(BaseModel):
    """Suspicious traffic pattern detected."""
    description: str
    src: str
    dst: str
    reason: str


class PCAPResult(BaseModel):
    """Result of parse_pcap."""
    conversations: list[PCAPConversation] = Field(default_factory=list)
    dns_queries: list[DNSQuery] = Field(default_factory=list)
    http_requests: list[HTTPRequest] = Field(default_factory=list)
    suspicious_traffic: list[SuspiciousTraffic] = Field(default_factory=list)


class BrowserResult(BaseModel):
    """Result of extract_browser_artifacts."""
    history: list[dict] = Field(default_factory=list)
    downloads: list[dict] = Field(default_factory=list)
    cookies_domains: list[str] = Field(default_factory=list)
    saved_credentials_count: int = 0


# ── Supertimeline (Iteration 3) ──────────────────────────────────────────────

class TimelineEvent(BaseModel):
    """Single event in a supertimeline."""
    timestamp: str
    source: str  # mft, prefetch, registry, pcap, memory, evtx
    event_type: str
    description: str
    artifact: str = ""
    extra: dict = Field(default_factory=dict)


class SuperTimelineResult(BaseModel):
    """Result of build_supertimeline."""
    events: list[TimelineEvent] = Field(default_factory=list)
    total_count: int = 0
    sources_used: list[str] = Field(default_factory=list)
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None


# ── MCP Function Call envelope ────────────────────────────────────────────────

class MCPRequest(BaseModel):
    """Envelope for an MCP function call from the agent."""
    function: str
    parameters: dict = Field(default_factory=dict)
    incident_id: Optional[str] = None
    plan_id: Optional[str] = None


class MCPResponse(BaseModel):
    """Envelope for an MCP function response."""
    function: str
    success: bool
    result: Optional[dict] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    raw_output_hash: str = ""
