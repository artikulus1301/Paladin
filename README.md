# ⛨ Paladin — Autonomous Corporate Security System

> **v2.0** · Local LLM · SIFT Forensics · Self-Correcting Agent

Paladin is an end-to-end, locally hosted, autonomous enterprise security system with a forensic investigation layer. It ingests corporate telemetry (logs, emails, chats, calls), parses it via NLP, maps entities to a Neo4j knowledge graph, correlates suspicious activities, and leverages a local LLM (Qwen 3.5:9B) for threat analysis and autonomous response.

Version 2.0 adds a **SIFT Workstation-based forensic layer** for deep incident investigation using the **Custom MCP Server** architectural pattern.

---

## 🏗️ System Architecture

```mermaid
graph TB
    subgraph "Layer 1 — Data Ingestion"
        LG[Log Generator] --> Q[Event Queue]
        MG[Mail Generator] --> Q
        CG[Chat Generator] --> Q
        KG[Call Generator] --> Q
    end

    subgraph "Layer 2 — SAP Core"
        Q --> MP["Morpho Parser (SpaCy)"]
        MP --> GE[Graph Enricher]
        GE --> NEO[(Neo4j)]
        GE --> COR[Correlator]
        COR --> IM[Incident Manager]
    end

    subgraph "Layer 3 — LLM & Verification"
        IM -->|context| LLM[Qwen 3.5:9B via Ollama]
        LLM -->|proposed action| VER[Action Verifier]
        VER -->|approved| NEO
        VER -->|rejected| LLM
    end

    subgraph "Layer 4 — Autonomous Executor"
        AE[Auto-Executor]
        NEO -->|stale pending| AE
        AE -->|execute| NEO
    end

    subgraph "Layer 5 — Forensic Investigation v2.0"
        IM -->|"score ≥ 0.65"| FPM[ForensicPlanManager]
        FPM --> MCP[SIFT MCP Server]
        MCP --> SB[Docker Sandbox]
        SB -->|findings| CE[Correlation Engine]
        CE --> HT[Hallucination Tracker]
        HT --> AR[Accuracy Report]
    end

    subgraph "Layer 6 — Dashboard"
        NEO --> API[FastAPI + JWT]
        API --> WS[WebSocket]
        WS --> UI[Operator Dashboard]
    end

    subgraph "Storage"
        NEO[(Neo4j — Hot Graph)]
        PG[(PostgreSQL — Cold Archive + Forensic Logs)]
    end
```

---

## ✨ Core Features (v1.0)

| Feature | Description |
|---------|-------------|
| **Multi-Modal Ingestion** | System logs, corporate emails, messenger chats, voice call transcripts |
| **Morpho-Semantic Parsing** | SpaCy/Natasha + custom security vocabulary for risk/sentiment scoring |
| **Graph Correlation** | Neo4j Cypher traversals detect complex patterns (mass download, brute force, insider chains) |
| **Local LLM Analysis** | Qwen 3.5:9B generates incident summaries and proposes actions (NOTIFY, FLAG, ISOLATE, BLOCK, BLOCK_IP, QUARANTINE_FILE, REVOKE_SESSIONS) |
| **Multi-Signal Verifier** | Gates LLM actions via severity policies + quality metrics (Entropy, Semantic Coherence) |
| **Dual-Mode Response** | Toggle via UI: **Autonomous** (instant enforcement) or **Human-in-the-Loop** (see *Response Policy* below) |
| **Auto-Executor** | Background service enforces proposed actions after operator timeout |
| **Alert Deduplication** | Aggregates related events into single incidents to prevent alert fatigue |
| **Real-Time Dashboard** | FastAPI + WebSocket UI for SOC operators — incidents, graph viewer, scenario triggers |
| **E2EE** | Self-signed TLS for HTTPS/WSS dashboard access |
| **Internal mTLS** | Secure Neo4j (Bolt+SSC) and PostgreSQL (SSLMode) via local Certificate Authority |
| **JWT Authentication** | All API endpoints and WebSocket connections require valid tokens |

---

## 🛂 Response Policy

| Action level | Human-in-the-Loop mode (default) | Autonomous mode |
|---|---|---|
| READ, NOTIFY | Executed after the operator timeout (default 60s) | Executed immediately |
| FLAG, REVOKE_SESSIONS | Executed after the operator timeout | Executed immediately |
| ISOLATE, BLOCK, BLOCK_IP, QUARANTINE_FILE | **Never auto-executed** — after the timeout the incident moves to `awaiting_operator` | Executed immediately |

* **Approve** in the dashboard executes the proposed action; **Reject** cancels it.
* The verifier caps the action by severity (LOW→NOTIFY, MEDIUM→FLAG, HIGH/CRITICAL→ISOLATE). A rejected proposal is retried once with the verifier's feedback; if still rejected, Paladin falls back to NOTIFY.
* Low-quality LLM reasoning (entropy/perplexity outliers) forces FLAG-and-above actions to wait for the operator.
* `PROTECTED_ACCOUNTS` (account names or employee UIDs, case-insensitive) are never targeted automatically: such incidents go straight to `awaiting_operator`, and the executor skips protected entities even on approval.
* LLM output that is not valid JSON defaults to **NOTIFY** — keywords in free text are never interpreted as actions.
* Monitored content (emails, chats, transcripts, tool output) reaches the model only inside `<untrusted_data>` fences; instructions inside them are ignored and reported as manipulation.
* Incidents that are aggregated into an open one are re-analysed when their severity escalates.
* In `PALADIN_MODE=production` the system refuses to start while `DASHBOARD_ADMIN_PASSWORD`, `DASHBOARD_SECRET` or `NEO4J_PASSWORD` hold their defaults. Login is rate-limited (5 failures / 5 min).

---

## 🔬 Forensic Layer (v2.0)

### How It Works

When an incident's severity score crosses the threshold (≥ 0.65), Paladin switches from **Tool Mode** (quick inline analysis) to **Pipeline Mode** — launching a full forensic investigation:

```
1. Incident triggers Pipeline Mode (score ≥ 0.65)
2. SandboxManager creates isolated Docker container
3. ForensicPlanManager asks Qwen to generate investigation plan
4. SIFT MCP Server executes each step inside the sandbox
5. Findings stored in Neo4j with [:PRODUCED] edges
6. Self-Correction Loop checks for contradictions after each finding
7. Correlation Engine detects cross-source discrepancies
8. Hallucination Tracker verifies LLM claims against raw tool output
9. Accuracy Report generated with verification metrics
```

### Security Boundaries (4 layers, defense-in-depth)

| # | Boundary | Mechanism | Protection |
|---|----------|-----------|------------|
| 1 | **Action Verifier** | Programmatic filter | SAFE / REQUIRES_APPROVAL / FORBIDDEN classification. Shell injection detection (`;`, `&&`, `\|`, `` ` ``, `$()`, NUL/newline). Paths are normalized before the boundary check. Default-deny policy. REQUIRES_APPROVAL calls are parked until an operator approves them in the dashboard and are auto-denied after `FORENSIC_APPROVAL_TIMEOUT` (60s). |
| 2 | **MCP Server API** | API surface limitation | No destructive functions exist in the codebase. No `rm`, `dd`, `chmod`, `mkfs`, shell access. Only 11 read-only functions exposed. |
| 3 | **Sandbox Filesystem** | Kernel-level isolation | `/evidence` mounted with `:ro` flag. OS-level write prohibition. |
| 4 | **Sandbox Network** | Docker network isolation | `network: none`. Zero outbound connectivity. No DNS, no exfiltration surface. |

Additional hardening: `--security-opt no-new-privileges`, `--read-only`, `--cap-drop ALL`, `--pids-limit 256`, CPU/memory limits, tmpfs for scratch work.

### MCP Functions (Custom MCP Server)

| Function | Backend Tool | Evidence Type | Output |
|----------|-------------|---------------|--------|
| `get_file_metadata` | stat + file | Disk | FileMetadata (name, size, timestamps, MIME, permissions) |
| `compute_hash` | md5sum / sha256sum | Disk | HashResult (path, algorithm, hash, size) |
| `extract_strings` | strings | Disk | StringsList + SuspiciousPattern IOC detection (IPs, URLs, emails) |
| `analyze_process_list` | Volatility3 pslist | Memory | ProcessList + suspicious process flagging |
| `scan_network_connections` | Volatility3 netscan | Memory | ConnectionList + external connection filtering |
| `extract_loaded_modules` | Volatility3 dlllist | Memory | ModuleList (loaded DLLs per PID) |
| `parse_mft` | analyzeMFT | Disk | MFTResult (NTFS timeline + timestomping anomalies) |
| `parse_prefetch` | prefetch_parser | Disk | PrefetchResult (execution history + suspicious executables) |
| `extract_registry_hive` | regripper | Disk | RegistryResult (keys, autorun entries, recent activity) |
| `parse_pcap` | tshark | Network | PCAPResult (DNS queries, HTTP requests, suspicious traffic) |
| `extract_browser_artifacts` | hindsight | Disk | BrowserResult (history, downloads, cookies, saved creds) |

All outputs are **typed Pydantic models** — the LLM agent never receives raw shell output.

### Self-Correction Loop

After each finding, Qwen reviews all previous findings for contradictions:
- **Contradiction detected** → Creates `[:CONTRADICTS]` edge in Neo4j
- **Rerun required** → Adds RECHECK TodoItem, increments plan iteration
- **Iteration limit** (default 5) → Finalizes with `COMPLETED_WITH_GAPS` status
- **Version history** → Each iteration creates a `[:HAS_VERSION]` snapshot

### Correlation Engine (LLM-free)

Deterministic cross-source contradiction detection:

| Detection | Description | Example |
|-----------|-------------|---------|
| **Ghost Process** | Process in memory but no disk artifacts | Rootkit, process hollowing |
| **Temporal Paradox** | Timeline conflicts between sources | File created after its hash appeared in network traffic |
| **Registry Mismatch** | Execution evidence without installation record | Portable or dropped malware |
| **Invisible Connection** | Network connection without DNS query | Direct IP C2 or DNS tunneling |

### Hallucination Tracker

Verifies every LLM finding against actual tool output:
- **Exact match**: `evidence_quote` found verbatim in a tool output value
- **Normalized match**: same contiguous text after case/whitespace/quote normalization (may span fields of one record)
- Quotes shorter than 6 characters and scattered word overlap are **not** accepted
- **Accuracy Report**: Total/verified/unverified/simulated findings, hallucination rate, confidence-accuracy correlation, `data_source` (`real_tools` / `mixed` / `demo_fixtures`)

### Demo Fixtures

The *nromanoff* demo (`demo_nromanoff.py`, `demo_full_showcase.py`) can run without Volatility/RegRipper/Hindsight in the sandbox: with `FORENSIC_DEMO_FIXTURES=true` (set automatically by those scripts) canned results from `paladin/forensic/demo_fixtures.py` are served for that case. Every such result is flagged `simulated`, and findings, the incident summary and the accuracy report say so. Fixtures are off by default and must never be enabled in production.

---

## 🧱 Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| LLM | Qwen 3.5:9B via Ollama | Incident analysis, forensic planning, self-correction |
| Knowledge Graph | Neo4j 5.18 + APOC | Entity relationships, incidents, forensic plans, findings |
| Archive DB | PostgreSQL 16 | Cold storage, tool execution logs, accuracy metrics |
| API | FastAPI + Uvicorn | Dashboard REST + WebSocket |
| NLP | SpaCy + Natasha | Morpho-semantic parsing |
| Auth | JWT + mTLS | Dashboard authentication, internal DB encryption |
| Sandbox | Docker (custom SIFT image) | Isolated forensic tool execution |
| Forensic Tools | Volatility3, Sleuthkit, tshark, regripper, plaso | Evidence analysis inside sandbox |

---

## 📁 Project Structure

```
paladin/
├── main.py                     # Orchestrator — event loop, pipeline wiring
├── config/
│   └── settings.py             # PydanticSettings (35+ config vars)
├── graph/
│   ├── schema.py               # Neo4j schema: 16 node labels, 25+ rel types
│   └── neo4j_client.py         # 30+ async CRUD methods (incidents + forensic)
├── llm/
│   ├── ollama_client.py        # Async Qwen interface
│   └── prompts.py              # System prompt + incident prompt builder
├── sap/
│   ├── morpho_parser.py        # SpaCy/Natasha NLP pipeline
│   ├── graph_enricher.py       # Event → Neo4j entity mapping
│   ├── correlator.py           # Multi-pattern correlation engine
│   ├── incident_manager.py     # Incident lifecycle + mode routing (v2.0)
│   └── auto_executor.py        # Autonomous timeout enforcement
├── verifier/
│   ├── verifier.py             # Multi-signal action gating
│   └── action_registry.py      # Action definitions + severity levels
├── forensic/                   # ── v2.0 Forensic Layer ──
│   ├── action_verifier.py      # Security boundary #1 (SAFE/APPROVAL/FORBIDDEN)
│   ├── mcp_server.py           # SIFT MCP Server — 11 typed functions
│   ├── mcp_types.py            # 25+ Pydantic models for MCP I/O
│   ├── sandbox_manager.py      # Docker sandbox lifecycle (boundaries #3, #4)
│   ├── plan_manager.py         # ForensicPlanManager + self-correction loop
│   ├── correlation_engine.py   # Cross-source contradiction detection
│   ├── hallucination_tracker.py # Finding verification + accuracy report
│   ├── prompts.py              # Planning, execution, self-check prompts
│   └── pg_store.py             # PostgreSQL: tool_executions, accuracy_metrics
├── dashboard/
│   ├── api.py                  # FastAPI app + forensic endpoints
│   └── frontend/index.html     # SOC operator dashboard
└── requirements.txt            # Python dependencies

docker/
└── sift-sandbox/
    └── Dockerfile              # SIFT forensic tools image

tests/
├── conftest.py                 # pytest glue (async tests, legacy script-style tests)
├── test_core.py                # Response policy, verifiers, approvals, API (pytest)
├── test_attack_shadow_paladin.py # Adversarial scenario: attacks on Paladin itself (defense report)
├── test_complex_cyberattacks.py # Multi-vector attack scenarios
├── test_forensic.py            # Forensic layer tests (63 checks)
└── test_total.py               # Total system test (run by test_core.py)
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Docker & Docker Compose
- [Ollama](https://ollama.ai/) with `qwen3.5:9b` model
- NVIDIA GPU (recommended for LLM inference)

### Local Demo (Windows, one command)

```powershell
.\start_demo.ps1     # checks prerequisites, starts Neo4j + PostgreSQL (docker-compose.demo.yml),
                     # warms up the model, launches Paladin, smoke-tests the API
.\stop_demo.ps1
```

Requires Docker Desktop, Ollama with `qwen3.5:9b` and the `.venv`. The demo stack uses ports
17474/17687/15432, so it can run next to other Neo4j/PostgreSQL instances. Talk track: [DEMO.md](DEMO.md).

### Quick Start

```bash
# 1. Install dependencies
pip install -r paladin/requirements.txt
python -m spacy download en_core_web_sm

# 2. Start infrastructure
docker run -d --name paladin-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/changeme123 neo4j:latest

# 3. Start Ollama
ollama serve && ollama pull qwen3.5:9b

# 4. Run demo
python demo.py

# 5. Open dashboard
# https://localhost:8888  (admin / admin)
```

### Full Docker Deployment (with TLS + PostgreSQL + SIFT)

```bash
cp paladin/.env.example .env
python setup_internal_tls.py
docker-compose -f docker-compose.paladin.yml up -d

# Build SIFT sandbox image
docker-compose -f docker-compose.paladin.yml --profile build-only build sift-sandbox
```

### Run Tests

```bash
pip install pytest
pytest            # whole suite, no Neo4j/Ollama/Docker required
```

#### Operation "Shadow Paladin" (adversarial scenario)

`tests/test_attack_shadow_paladin.py` attacks Paladin itself with a deliberately **compromised LLM**
(it obeys injected instructions and always picks the harshest action) and prints a defense report:
weaponizing the SOAR against the CEO, LLM overreach, keyword smuggling, dashboard takeover, insider
exfiltration, poisoned evidence with a hijacked forensic plan, direct sandbox-escape payloads, and
approval bypass. Each stage must be repelled by a programmatic guard, independent of the model.

```bash
pytest tests/test_attack_shadow_paladin.py -s           # with defense report
PALADIN_LIVE_LLM=1 pytest tests/test_attack_shadow_paladin.py -s   # S1 also against real Ollama
```

---

## 🧪 Simulated Attack Scenarios

14 built-in threat scenarios for testing:

| Source | Scenarios |
|--------|-----------|
| **Logs** | `brute_force`, `data_exfiltration`, `insider_threat`, `privilege_escalation` |
| **Emails** | `phishing`, `data_leak_email`, `social_engineering`, `external_exfil` |
| **Chat** | `insider_chat`, `credential_sharing`, `competitor_contact` |
| **Calls** | `data_theft_call`, `insider_recruitment`, `bribery_call` |

Trigger via dashboard UI or API: `POST /api/scenario`

---

## 🗄️ Neo4j Graph Schema

### Node Labels (16)

| Label | Domain | Description |
|-------|--------|-------------|
| `Employee` | Core | Corporate personnel with UID, department, clearance |
| `Device`, `File`, `IPAddress` | Core | Infrastructure entities |
| `Email`, `Message`, `Call` | Core | Communication events |
| `LogEvent` | Core | System/application logs with risk scores |
| `Incident` | Core | Correlated security incidents |
| `Department`, `Role`, `ClearanceLevel` | Org | Organizational hierarchy |
| `ForensicPlan` | Forensic | Investigation plan with iteration tracking |
| `TodoItem` | Forensic | Individual investigation step |
| `Finding` | Forensic | Evidence-backed conclusion with confidence score |
| `ToolExecution` | Forensic | MCP function execution record |

### Key Relationships

| Relationship | Domain | Connects |
|-------------|--------|----------|
| `SENT_EMAIL`, `SENT_MESSAGE`, `MADE_CALL` | Core | Employee → Communication |
| `USES_DEVICE`, `ACCESSED_FILE` | Core | Employee → Assets |
| `INVOLVED_IN`, `TRIGGERED_BY` | Core | Entity → Incident |
| `HAS_FORENSIC_PLAN` | Forensic | Incident → ForensicPlan |
| `CONTAINS_TODO` | Forensic | ForensicPlan → TodoItem |
| `PRODUCED` | Forensic | ForensicPlan → Finding |
| `CONTRADICTS` | Forensic | Finding ↔ Finding |
| `HAS_VERSION` | Forensic | ForensicPlan → ForensicPlan (snapshot) |

---

## 📊 API Endpoints

### Core API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | JWT authentication |
| GET | `/api/incidents` | List open incidents (`?status=` filters by status or action_status) |
| POST | `/api/incidents/action` | Approve (executes the action) / reject (cancels it) |
| GET | `/api/graph/{incident_id}` | Get incident subgraph |
| POST | `/api/scenario` | Trigger test scenario |
| GET/POST | `/api/config/mode` | Read / toggle autonomous vs HITL mode |
| GET | `/api/status` | System health check |
| WS | `/ws` | Real-time event stream |

### Forensic API (v2.0)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/forensic/plan/{plan_id}` | Get forensic plan with items + findings |
| GET | `/api/forensic/incident/{incident_id}` | Get forensic plan for incident |
| GET | `/api/forensic/accuracy/{plan_id}` | Generate accuracy report |
| GET | `/api/forensic/approvals` | Pending REQUIRES_APPROVAL MCP calls |
| POST | `/api/forensic/approvals/{request_id}` | `{"decision": "approve"\|"deny"}` |

---

## 📜 License

[MIT License](LICENSE)
