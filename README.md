# ⛨ Paladin Autonomous Local Security System

Paladin is an end-to-end, locally hosted, autonomous enterprise security system. It ingests simulated or real corporate data (logs, emails, chats, calls), parses it using NLP, maps it to a Neo4j knowledge graph, correlates suspicious activities, and leverages a local LLM (Qwen3.5:9B) for threat analysis and autonomous response (FLAG, ISOLATE) with a human-in-the-loop dashboard.

Originally evolved from the Richter RAG bot, Paladin is a complete architectural overhaul focused on proactive corporate monitoring and automated incident response.

## 🏗️ Architecture

```mermaid
graph TB
    subgraph "Layer 1 — Data Generators (Simulation)"
        LG[Log Generator] --> Q[Event Queue]
        MG[Mail Generator] --> Q
        CG[Chat Generator] --> Q
        KG[Call Generator] --> Q
    end

    subgraph "Layer 2 — Ingestion"
        Q --> COL[Collectors]
        COL --> |raw files| FS[Filesystem]
    end

    subgraph "Layer 3 — SAP Core (Parsing & Correlation)"
        COL --> MP[Morpho Parser (SpaCy)]
        MP --> GE[Graph Enricher]
        GE --> NEO[Neo4j]
        GE --> COR[Correlator]
        COR --> IM[Incident Manager]
    end

    subgraph "Layer 4 — LLM & Verification"
        IM --> |context| LLM[Qwen3.5:9B via Ollama]
        LLM --> |proposed action| VER
        VER[Action Verifier]
        VER --> |approved| NEO
        VER --> |rejected| LLM
    end

    subgraph "Layer 5 — Autonomous Executor"
        AE[Auto-Executor]
        NEO --> |stale pending incidents| AE
        AE --> |auto-execute action| NEO
    end

    subgraph "Layer 6 — Dashboard"
        NEO --> API[FastAPI]
        API --> WS[WebSocket]
        WS --> UI[Operator Dashboard]
    end

    subgraph "Storage"
        NEO[(Neo4j — Hot Graph)]
        PG[(PostgreSQL — Cold Archive)]
        FS[(Filesystem — Raw Data)]
        NEO --> |cron archive| PG
    end
```

## ✨ Key Features

- **Multi-Modal Data Ingestion**: Parses system logs, corporate emails, messenger chats, and voice call transcripts.
- **Morpho-Semantic Parsing**: Uses SpaCy/Natasha with a custom security vocabulary to score text segments for risk and sentiment.
- **Graph-Based Correlation**: Maps events, employees, files, and devices into Neo4j. Uses Cypher traversals to detect complex attack patterns (e.g., Mass Download, Brute Force).
- **Local LLM Analysis**: Uses `qwen3.5:9b` via Ollama to generate human-readable incident summaries and propose mitigation actions (NOTIFY, FLAG, READ, ISOLATE, BLOCK, BLOCK_IP, QUARANTINE_FILE, REVOKE_SESSIONS).
- **Multi-Signal Verifier**: Gates LLM actions based on severity policies and quality metrics (Entropy, Semantic Coherence).
- **Dual-Mode Response**: Toggle dynamically via the UI between **Autonomous Mode** (instant enforcement: locking accounts, blocking IPs, revoking sessions) and **Human-in-the-Loop Mode** (60-second window for operator review).
- **Alert Fatigue Mitigation**: Automatically aggregates related trigger events into single open incidents to prevent duplicate alerts and optimize LLM API usage.
- **Real-Time Dashboard**: A FastAPI-powered, WebSocket-enabled React-style UI for SOC operators to monitor, approve, and visualize graph incidents.

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (for production setup)
- [Ollama](https://ollama.ai/) with the `qwen3.5:9b` model pulled locally.

### Local Demo Setup

The easiest way to test Paladin is using the included demo script, which starts the system in dummy mode, spawns 15 synthetic employees, and triggers test attacks.

1. **Install Python dependencies:**
   ```bash
   pip install -r paladin/requirements.txt
   ```

2. **Download NLP models:**
   ```bash
   python -m spacy download en_core_web_sm
   python -m spacy download ru_core_news_sm
   python -m spacy download xx_ent_wiki_sm
   ```

3. **Start Neo4j (via Docker):**
   ```bash
   docker run -d --name paladin-neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/changeme123 neo4j:latest
   ```

4. **Ensure Ollama is running:**
   ```bash
   ollama serve
   ollama pull qwen3.5:9b
   ```

5. **Run the Demonstration:**
   ```powershell
   python demo.py
   # Or use the runner: .\run_demo.ps1
   ```

6. **Open the Dashboard:**
   Navigate to [http://localhost:8888](http://localhost:8888) in your browser.

## 🧪 Simulated Attack Scenarios

Paladin comes with 14 built-in threat scenarios that can be triggered via the dashboard or API to test correlation and LLM response:

- **Logs**: `brute_force`, `data_exfiltration`, `insider_threat`, `privilege_escalation`
- **Emails**: `phishing`, `data_leak_email`, `social_engineering`, `external_exfil`
- **Chat**: `insider_chat`, `credential_sharing`, `competitor_contact`
- **Calls**: `data_theft_call`, `insider_recruitment`, `bribery_call`

## 🐳 Docker Deployment

For a full containerized stack including PostgreSQL archiving:

```bash
cp paladin/.env.example .env
docker-compose -f docker-compose.paladin.yml up -d
```

## 📜 License

[MIT License](LICENSE)
