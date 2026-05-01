"""
Paladin — Central configuration via Pydantic Settings.
All values configurable through .env or environment variables.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, List

from pydantic import Field
from pydantic_settings import BaseSettings


class RunMode(str, Enum):
    DUMMY = "dummy"
    PRODUCTION = "production"


class Settings(BaseSettings):
    # ── General ────────────────────────────────────────────────────────────────
    run_mode: RunMode = Field(RunMode.DUMMY, env="PALADIN_MODE")
    instance_name: str = Field("paladin-dev", env="PALADIN_INSTANCE")

    # ── Neo4j (hot graph) ──────────────────────────────────────────────────────
    neo4j_uri: str = Field("bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field("neo4j", env="NEO4J_USER")
    neo4j_password: str = Field("changeme123", env="NEO4J_PASSWORD")
    max_neo4j_results: int = Field(25, env="MAX_NEO4J_RESULTS")

    # ── PostgreSQL (cold archive) ──────────────────────────────────────────────
    postgres_dsn: str = Field(
        "postgresql://paladin:paladin@localhost:5432/paladin_archive",
        env="POSTGRES_DSN",
    )

    # ── Kafka ──────────────────────────────────────────────────────────────────
    kafka_bootstrap: str = Field("localhost:9092", env="KAFKA_BOOTSTRAP")
    kafka_topics: List[str] = Field(
        default=["logs", "emails", "messages", "calls"],
        env="KAFKA_TOPICS",
    )
    # In dummy mode Kafka is replaced by asyncio.Queue
    use_memory_queue: bool = Field(True, env="USE_MEMORY_QUEUE")

    # ── Ollama / LLM ──────────────────────────────────────────────────────────
    ollama_base_url: str = Field("http://localhost:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field("qwen3.5:9b", env="OLLAMA_MODEL")
    ollama_timeout: int = Field(120, env="OLLAMA_TIMEOUT")

    # ── Internet (SearXNG + trafilatura) ───────────────────────────────────────
    searxng_url: str = Field("http://localhost:8080", env="SEARXNG_URL")
    max_search_results: int = Field(5, env="MAX_SEARCH_RESULTS")

    # ── SAP thresholds ─────────────────────────────────────────────────────────
    sap_score_threshold: float = Field(0.7, env="SAP_SCORE_THRESHOLD")
    sap_correlation_window_minutes: int = Field(60, env="SAP_CORRELATION_WINDOW")
    sap_max_events_per_batch: int = Field(100, env="SAP_MAX_EVENTS_BATCH")

    # ── Verifier ───────────────────────────────────────────────────────────────
    verifier_entropy_window: int = Field(50, env="VERIFIER_ENTROPY_WINDOW")
    entropy_z_threshold: float = Field(2.0, env="ENTROPY_Z_THRESHOLD")
    semantic_similarity_threshold: float = Field(0.35, env="SEMANTIC_SIMILARITY_THRESHOLD")
    perplexity_threshold: float = Field(500.0, env="PERPLEXITY_THRESHOLD")

    # ── Autonomous execution ──────────────────────────────────────────────────
    operator_timeout_seconds: int = Field(
        60, env="OPERATOR_TIMEOUT_SECONDS",
        description="Seconds to wait for operator before auto-executing action"
    )
    auto_execute_enabled: bool = Field(
        True, env="AUTO_EXECUTE_ENABLED",
        description="Enable autonomous action execution on operator timeout"
    )
    auto_execute_check_interval: int = Field(
        10, env="AUTO_EXECUTE_CHECK_INTERVAL",
        description="How often (seconds) to scan for stale pending incidents"
    )

    # ── Dashboard ──────────────────────────────────────────────────────────────
    dashboard_host: str = Field("0.0.0.0", env="DASHBOARD_HOST")
    dashboard_port: int = Field(8888, env="DASHBOARD_PORT")
    dashboard_secret: str = Field("paladin-secret-change-me", env="DASHBOARD_SECRET")

    # ── Archive policy (days) ──────────────────────────────────────────────────
    archive_log_days: int = Field(30, env="ARCHIVE_LOG_DAYS")
    archive_comms_days: int = Field(90, env="ARCHIVE_COMMS_DAYS")
    archive_incident_days: int = Field(180, env="ARCHIVE_INCIDENT_DAYS")
    archive_risk_score_cutoff: float = Field(0.2, env="ARCHIVE_RISK_CUTOFF")

    # ── Dummy generators ──────────────────────────────────────────────────────
    dummy_employee_count: int = Field(25, env="DUMMY_EMPLOYEE_COUNT")
    dummy_events_per_minute: int = Field(10, env="DUMMY_EVENTS_PER_MIN")
    dummy_anomaly_probability: float = Field(0.05, env="DUMMY_ANOMALY_PROB")

    # ── Logging ────────────────────────────────────────────────────────────────
    log_level: str = Field("INFO", env="LOG_LEVEL")

    # ── Protected entities (comma-separated) ───────────────────────────────────
    protected_accounts: str = Field(
        "admin,root,SYSTEM,paladin-service", env="PROTECTED_ACCOUNTS"
    )

    @property
    def protected_account_list(self) -> List[str]:
        return [a.strip() for a in self.protected_accounts.split(",") if a.strip()]

    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "extra": "ignore"
    }


settings = Settings()
