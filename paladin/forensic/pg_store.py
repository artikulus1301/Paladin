"""
PostgreSQL Store — tool_executions and accuracy_metrics tables.
Provides structured logging for hackathon Execution Logs requirement
and accuracy tracking for Hallucination Tracker.
"""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from typing import Optional
import structlog

log = structlog.get_logger(__name__)

# SQL for table creation
CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS tool_executions (
    execution_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     TEXT,
    plan_id         TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mcp_function    TEXT NOT NULL,
    parameters_json TEXT,
    raw_output_hash TEXT,
    output_summary  TEXT,
    finding_id      TEXT,
    token_usage     INT DEFAULT 0,
    duration_ms     INT DEFAULT 0,
    iteration_number INT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tool_exec_incident ON tool_executions(incident_id);
CREATE INDEX IF NOT EXISTS idx_tool_exec_plan ON tool_executions(plan_id);
CREATE INDEX IF NOT EXISTS idx_tool_exec_function ON tool_executions(mcp_function);

CREATE TABLE IF NOT EXISTS accuracy_metrics (
    metric_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id             TEXT NOT NULL,
    incident_id         TEXT,
    total_findings      INT DEFAULT 0,
    verified_findings   INT DEFAULT 0,
    unverified_findings INT DEFAULT 0,
    hallucination_rate  REAL DEFAULT 0.0,
    false_positive_count INT DEFAULT 0,
    avg_confidence      REAL DEFAULT 0.0,
    confidence_accuracy_correlation REAL DEFAULT 0.0,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accuracy_plan ON accuracy_metrics(plan_id);

CREATE TABLE IF NOT EXISTS verifier_audit_log (
    audit_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action_requested    TEXT NOT NULL,
    parameters_hash     TEXT,
    category_assigned   TEXT NOT NULL,
    decision            TEXT NOT NULL,
    operator_id         TEXT,
    incident_id         TEXT,
    forensic_plan_id    TEXT
);

CREATE INDEX IF NOT EXISTS idx_verifier_audit_incident ON verifier_audit_log(incident_id);
"""


class ForensicPGStore:
    """PostgreSQL store for forensic execution logs and accuracy metrics."""

    def __init__(self, pool=None) -> None:
        self._pool = pool

    async def initialize(self, dsn: str) -> None:
        """Create connection pool and initialize tables."""
        import asyncpg
        self._pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_TABLES_SQL)
        log.info("forensic_pg_store_initialized")

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    # ── Tool Executions ───────────────────────────────────────────────────────

    async def log_tool_execution(
        self, incident_id: str | None, plan_id: str | None,
        mcp_function: str, parameters: dict, raw_output_hash: str,
        duration_ms: int, output_summary: str = "",
        finding_id: str | None = None, token_usage: int = 0,
        iteration_number: int = 0,
    ) -> str:
        """Log a tool execution. Returns execution_id."""
        eid = str(uuid.uuid4())
        if not self._pool:
            log.debug("pg_store_not_connected", function=mcp_function)
            return eid
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO tool_executions
                (execution_id, incident_id, plan_id, mcp_function,
                 parameters_json, raw_output_hash, output_summary,
                 finding_id, token_usage, duration_ms, iteration_number)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            """, uuid.UUID(eid), incident_id, plan_id, mcp_function,
                json.dumps(parameters, default=str), raw_output_hash,
                output_summary, finding_id, token_usage, duration_ms,
                iteration_number)
        return eid

    async def get_executions_for_plan(self, plan_id: str) -> list[dict]:
        if not self._pool: return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM tool_executions WHERE plan_id = $1
                ORDER BY timestamp ASC
            """, plan_id)
            return [dict(r) for r in rows]

    async def get_raw_output_hash(self, execution_id: str) -> str | None:
        if not self._pool: return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT raw_output_hash FROM tool_executions WHERE execution_id=$1",
                uuid.UUID(execution_id))
            return row["raw_output_hash"] if row else None

    # ── Accuracy Metrics ──────────────────────────────────────────────────────

    async def upsert_accuracy_metrics(
        self, plan_id: str, incident_id: str | None,
        total: int, verified: int, unverified: int,
        hallucination_rate: float, avg_confidence: float,
    ) -> None:
        if not self._pool: return
        async with self._pool.acquire() as conn:
            # Delete old metric for this plan and insert fresh
            await conn.execute(
                "DELETE FROM accuracy_metrics WHERE plan_id=$1", plan_id)
            await conn.execute("""
                INSERT INTO accuracy_metrics
                (plan_id, incident_id, total_findings, verified_findings,
                 unverified_findings, hallucination_rate, avg_confidence)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
            """, plan_id, incident_id, total, verified, unverified,
                hallucination_rate, avg_confidence)

    async def get_accuracy_metrics(self, plan_id: str) -> dict | None:
        if not self._pool: return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM accuracy_metrics WHERE plan_id=$1", plan_id)
            return dict(row) if row else None

    # ── Verifier Audit Log ────────────────────────────────────────────────────

    async def log_verifier_decision(
        self, action_requested: str, parameters_hash: str,
        category: str, decision: str,
        incident_id: str | None = None, plan_id: str | None = None,
        operator_id: str | None = None,
    ) -> None:
        if not self._pool: return
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO verifier_audit_log
                (action_requested, parameters_hash, category_assigned,
                 decision, operator_id, incident_id, forensic_plan_id)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
            """, action_requested, parameters_hash, category, decision,
                operator_id, incident_id, plan_id)

    # ── Export for Hackathon ──────────────────────────────────────────────────

    async def export_execution_logs_jsonl(self, plan_id: str) -> str:
        """Export tool executions as JSONL for hackathon submission."""
        rows = await self.get_executions_for_plan(plan_id)
        lines = []
        for r in rows:
            obj = {
                "execution_id": str(r.get("execution_id", "")),
                "timestamp": r.get("timestamp", "").isoformat() if r.get("timestamp") else "",
                "mcp_function": r.get("mcp_function", ""),
                "parameters_hash": r.get("raw_output_hash", "")[:16],
                "finding_id": r.get("finding_id"),
                "token_usage": r.get("token_usage", 0),
                "duration_ms": r.get("duration_ms", 0),
                "iteration_number": r.get("iteration_number", 0),
            }
            lines.append(json.dumps(obj, default=str))
        return "\n".join(lines)
