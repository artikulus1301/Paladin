"""
Paladin — Main entry point and orchestrator.
Wires all layers together and starts the system.
"""
from __future__ import annotations

import asyncio
import os
import sys

import structlog
import uvicorn

from paladin.config.settings import settings, RunMode

# ── Logging setup ─────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger(__name__)

# ── Dummy employee pool ──────────────────────────────────────────────────────

DUMMY_EMPLOYEES = [
    {"uid": "emp-001", "full_name": "Alexei Petrov", "email": "a.petrov@corp.paladin.local", "department": "Engineering", "role": "Senior Developer", "manager_uid": "emp-005"},
    {"uid": "emp-002", "full_name": "Maria Ivanova", "email": "m.ivanova@corp.paladin.local", "department": "Finance", "role": "Accountant", "manager_uid": "emp-006"},
    {"uid": "emp-003", "full_name": "Dmitry Sokolov", "email": "d.sokolov@corp.paladin.local", "department": "IT Security", "role": "Security Analyst", "manager_uid": "emp-007"},
    {"uid": "emp-004", "full_name": "Elena Kuznetsova", "email": "e.kuznetsova@corp.paladin.local", "department": "HR", "role": "HR Specialist", "manager_uid": "emp-006"},
    {"uid": "emp-005", "full_name": "Sergei Volkov", "email": "s.volkov@corp.paladin.local", "department": "Engineering", "role": "Team Lead", "manager_uid": "emp-008"},
    {"uid": "emp-006", "full_name": "Olga Morozova", "email": "o.morozova@corp.paladin.local", "department": "Finance", "role": "Manager", "manager_uid": "emp-009"},
    {"uid": "emp-007", "full_name": "Andrei Kozlov", "email": "a.kozlov@corp.paladin.local", "department": "IT Security", "role": "Manager", "manager_uid": "emp-009"},
    {"uid": "emp-008", "full_name": "Natalia Orlova", "email": "n.orlova@corp.paladin.local", "department": "Engineering", "role": "Director", "manager_uid": "emp-010"},
    {"uid": "emp-009", "full_name": "Viktor Lebedev", "email": "v.lebedev@corp.paladin.local", "department": "Operations", "role": "VP", "manager_uid": "emp-010"},
    {"uid": "emp-010", "full_name": "Igor Smirnov", "email": "i.smirnov@corp.paladin.local", "department": "Executive", "role": "CEO", "manager_uid": None},
    {"uid": "emp-011", "full_name": "Anna Fedorova", "email": "a.fedorova@corp.paladin.local", "department": "Legal", "role": "Manager", "manager_uid": "emp-009"},
    {"uid": "emp-012", "full_name": "Pavel Novikov", "email": "p.novikov@corp.paladin.local", "department": "Engineering", "role": "Junior Developer", "manager_uid": "emp-005"},
    {"uid": "emp-013", "full_name": "Svetlana Popova", "email": "s.popova@corp.paladin.local", "department": "Sales", "role": "Manager", "manager_uid": "emp-009"},
    {"uid": "emp-014", "full_name": "Roman Karpov", "email": "r.karpov@corp.paladin.local", "department": "Engineering", "role": "Intern", "manager_uid": "emp-005"},
    {"uid": "emp-015", "full_name": "Irina Belova", "email": "i.belova@corp.paladin.local", "department": "IT Security", "role": "System Administrator", "manager_uid": "emp-007"},
]


def check_security_settings() -> None:
    """Refuse to run production with shipped default credentials; warn in dummy mode."""
    insecure = settings.insecure_defaults()
    if not insecure:
        return
    if settings.run_mode == RunMode.PRODUCTION:
        log.error("insecure_defaults_refusing_to_start", settings=insecure,
                  hint="set strong values in .env (DASHBOARD_SECRET must be >= 32 chars)")
        raise SystemExit(2)
    log.warning("insecure_defaults", settings=insecure,
                hint="acceptable for local demo only — production mode will refuse to start")


async def main() -> None:
    log.info("paladin_startup", mode=settings.run_mode, model=settings.ollama_model)
    check_security_settings()

    # ── Layer: Graph ──────────────────────────────────────────────────────
    from paladin.graph.neo4j_client import Neo4jClient
    neo4j = Neo4jClient()
    await neo4j.connect()
    await neo4j.seed_organization()

    # Seed dummy employees
    for emp in DUMMY_EMPLOYEES:
        await neo4j.upsert_employee(emp)
    log.info("employees_seeded", count=len(DUMMY_EMPLOYEES))

    # ── Layer: LLM ────────────────────────────────────────────────────────
    from paladin.llm.ollama_client import OllamaClient
    llm = OllamaClient()
    await llm.start()

    # ── Layer: SAP components ─────────────────────────────────────────────
    from paladin.sap.morpho_parser import MorphoParser
    from paladin.sap.graph_enricher import GraphEnricher
    from paladin.sap.correlator import Correlator
    from paladin.sap.incident_manager import IncidentManager

    parser = MorphoParser()
    enricher = GraphEnricher(neo4j)
    correlator = Correlator(neo4j)
    incident_mgr = IncidentManager(neo4j)

    # ── Layer: Verifier ───────────────────────────────────────────────────
    from paladin.verifier.verifier import ActionVerifier
    from paladin.sap.incident_analyzer import IncidentAnalyzer
    verifier = ActionVerifier()

    # ── Layer: Auto-Executor ──────────────────────────────────────────────
    from paladin.sap.auto_executor import AutoExecutor
    from paladin.dashboard.api import broadcast_incident, broadcast_event
    auto_exec = AutoExecutor(neo4j, broadcast_fn=broadcast_event)
    analyzer = IncidentAnalyzer(neo4j, llm, verifier, broadcast_fn=broadcast_incident)

    # ── Layer: Forensic (Paladin 2.0) ─────────────────────────────────────
    forensic_plan_mgr = None
    hallucination_tracker = None
    approval_broker = None

    if settings.forensic_enabled:
        from paladin.forensic.action_verifier import ForensicActionVerifier
        from paladin.forensic.approval_broker import ApprovalBroker
        from paladin.forensic.sandbox_manager import SandboxManager
        from paladin.forensic.mcp_server import SIFTMCPServer
        from paladin.forensic.pg_store import ForensicPGStore
        from paladin.forensic.plan_manager import ForensicPlanManager
        from paladin.forensic.hallucination_tracker import HallucinationTracker

        forensic_verifier = ForensicActionVerifier()
        sandbox_mgr = SandboxManager()
        pg_store = ForensicPGStore()
        approval_broker = ApprovalBroker(broadcast_fn=broadcast_event)

        try:
            await sandbox_mgr.cleanup_orphans()
        except Exception as e:
            log.warning("sandbox_orphan_cleanup_failed", error=str(e))

        # Initialize PostgreSQL for forensic logs (best-effort)
        try:
            await pg_store.initialize(settings.postgres_dsn)
            log.info("forensic_pg_store_ready")
        except Exception as e:
            log.warning("forensic_pg_store_unavailable", error=str(e))
            pg_store = None

        mcp_server = SIFTMCPServer(sandbox_mgr, forensic_verifier, pg_store,
                                   approval_broker=approval_broker)
        forensic_plan_mgr = ForensicPlanManager(
            neo4j=neo4j, llm=llm, mcp_server=mcp_server,
            sandbox=sandbox_mgr, pg_store=pg_store,
            broadcast_fn=broadcast_event)
        hallucination_tracker = HallucinationTracker(neo4j, pg_store)

        # Inject into incident manager for mode routing
        incident_mgr.set_forensic_plan_manager(forensic_plan_mgr)

        if settings.forensic_demo_fixtures:
            log.warning("forensic_demo_fixtures_enabled",
                        key=settings.forensic_demo_fixture_key,
                        note="matching investigations use canned data, marked simulated")

        log.info("forensic_layer_initialized",
                 mcp_functions=mcp_server.get_available_functions(),
                 pipeline_threshold=settings.severity_pipeline_threshold,
                 max_concurrent=settings.max_concurrent_investigations)

    # ── Layer: Dashboard ──────────────────────────────────────────────────
    from paladin.dashboard.api import app as dashboard_app, init_dashboard
    scenario_bus: asyncio.Queue = asyncio.Queue()
    init_dashboard(neo4j, scenario_bus, auto_exec,
                   forensic_plan_mgr=forensic_plan_mgr,
                   hallucination_tracker=hallucination_tracker,
                   approval_broker=approval_broker)

    # ── Queues (replace Kafka in dummy mode) ──────────────────────────────
    # event_queue    : raw events → single ordered SAP consumer (parse/enrich/correlate)
    # analysis_queue : incident contexts → pool of LLM workers (slow, parallel)
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    analysis_queue: asyncio.Queue = asyncio.Queue(maxsize=200)

    # ── Background task bookkeeping ───────────────────────────────────────
    background_tasks: set[asyncio.Task] = set()
    investigating: set[str] = set()
    investigation_slots = asyncio.Semaphore(max(1, settings.max_concurrent_investigations))

    def spawn(coro, name: str) -> None:
        """Run a fire-and-forget task while keeping a reference and logging failures."""
        task = asyncio.create_task(coro, name=name)
        background_tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            background_tasks.discard(t)
            if not t.cancelled() and t.exception():
                log.error("background_task_failed", task=name, error=str(t.exception()))
        task.add_done_callback(_done)

    async def run_investigation(llm_context: dict) -> None:
        iid = llm_context["incident_id"]
        try:
            async with investigation_slots:
                log.info("pipeline_mode_activated", incident_id=iid)
                await forensic_plan_mgr.run_full_investigation(
                    incident_id=iid,
                    context=llm_context,
                    evidence_path=settings.forensic_evidence_base,
                )
        finally:
            investigating.discard(iid)

    # ── SAP event processor (stages 1-4, ordered) ─────────────────────────
    async def process_event(topic: str, event: dict) -> None:
        """SAP pipeline: parse → enrich → correlate → incident."""
        # Stage 1: Morpho-semantic analysis
        text_content = _extract_text(topic, event)
        analysis = None
        if text_content and len(text_content) > 10:
            try:
                analysis = await asyncio.to_thread(parser.analyze, text_content)
            except Exception as e:
                log.error("morpho_error", error=str(e))

        # Stage 2: Graph enrichment
        await enricher.enrich(topic, event, analysis)

        # Stage 3: Correlation
        correlation = await correlator.correlate(topic, event)

        # Stage 4: Incident trigger (new incident or severity escalation)
        llm_context = await incident_mgr.maybe_create_incident(topic, event, correlation)
        if llm_context:
            await analysis_queue.put(llm_context)

    # ── LLM analysis + verification (stage 5, parallel workers) ───────────
    async def analyze_incident(llm_context: dict) -> None:
        iid = llm_context["incident_id"]

        # Paladin 2.0: Pipeline Mode — forensic investigation runs alongside
        if (llm_context.get("forensic_mode") == "pipeline" and forensic_plan_mgr
                and iid not in investigating):
            investigating.add(iid)
            spawn(run_investigation(llm_context), name=f"investigation-{iid}")

        await analyzer.analyze(llm_context)

    def _extract_text(topic: str, event: dict) -> str:
        if topic == "logs":
            return event.get("details", "")
        elif topic == "emails":
            return f"{event.get('subject', '')} {event.get('body', '')}"
        elif topic == "messages":
            return event.get("text", "")
        elif topic == "calls":
            return event.get("transcript", "")
        return ""

    # ── Consumers ─────────────────────────────────────────────────────────
    async def event_consumer():
        log.info("event_consumer_started")
        while True:
            topic, event = await event_queue.get()
            try:
                await process_event(topic, event)
            except Exception as e:
                log.error("consumer_error", error=str(e), topic=topic)
            finally:
                event_queue.task_done()

    async def analysis_worker(n: int):
        log.info("analysis_worker_started", worker=n)
        while True:
            llm_context = await analysis_queue.get()
            try:
                await analyze_incident(llm_context)
            except Exception as e:
                log.error("analysis_worker_error", worker=n, error=str(e))
            finally:
                analysis_queue.task_done()

    # ── Scenario handler ─────────────────────────────────────────────────
    async def scenario_handler():
        from paladin.dummy.log_generator import LogGenerator
        from paladin.dummy.mail_generator import MailGenerator
        from paladin.dummy.chat_generator import ChatGenerator
        from paladin.dummy.call_generator import CallGenerator

        employee_uids = [e["uid"] for e in DUMMY_EMPLOYEES]
        generators = {
            "logs": LogGenerator(employee_uids),
            "emails": MailGenerator(DUMMY_EMPLOYEES),
            "messages": ChatGenerator(DUMMY_EMPLOYEES),
            "calls": CallGenerator(DUMMY_EMPLOYEES),
        }

        while True:
            req = await scenario_bus.get()
            try:
                if isinstance(req, dict) and req.get("type") == "scenario_trigger":
                    gen = generators.get(req["source"])
                    if gen:
                        params = {}
                        if req.get("actor_uid"):
                            # Insider scenarios name the employee actor_uid, attacks
                            # against an employee (brute force, phishing) target_uid
                            params["actor_uid"] = params["target_uid"] = req["actor_uid"]
                        await gen.generate_scenario(event_queue, req["scenario"], **params)
                        log.info("scenario_executed", scenario=req["scenario"])
                    else:
                        log.warning("scenario_unknown_source", source=req.get("source"))
            except Exception as e:
                log.error("scenario_error", error=str(e))

    # ── Dummy generators (background traffic) ─────────────────────────────
    async def start_dummy_generators():
        from paladin.dummy.log_generator import LogGenerator
        from paladin.dummy.mail_generator import MailGenerator
        from paladin.dummy.chat_generator import ChatGenerator
        from paladin.dummy.call_generator import CallGenerator

        employee_uids = [e["uid"] for e in DUMMY_EMPLOYEES]
        gens = [
            LogGenerator(employee_uids).generate_normal(event_queue, settings.dummy_events_per_minute),
            MailGenerator(DUMMY_EMPLOYEES).generate_normal(event_queue, 2),
            ChatGenerator(DUMMY_EMPLOYEES).generate_normal(event_queue, 3),
            CallGenerator(DUMMY_EMPLOYEES).generate_normal(event_queue, 0.5),
        ]
        await asyncio.gather(*gens)

    # ── Dashboard server ──────────────────────────────────────────────────
    async def run_dashboard():
        config = uvicorn.Config(
            dashboard_app,
            host=settings.dashboard_host,
            port=settings.dashboard_port,
            log_level="warning",
            ssl_keyfile="key.pem" if os.path.exists("key.pem") else None,
            ssl_certfile="cert.pem" if os.path.exists("cert.pem") else None,
        )
        server = uvicorn.Server(config)
        await server.serve()

    # ── Launch all ────────────────────────────────────────────────────────

    log.info("paladin_ready",
             dashboard=f"http://localhost:{settings.dashboard_port}",
             mode=settings.run_mode,
             auto_execute=settings.auto_execute_enabled,
             operator_timeout=settings.operator_timeout_seconds,
             llm_workers=settings.llm_workers)

    tasks = [
        asyncio.create_task(event_consumer()),
        asyncio.create_task(scenario_handler()),
        asyncio.create_task(run_dashboard()),
        asyncio.create_task(auto_exec.run()),
    ]
    tasks += [asyncio.create_task(analysis_worker(n))
              for n in range(max(1, settings.llm_workers))]

    if settings.run_mode == RunMode.DUMMY:
        tasks.append(asyncio.create_task(start_dummy_generators()))

    try:
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        log.info("paladin_shutdown", background_tasks=len(background_tasks))
        for t in [*tasks, *background_tasks]:
            t.cancel()
        await asyncio.gather(*tasks, *background_tasks, return_exceptions=True)
        await llm.stop()
        await neo4j.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
