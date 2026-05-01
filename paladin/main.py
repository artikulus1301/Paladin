"""
Paladin — Main entry point and orchestrator.
Wires all layers together and starts the system.
"""
from __future__ import annotations

import asyncio
import random
import sys
import uuid
from datetime import datetime, timezone

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


async def main() -> None:
    log.info("paladin_startup", mode=settings.run_mode, model=settings.ollama_model)

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
    from paladin.llm.prompts import SYSTEM_PROMPT, build_incident_prompt, parse_llm_response
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
    verifier = ActionVerifier()

    # ── Layer: Auto-Executor ──────────────────────────────────────────────
    from paladin.sap.auto_executor import AutoExecutor
    from paladin.dashboard.api import broadcast_incident
    auto_exec = AutoExecutor(neo4j, broadcast_fn=broadcast_incident)

    # ── Layer: Dashboard ──────────────────────────────────────────────────
    from paladin.dashboard.api import app as dashboard_app, init_dashboard
    scenario_bus: asyncio.Queue = asyncio.Queue()
    init_dashboard(neo4j, scenario_bus, auto_exec)

    # ── Queues (replace Kafka in dummy mode) ──────────────────────────────
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    # ── SAP event processor ───────────────────────────────────────────────
    async def process_event(topic: str, event: dict) -> None:
        """SAP pipeline: parse → enrich → correlate → incident → LLM → verify."""
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

        # Stage 4: Incident trigger
        llm_context = await incident_mgr.maybe_create_incident(topic, event, correlation)
        if not llm_context:
            return

        # ── LLM notification ──────────────────────────────────────────
        try:
            prompt = build_incident_prompt(llm_context)
            llm_response = await llm.generate(prompt, system=SYSTEM_PROMPT)
            parsed = parse_llm_response(llm_response)

            # ── Verification ──────────────────────────────────────────
            verification = verifier.verify_action(
                proposed_action=parsed["action"],
                severity=llm_context["severity"],
                target_entities=llm_context["involved_employees"],
                llm_response=llm_response,
            )

            if verification.action_check.approved:
                await neo4j.update_incident(llm_context["incident_id"], {
                    "llm_summary": parsed["summary"],
                    "action_proposed": parsed["action"],
                    "action_status": "pending",
                })
                log.info("incident_processed",
                         id=llm_context["incident_id"],
                         action=parsed["action"],
                         approved=True)
            else:
                # Retry with feedback
                log.warning("action_rejected", reason=verification.action_check.reason)
                await neo4j.update_incident(llm_context["incident_id"], {
                    "llm_summary": parsed["summary"] + f"\n\n[VERIFIER REJECTED: {verification.action_check.reason}]",
                    "action_proposed": "NOTIFY",
                    "action_status": "auto_executed",
                })

            # Broadcast to dashboard
            await broadcast_incident({
                "incident_id": llm_context["incident_id"],
                "title": llm_context["title"],
                "severity": llm_context["severity"],
                "score": llm_context["score"],
                "action": parsed["action"],
            })

        except Exception as e:
            log.error("llm_pipeline_error", error=str(e), incident=llm_context["incident_id"])
            await neo4j.update_incident(llm_context["incident_id"], {
                "llm_summary": f"LLM processing error: {e}",
                "action_proposed": "NOTIFY",
                "action_status": "error",
            })

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

    # ── Event consumer loop ───────────────────────────────────────────────
    async def event_consumer():
        log.info("event_consumer_started")
        while True:
            try:
                topic, event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                await process_event(topic, event)
                event_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error("consumer_error", error=str(e))

    # ── Scenario handler ─────────────────────────────────────────────────
    async def scenario_handler():
        from paladin.dummy.log_generator import LogGenerator
        from paladin.dummy.mail_generator import MailGenerator
        from paladin.dummy.chat_generator import ChatGenerator
        from paladin.dummy.call_generator import CallGenerator

        employee_uids = [e["uid"] for e in DUMMY_EMPLOYEES]
        log_gen = LogGenerator(employee_uids)
        mail_gen = MailGenerator(DUMMY_EMPLOYEES)
        chat_gen = ChatGenerator(DUMMY_EMPLOYEES)
        call_gen = CallGenerator(DUMMY_EMPLOYEES)

        generators = {
            "logs": log_gen, "emails": mail_gen,
            "messages": chat_gen, "calls": call_gen,
        }

        while True:
            try:
                req = await asyncio.wait_for(scenario_bus.get(), timeout=1.0)
                if isinstance(req, dict) and req.get("type") == "scenario_trigger":
                    gen = generators.get(req["source"])
                    if gen:
                        params = {}
                        if req.get("actor_uid"):
                            params["actor_uid"] = req["actor_uid"]
                        await gen.generate_scenario(event_queue, req["scenario"], **params)
                        log.info("scenario_executed", scenario=req["scenario"])
            except asyncio.TimeoutError:
                continue
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
        )
        server = uvicorn.Server(config)
        await server.serve()

    # ── Launch all ────────────────────────────────────────────────────────

    log.info("paladin_ready",
             dashboard=f"http://localhost:{settings.dashboard_port}",
             mode=settings.run_mode,
             auto_execute=settings.auto_execute_enabled,
             operator_timeout=settings.operator_timeout_seconds)

    tasks = [
        asyncio.create_task(event_consumer()),
        asyncio.create_task(scenario_handler()),
        asyncio.create_task(run_dashboard()),
        asyncio.create_task(auto_exec.run()),
    ]

    if settings.run_mode == RunMode.DUMMY:
        tasks.append(asyncio.create_task(start_dummy_generators()))

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        pass
    finally:
        log.info("paladin_shutdown")
        await llm.stop()
        await neo4j.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
