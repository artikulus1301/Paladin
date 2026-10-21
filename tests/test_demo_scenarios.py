"""
Every scenario in the dashboard picker, run through the real generators and the
real SAP pipeline (parser → enricher → correlator → incident manager → analyzer),
must raise an incident about the employee the presenter selected.
"""
import asyncio

import pytest

from paladin.dashboard.api import SCENARIOS
from test_attack_shadow_paladin import CompromisedLLM, Pipeline, ScenarioGraph

ACTOR = "emp-005"  # Sergei Volkov — chosen in the dashboard picker

CASES = [(source, scenario) for source, names in SCENARIOS.items() for scenario in sorted(names)]


def _generator(source):
    from paladin.dummy.call_generator import CallGenerator
    from paladin.dummy.chat_generator import ChatGenerator
    from paladin.dummy.log_generator import LogGenerator
    from paladin.dummy.mail_generator import MailGenerator
    from paladin.main import DUMMY_EMPLOYEES
    return {
        "logs": lambda: LogGenerator([e["uid"] for e in DUMMY_EMPLOYEES]),
        "emails": lambda: MailGenerator(DUMMY_EMPLOYEES),
        "messages": lambda: ChatGenerator(DUMMY_EMPLOYEES),
        "calls": lambda: CallGenerator(DUMMY_EMPLOYEES),
    }[source]()


@pytest.fixture(scope="module")
def parser():
    from paladin.sap.morpho_parser import MorphoParser
    return MorphoParser()


@pytest.mark.parametrize("text", [
    "Sure, use these creds: admin / Pr0d_DB_2025!",
    "my password: Hunter2024",
    "пароль = qwerty123",
    "login is svc_backup / Backup#2026x",
])
def test_plaintext_credentials_are_high_risk(parser, text):
    assert parser.analyze(text).text_risk_score >= 0.85


@pytest.mark.parametrize("text", [
    "path=/finance/Q3_Report-2026.xlsx size=15MB",
    "see https://corp.local/wiki/page2024",
    "Branch feature/AUTH-1234 merged",
    "Time: 2026-10-18T21:12:30Z",
    "Reset your password at https://portal/reset2024X",
    "Meeting at 10:30 in room 4/12",
])
def test_paths_urls_and_timestamps_are_not_credentials(parser, text):
    found = [t for t, _ in parser.analyze(text).security_terms_found]
    assert "plaintext credential" not in found and "username/password pair" not in found


@pytest.mark.parametrize("source,scenario", CASES, ids=[f"{s}:{n}" for s, n in CASES])
async def test_scenario_raises_incident_about_selected_employee(source, scenario, parser):
    queue: asyncio.Queue = asyncio.Queue()
    # Same parameters paladin.main's scenario handler passes for a selected employee
    await _generator(source).generate_scenario(queue, scenario, actor_uid=ACTOR, target_uid=ACTOR)
    assert not queue.empty(), "scenario produced no events"

    graph = ScenarioGraph()
    pipe = Pipeline(graph, CompromisedLLM(), parser)
    while not queue.empty():
        topic, event = queue.get_nowait()
        await pipe.ingest(topic, event)

    about_actor = [i for i in graph.incidents.values() if ACTOR in i.get("involved_employees", [])]
    assert about_actor, (f"no incident about {ACTOR}; incidents: "
                         f"{[(i['title'], i['involved_employees']) for i in graph.incidents.values()]}")
