"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        ⛨  PALADIN v2.0 — ПОЛНЫЙ ДЕМОНСТРАЦИОННЫЙ СКРИПТ                   ║
║        Комплексное демо всех возможностей системы для видеозаписи           ║
╚══════════════════════════════════════════════════════════════════════════════╝

ПОКРЫТИЕ ВОЗМОЖНОСТЕЙ:
  Layer 1 — Data Ingestion   : Logs / Emails / Chat / Calls (14 сценариев)
  Layer 2 — SAP Core         : MorphoParser, GraphEnricher, Correlator
  Layer 3 — LLM & Verifier   : Qwen 3.5:9B + ActionVerifier
  Layer 4 — Auto-Executor    : Autonomous режим (timeout=0)
  Layer 5 — Forensic v2.0   : SandboxManager, MCP Server, PlanManager,
                               CorrelationEngine, HallucinationTracker
  Layer 6 — Dashboard        : FastAPI + WebSocket + JWT

ИСПОЛЬЗОВАНИЕ:
  python demo_full_showcase.py [--phase PHASE] [--timeout SECS]

  --phase: all | ingestion | sap | llm | autonomous | forensic | dashboard
  --timeout: оператор timeout в секундах (default=5, для авто-демо)
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Путь к файлам улик Натали Романофф ────────────────────────────────────────
EVIDENCE_PATH = r"c:\Users\Lenovo\Downloads\win7-32-nromanoff-10.3.58.5"

DASHBOARD_URL = "https://localhost:8888"
API = DASHBOARD_URL + "/api"

# ── Цветовая палитра для терминала ────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BG_RED  = "\033[41m"
    BG_BLUE = "\033[44m"


# ── Утилиты форматирования ────────────────────────────────────────────────────

def banner(text: str, color: str = C.CYAN) -> None:
    width = 78
    print()
    print(color + "╔" + "═" * (width - 2) + "╗" + C.RESET)
    for line in text.strip().splitlines():
        padding = width - 4 - len(re.sub(r'\033\[[0-9;]*m', '', line))
        print(color + "║  " + C.RESET + line + " " * max(0, padding) + color + "  ║" + C.RESET)
    print(color + "╚" + "═" * (width - 2) + "╝" + C.RESET)
    print()


def section(title: str, icon: str = "▶", color: str = C.BLUE) -> None:
    width = 78
    print()
    print(color + C.BOLD + f"{'─' * 3} {icon}  {title} " + "─" * max(0, width - 7 - len(title)) + C.RESET)
    print()


def step(msg: str, status: str = "info") -> None:
    icons = {
        "info":    C.BLUE    + "[•]" + C.RESET,
        "ok":      C.GREEN   + "[✓]" + C.RESET,
        "warn":    C.YELLOW  + "[⚠]" + C.RESET,
        "error":   C.RED     + "[✗]" + C.RESET,
        "wait":    C.CYAN    + "[⏳]" + C.RESET,
        "attack":  C.RED + C.BOLD + "[🚨]" + C.RESET,
        "llm":     C.MAGENTA + "[🤖]" + C.RESET,
        "action":  C.YELLOW  + "[⚡]" + C.RESET,
        "forensic":C.GREEN   + "[🔬]" + C.RESET,
        "graph":   C.CYAN    + "[🕸]" + C.RESET,
        "auto":    C.RED + C.BOLD + "[🤖 AUTO]" + C.RESET,
    }
    icon = icons.get(status, "[•]")
    print(f"  {icon} {msg}")


def pause(secs: float, label: str = "") -> None:
    if label:
        print(f"  {C.DIM}  ⏱  {label} ({secs:.0f}с)...{C.RESET}", end="", flush=True)
    time.sleep(secs)
    if label:
        print(f" {C.GREEN}готово{C.RESET}")


# ── Системные проверки ────────────────────────────────────────────────────────

def check_port(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def detect_ollama() -> str:
    """Определить порт активного Ollama."""
    for port in [11434, 11435]:
        try:
            r = requests.get(f"http://localhost:{port}/api/tags", timeout=2)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                step(f"Ollama найден на порту {port}. Модели: {', '.join(models[:3])}", "ok")
                return f"http://localhost:{port}"
        except Exception:
            pass
    step("Ollama не найден! Убедитесь, что приложение запущено.", "error")
    return "http://localhost:11434"


def preflight_checks() -> dict:
    """Предполётная проверка всех сервисов."""
    section("ПРЕДПОЛЁТНЫЕ ПРОВЕРКИ", "🔍", C.YELLOW)
    results = {}

    # Ollama
    ollama_url = detect_ollama()
    results["ollama_url"] = ollama_url
    results["ollama_ok"] = ollama_url != "http://localhost:11434" or check_port(11434)

    # Neo4j
    neo4j_ok = check_port(7687)
    results["neo4j_ok"] = neo4j_ok
    step(f"Neo4j Bolt (7687): {'работает' if neo4j_ok else 'НЕ ЗАПУЩЕН'}", "ok" if neo4j_ok else "warn")

    # PostgreSQL
    pg_ok = check_port(5432)
    results["pg_ok"] = pg_ok
    step(f"PostgreSQL (5432): {'работает' if pg_ok else 'не запущен (forensic без PG)'}", "ok" if pg_ok else "warn")

    # Docker
    try:
        docker_r = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
        docker_ok = docker_r.returncode == 0
    except Exception:
        docker_ok = False
    results["docker_ok"] = docker_ok
    step(f"Docker: {'работает' if docker_ok else 'НЕ ЗАПУЩЕН (forensic sandbox будет пропущен)'}", "ok" if docker_ok else "warn")

    # Evidence files
    ev_ok = os.path.exists(EVIDENCE_PATH)
    results["evidence_ok"] = ev_ok
    if ev_ok:
        file_count = sum(1 for _ in __import__("pathlib").Path(EVIDENCE_PATH).rglob("*") if _.is_file())
        step(f"Улики nromanoff: {file_count} файлов в {EVIDENCE_PATH}", "ok")
    else:
        step(f"Папка улик не найдена: {EVIDENCE_PATH}", "warn")

    return results


# ── Запуск Paladin ────────────────────────────────────────────────────────────

def start_paladin(ollama_url: str, operator_timeout: int) -> subprocess.Popen:
    """Запустить главный процесс Paladin."""
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env["PYTHONUTF8"] = "1"
    env["OLLAMA_BASE_URL"] = ollama_url
    env["OPERATOR_TIMEOUT_SECONDS"] = str(operator_timeout)
    env["AUTO_EXECUTE_ENABLED"] = "true"
    env["FORENSIC_ENABLED"] = "true"
    env["FORENSIC_EVIDENCE_BASE"] = EVIDENCE_PATH
    env["PALADIN_MODE"] = "dummy"
    env["LOG_LEVEL"] = "WARNING"   # Только важные события в stdout оркестратора
    env["TELEGRAM_TOKEN"] = ""     # Отключаем Telegram бота во время демо, чтобы избежать ошибки валидации токена

    proc = subprocess.Popen(
        [sys.executable, "-m", "paladin.main"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    return proc


def wait_for_api(timeout_sec: int = 60) -> str | None:
    """Ждать готовности API и вернуть токен JWT."""
    step("Ожидание запуска API...", "wait")
    for i in range(timeout_sec // 2):
        try:
            r = requests.get(f"{API}/status", timeout=2, verify=False)
            if r.status_code in (200, 401, 403):
                step("Paladin API готов!", "ok")
                break
        except Exception:
            pass
        time.sleep(2)
        print(f"    {C.DIM}... ({i*2+2}/{timeout_sec}с){C.RESET}", end="\r")
    else:
        step("Не удалось подключиться к API.", "error")
        return None

    # Логин
    try:
        r = requests.post(f"{API}/login",
                          json={"username": "admin", "password": "admin"},
                          verify=False, timeout=5)
        if r.ok:
            token = r.json()["access_token"]
            step(f"JWT получен: {token[:20]}...", "ok")
            return token
    except Exception as e:
        step(f"Ошибка логина: {e}", "error")
    return None


def wait_for_demo_start(token: str) -> None:
    """Ждать сигнала старта из дэшборда."""
    banner("ОЖИДАНИЕ ЗАПУСКА ДЕМО ИЗ ДЭШБОРДА", C.MAGENTA)
    print(f"  {C.MAGENTA}Откройте {C.CYAN}{DASHBOARD_URL}{C.MAGENTA} и нажмите кнопку 'Start Showcase'.{C.RESET}")
    print()
    while True:
        try:
            r = requests.get(f"{API}/status", timeout=2, verify=False, headers={"Authorization": f"Bearer {token}"})
            if r.ok and r.json().get("demo_started", False):
                step("Сигнал на старт получен из дэшборда!", "ok")
                break
        except Exception:
            pass
        time.sleep(1)


# ── Phase 1: Ingestion — все 14 сценариев ────────────────────────────────────

ALL_SCENARIOS = [
    # (source, scenario, label, severity_icon)
    ("logs",     "brute_force",          "🔓 Brute Force Attack (Logs)",           "🔴"),
    ("logs",     "data_exfiltration",    "💾 Data Exfiltration (Logs)",             "🔴"),
    ("logs",     "insider_threat",       "🕵 Insider Threat (Logs)",                "🟠"),
    ("logs",     "privilege_escalation", "⬆️ Privilege Escalation (Logs)",          "🔴"),
    ("emails",   "phishing",             "📧 Phishing Campaign (Email)",             "🟠"),
    ("emails",   "data_leak_email",      "📤 Data Leak via Email",                  "🔴"),
    ("emails",   "social_engineering",   "🎭 Social Engineering (Email)",            "🟠"),
    ("emails",   "external_exfil",       "🌐 External Exfiltration (Email)",         "🔴"),
    ("messages", "insider_chat",         "💬 Insider Conspiracy (Chat)",             "🟠"),
    ("messages", "credential_sharing",   "🔑 Credential Sharing (Chat)",             "🔴"),
    ("messages", "competitor_contact",   "🏢 Competitor Contact (Chat)",             "🟡"),
    ("calls",    "data_theft_call",      "📞 Data Theft Call",                      "🔴"),
    ("calls",    "insider_recruitment",  "🤝 Insider Recruitment (Call)",            "🟠"),
    ("calls",    "bribery_call",         "💰 Bribery Attempt (Call)",               "🔴"),
]


def phase_ingestion(token: str, demo_mode: bool = False) -> None:
    """Демонстрация Layer 1: все 14 сценариев атак."""
    banner(
        "  LAYER 1 — DATA INGESTION\n"
        "  Запуск всех 14 встроенных сценариев атак:\n"
        "  Logs / Emails / Chats / Calls",
        C.RED
    )
    headers = {"Authorization": f"Bearer {token}"}

    # В demo_mode запускаем только 4 ключевых сценария для скорости
    scenarios = ALL_SCENARIOS if not demo_mode else [
        ALL_SCENARIOS[0],  # brute_force
        ALL_SCENARIOS[1],  # data_exfiltration
        ALL_SCENARIOS[4],  # phishing
        ALL_SCENARIOS[8],  # insider_chat
    ]

    for source, scenario, label, icon in scenarios:
        print(f"  {icon} Запуск сценария: {C.BOLD}{label}{C.RESET} ... ", end="", flush=True)
        try:
            r = requests.post(
                f"{API}/scenario",
                json={"scenario": scenario, "source": source},
                timeout=10, verify=False, headers=headers,
            )
            if r.status_code == 200:
                print(C.GREEN + "✓ отправлен в очередь" + C.RESET)
            else:
                print(C.YELLOW + f"⚠ статус {r.status_code}" + C.RESET)
        except Exception as e:
            print(C.RED + f"✗ {e}" + C.RESET)
        time.sleep(0.5)

    step("Все сценарии поставлены в очередь на обработку.", "ok")


# ── Phase 2: SAP Core — показ корреляции ─────────────────────────────────────

def phase_sap_demo() -> None:
    """Объяснение работы SAP: MorphoParser + GraphEnricher + Correlator."""
    banner(
        "  LAYER 2 — SAP CORE\n"
        "  MorphoParser → GraphEnricher → Correlator → IncidentManager\n"
        "  Паттерны корреляции: 6 детекторов",
        C.BLUE
    )

    patterns = [
        ("clearance_violation",      "+0.35", "Доступ к файлам выше уровня допуска"),
        ("off_hours_activity",       "+0.15", "Активность в нерабочее время (00–06)"),
        ("cross_channel_correlation","+0.40", "Аномалии сразу по нескольким каналам"),
        ("mass_download",            "+0.50", "Скачивание более 3 файлов за 60 мин"),
        ("external_sensitive_comms", "+0.40", "Внешние коммуникации с чувств. данными"),
        ("brute_force",              "+0.60", "5+ неудачных попыток входа за 15 мин"),
    ]

    section("Корреляционные паттерны", "🕸", C.CYAN)
    for name, score, desc in patterns:
        print(f"    {C.CYAN}{name:<30}{C.RESET} {C.YELLOW}{score:<8}{C.RESET} {desc}")

    print()
    section("Маршрутизация по серьёзности", "⚙", C.BLUE)
    routing = [
        ("< 0.65",  "Tool Mode",     "Быстрый inline-анализ LLM"),
        ("≥ 0.65",  "Pipeline Mode", "Полная криминалистическая цепочка (v2.0)"),
        ("≥ 0.70",  "INCIDENT",      "Создание инцидента + действие LLM"),
        ("≥ 0.90",  "CRITICAL",      "Немедленная изоляция / блокировка"),
    ]
    for threshold, mode, desc in routing:
        color = C.RED if "0.90" in threshold else C.YELLOW if "0.70" in threshold else C.GREEN
        print(f"    Score {color}{threshold:<8}{C.RESET} → {C.BOLD}{mode:<16}{C.RESET} {desc}")


# ── Phase 3: LLM + Verifier — мониторинг в реальном времени ──────────────────

def phase_llm_monitor(token: str, watch_seconds: int = 90) -> dict:
    """Мониторинг появления инцидентов и LLM-ответов."""
    banner(
        "  LAYER 3 — LLM & VERIFIER\n"
        f"  Мониторинг {watch_seconds}с: Qwen 3.5:9B анализирует инциденты\n"
        "  ActionVerifier: level check + protected entities + entropy/perplexity",
        C.MAGENTA
    )

    headers = {"Authorization": f"Bearer {token}"}
    seen_incidents: dict[str, str] = {}  # id → stage
    found_incidents = {}

    section("Ожидание инцидентов...", "👁", C.MAGENTA)

    deadline = time.time() + watch_seconds
    last_dot = time.time()

    while time.time() < deadline:
        try:
            r = requests.get(f"{API}/incidents", timeout=3, verify=False, headers=headers)
            incidents = r.json().get("incidents", []) if r.ok else []
        except Exception:
            incidents = []

        for inc in incidents:
            iid = inc["incident_id"]
            sev = inc.get("severity", "?")
            status = inc.get("action_status", "")
            icon_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            sev_icon = icon_map.get(sev, "⚪")

            # Новый инцидент
            if iid not in seen_incidents:
                seen_incidents[iid] = "new"
                found_incidents[iid] = inc
                score = inc.get("score", 0)
                f_mode = inc.get("forensic_mode", "tool")
                f_label = (C.GREEN + "⚗ PIPELINE" + C.RESET) if f_mode == "pipeline" else (C.DIM + "🔧 tool" + C.RESET)
                print(f"\n  {sev_icon} {C.BOLD}НОВЫЙ ИНЦИДЕНТ{C.RESET} {C.CYAN}{iid}{C.RESET}")
                print(f"     Название  : {inc.get('title', '—')}")
                print(f"     Серьёзность: {C.BOLD}{sev}{C.RESET} | Score: {C.YELLOW}{score}{C.RESET}")
                print(f"     Forensic   : {f_label}")
                print(f"     Участники  : {', '.join(inc.get('involved', []))}")

            # LLM заключение появилось
            if inc.get("llm_summary") and seen_incidents.get(iid) == "new":
                seen_incidents[iid] = "llm"
                summary = (inc.get("llm_summary") or "")[:200].replace("\n", " ")
                action = inc.get("action_proposed", "?")
                action_color = {
                    "ISOLATE": C.RED, "BLOCK": C.RED,
                    "FLAG": C.YELLOW, "REVOKE_SESSIONS": C.YELLOW,
                    "NOTIFY": C.CYAN, "READ": C.DIM,
                }.get(action, C.WHITE)
                print(f"\n  {C.MAGENTA}🤖 LLM ОТВЕТ{C.RESET} [{iid}]")
                print(f"     Анализ  : {summary}...")
                print(f"     Действие: {action_color}{C.BOLD}{action}{C.RESET}")
                if status == "pending":
                    step(f"Статус: PENDING — ожидание оператора или auto-execute...", "wait")

            # Авто-исполнение
            if "auto_executed" in status and seen_incidents.get(iid) not in ("auto", "manual"):
                seen_incidents[iid] = "auto" if "timeout" in status else "manual"
                note = (inc.get("operator_note") or "")[:120]
                print(f"\n  {C.RED}{C.BOLD}⚡ АВТО-ИСПОЛНЕНО{C.RESET} [{iid}]")
                print(f"     Действие: {inc.get('action_proposed', '?')}")
                print(f"     Статус  : {status}")
                print(f"     Примечание: {note}")
                found_incidents[iid] = inc

        # Прогресс-точки
        if time.time() - last_dot > 5:
            last_dot = time.time()
            remaining = int(deadline - time.time())
            print(f"  {C.DIM}  ⏱ {remaining}с до следующей фазы | инцидентов: {len(seen_incidents)}{C.RESET}")

        time.sleep(2)

    step(f"Итого зафиксировано инцидентов: {len(seen_incidents)}", "ok")
    return found_incidents


# ── Phase 4: Autonomous Mode — демонстрация timeout ──────────────────────────

def phase_autonomous(token: str) -> None:
    """Демонстрация автономного режима."""
    banner(
        "  LAYER 4 — AUTO-EXECUTOR\n"
        "  Autonomous Mode: оператор timeout = 5с → немедленное исполнение\n"
        "  Human-in-the-Loop: оператор может одобрить/отклонить вручную",
        C.YELLOW
    )
    headers = {"Authorization": f"Bearer {token}"}

    section("Ручное переключение режима через API", "🔄", C.YELLOW)

    # Переключить в автономный режим
    try:
        r = requests.post(f"{API}/config/mode",
                          json={"mode": "autonomous"},
                          timeout=5, verify=False, headers=headers)
        if r.ok:
            step("Режим переключён: AUTONOMOUS (instant auto-execute)", "ok")
        else:
            step(f"Переключение режима: статус {r.status_code}", "warn")
    except Exception as e:
        step(f"Ошибка переключения: {e}", "warn")

    # Запустить критический сценарий для демонстрации
    step("Запуск критического сценария data_exfiltration...", "attack")
    try:
        r = requests.post(f"{API}/scenario",
                          json={"scenario": "data_exfiltration", "source": "logs"},
                          timeout=10, verify=False, headers=headers)
        step(f"Сценарий отправлен: {r.status_code}", "ok" if r.ok else "warn")
    except Exception as e:
        step(f"Ошибка: {e}", "error")

    pause(3, "ожидание LLM")

    section("Статус авто-исполненных инцидентов", "⚡", C.RED)
    try:
        r = requests.get(f"{API}/incidents", timeout=5, verify=False, headers=headers)
        incidents = r.json().get("incidents", []) if r.ok else []
        auto_count = sum(1 for i in incidents if "auto_executed" in i.get("action_status", ""))
        step(f"Авто-исполнено инцидентов: {auto_count}", "auto")
        for inc in incidents:
            if "auto_executed" in inc.get("action_status", ""):
                print(f"    • {inc['incident_id']} | {inc.get('severity')} | {inc.get('action_proposed')} ← {inc.get('action_status')}")
    except Exception as e:
        step(f"Ошибка запроса: {e}", "warn")


# ── Phase 5: Forensic Pipeline v2.0 ──────────────────────────────────────────

async def phase_forensic(ollama_url: str, use_evidence: bool = True) -> None:
    """Демонстрация полного forensic pipeline v2.0."""
    banner(
        "  LAYER 5 — FORENSIC INVESTIGATION v2.0\n"
        "  Incident → ForensicPlanManager → SIFT MCP Server → Sandbox\n"
        "  → CorrelationEngine → HallucinationTracker → AccuracyReport",
        C.GREEN
    )

    # Настройка окружения
    os.environ["OLLAMA_BASE_URL"] = ollama_url
    os.environ["FORENSIC_EVIDENCE_BASE"] = EVIDENCE_PATH if use_evidence else "/tmp/demo_evidence"
    os.environ["OLLAMA_TIMEOUT"] = "600"

    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

    section("Инициализация компонентов Forensic Layer", "⚙", C.GREEN)

    try:
        from paladin.config.settings import settings
        from paladin.graph.neo4j_client import Neo4jClient
        from paladin.llm.ollama_client import OllamaClient
        from paladin.forensic.action_verifier import ForensicActionVerifier
        from paladin.forensic.sandbox_manager import SandboxManager
        from paladin.forensic.mcp_server import SIFTMCPServer
        from paladin.forensic.pg_store import ForensicPGStore
        from paladin.forensic.plan_manager import ForensicPlanManager
        from paladin.forensic.correlation_engine import CorrelationEngine
        from paladin.forensic.hallucination_tracker import HallucinationTracker
    except ImportError as e:
        step(f"Ошибка импорта Paladin: {e}", "error")
        step("Убедитесь что запущено из директории проекта с PYTHONPATH=.", "warn")
        return

    # Neo4j
    neo4j = Neo4jClient()
    step("Подключение к Neo4j...", "wait")
    try:
        await neo4j.connect()
        await neo4j.seed_organization()
    except Exception as e:
        step(f"Neo4j недоступен: {e}", "error")
        step("Запустите: docker-compose -f docker-compose.paladin.yml up -d neo4j", "warn")
        return
    step("Neo4j подключён, организация инициализирована.", "ok")

    # Создаём сотрудника-субъекта расследования
    emp = {
        "uid": "emp-nromanoff",
        "full_name": "Natalie Romanoff",
        "email": "n.romanoff@corp.paladin.local",
        "department": "Engineering",
        "role": "Senior Developer",
        "manager_uid": "emp-005"
    }
    await neo4j.upsert_employee(emp)
    step(f"Субъект расследования: {emp['full_name']} ({emp['department']})", "ok")

    # LLM
    llm = OllamaClient()
    step("Запуск OllamaClient...", "wait")
    await llm.start()
    step(f"LLM готов: Qwen 3.5:9B @ {ollama_url}", "ok")

    # Forensic компоненты
    verifier = ForensicActionVerifier()
    sandbox = SandboxManager()
    pg = ForensicPGStore()

    try:
        await pg.initialize(settings.postgres_dsn)
        step("PostgreSQL Forensic Store инициализирован.", "ok")
    except Exception as e:
        step(f"PG Store недоступен (memory-only режим): {e}", "warn")
        pg = None

    # Счётчики для статистики
    stats = {
        "steps_total": 0,
        "steps_done": 0,
        "findings": 0,
        "contradictions": 0,
        "corrections": 0,
    }

    # Callback для событий в реальном времени
    async def live_broadcast(event: dict) -> None:
        ev = event.get("type", "")
        if ev == "forensic_plan_created":
            stats["steps_total"] = event.get("todo_count", 0)
            print()
            step(
                f"План создан: {event['plan_id'][:20]}... | "
                f"Шагов расследования: {C.YELLOW}{event['todo_count']}{C.RESET}",
                "forensic"
            )
        elif ev == "todo_item_updated":
            new_status = event.get("new_status", "")
            if new_status == "DONE":
                stats["steps_done"] += 1
                pct = int(stats["steps_done"] / max(stats["steps_total"], 1) * 100)
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                print(f"  {C.GREEN}  [{bar}] {pct}%{C.RESET}  Шаг {event['item_id'][:20]}... → DONE", end="\r")
        elif ev == "finding_added":
            stats["findings"] += 1
            print()
            step(
                f"Находка #{stats['findings']}: {event['description'][:80]} "
                f"(confidence={C.YELLOW}{event['confidence']}%{C.RESET})",
                "forensic"
            )
        elif ev == "contradiction_detected":
            stats["contradictions"] += 1
            print()
            step(
                f"ПРОТИВОРЕЧИЕ #{stats['contradictions']}: "
                f"{event['finding_id_a'][:15]} ↔ {event['finding_id_b'][:15]}",
                "warn"
            )
        elif ev == "self_correction_triggered":
            stats["corrections"] += 1
            step(
                f"Self-Correction #{stats['corrections']}: "
                f"итерация {event['iteration_count']}/{event['max_iterations']} — {event.get('recheck_reason', '')[:60]}",
                "warn"
            )
        elif ev == "plan_completed":
            print()
            hallucination_rate = event.get("hallucination_rate", 0)
            hr_color = C.RED if hallucination_rate > 0.3 else C.GREEN
            step(
                f"РАССЛЕДОВАНИЕ ЗАВЕРШЕНО | "
                f"Статус: {C.BOLD}{event['status']}{C.RESET} | "
                f"Находок: {event['total_findings']} | "
                f"Hallucination rate: {hr_color}{hallucination_rate * 100:.1f}%{C.RESET}",
                "ok"
            )

    # Создание MCP сервера и Plan Manager
    mcp = SIFTMCPServer(sandbox, verifier, pg)

    section("Доступные MCP функции SIFT", "🔧", C.GREEN)
    mcp_funcs = mcp.get_available_functions() if hasattr(mcp, "get_available_functions") else [
        "get_file_metadata", "compute_hash", "extract_strings",
        "analyze_process_list", "scan_network_connections", "extract_loaded_modules",
        "parse_mft", "parse_prefetch", "extract_registry_hive",
        "parse_pcap", "extract_browser_artifacts",
    ]
    for i, fn in enumerate(mcp_funcs, 1):
        print(f"    {i:2}. {C.CYAN}{fn}{C.RESET}")

    plan_mgr = ForensicPlanManager(
        neo4j=neo4j, llm=llm, mcp_server=mcp,
        sandbox=sandbox, pg_store=pg,
        broadcast_fn=live_broadcast
    )

    section("Создание тестового инцидента CRITICAL", "🚨", C.RED)

    incident_id = "INC-NROMANOFF-FULLSHOWCASE"
    context = {
        "incident_id": incident_id,
        "title": "Natalie Romanoff Workstation Compromise — Full Showcase",
        "severity": "CRITICAL",
        "score": 0.97,
        "description": (
            "Критический инцидент: признаки lateral movement, кражи учётных данных "
            "и возможного заражения вредоносным ПО на рабочей станции "
            "Natalie Romanoff (10.3.58.5). Прилагаются дамп памяти и образ диска C:."
        ),
        "involved_employees": ["emp-nromanoff"],
    }

    step(f"Инцидент: {incident_id}", "attack")
    step(f"Серьёзность: CRITICAL | Score: {context['score']}", "attack")

    # Очистка предыдущего состояния
    async with neo4j._driver.session() as s:
        await s.run("MATCH (n {incident_id: $iid}) DETACH DELETE n", iid=incident_id)
        await s.run("MATCH (n {plan_id: $iid}) DETACH DELETE n", iid=incident_id)

    subprocess.run(
        ["docker", "rm", "-f", f"sift-sandbox-{incident_id}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    await neo4j.create_incident(context)
    step("Инцидент создан в Neo4j.", "ok")

    section("Запуск Forensic Pipeline", "🔬", C.GREEN)
    step("Pipeline: Sandbox → MCP → LLM Plans → Self-Correction → Correlation...", "forensic")

    evidence_path = EVIDENCE_PATH if os.path.exists(EVIDENCE_PATH) else None
    if not evidence_path:
        step(f"Папка улик не найдена ({EVIDENCE_PATH}), forensic запустится без реальных файлов.", "warn")

    try:
        plan_id = await plan_mgr.run_full_investigation(
            incident_id=incident_id,
            context=context,
            evidence_path=evidence_path or "/tmp/empty",
        )
        print()
        step(f"Forensic Pipeline завершён. Plan ID: {plan_id}", "ok")

        # ── Correlation Engine ───────────────────────────────────────────────
        section("Correlation Engine — Cross-Source Detection", "🔀", C.CYAN)
        correlation_engine = CorrelationEngine(neo4j, broadcast_fn=live_broadcast)
        try:
            correlations = await correlation_engine.run(plan_id)
            if correlations:
                for corr in correlations:
                    print(f"    • {C.YELLOW}{corr.get('type', '?')}{C.RESET}: {corr.get('description', '')[:80]}")
            else:
                step("Противоречий между источниками не найдено.", "ok")
        except Exception as e:
            step(f"Correlation Engine: {e}", "warn")

        # ── Hallucination Tracker ────────────────────────────────────────────
        section("Hallucination Tracker — Accuracy Report", "🎯", C.MAGENTA)
        hallucination_tracker = HallucinationTracker(neo4j, pg)
        try:
            report = await hallucination_tracker.generate_accuracy_report(plan_id)
            total = report.get("total_findings", 0)
            verified = report.get("verified_findings", 0)
            hr = report.get("hallucination_rate", 0.0)
            hr_color = C.RED if hr > 0.3 else C.YELLOW if hr > 0.1 else C.GREEN

            print(f"    Всего находок    : {total}")
            print(f"    Верифицированных : {C.GREEN}{verified}{C.RESET}")
            print(f"    Hallucination    : {hr_color}{hr * 100:.1f}%{C.RESET}")
            print(f"    Метод верификации: exact / case-insensitive / semantic (70%+ overlap)")
        except Exception as e:
            step(f"Hallucination Tracker: {e}", "warn")

    except Exception as e:
        step(f"Ошибка forensic pipeline: {e}", "error")
        import traceback
        traceback.print_exc()

    await llm.stop()
    await neo4j.close()

    # Итоговая статистика
    section("Forensic Summary", "📊", C.GREEN)
    print(f"    Шагов расследования : {stats['steps_total']}")
    print(f"    Выполнено шагов     : {stats['steps_done']}")
    print(f"    Находок             : {stats['findings']}")
    print(f"    Противоречий        : {stats['contradictions']}")
    print(f"    Self-corrections    : {stats['corrections']}")


# ── Phase 6: Dashboard — демонстрация API ─────────────────────────────────────

def phase_dashboard(token: str) -> None:
    """Демонстрация всех API endpoints."""
    banner(
        "  LAYER 6 — DASHBOARD & API\n"
        f"  {DASHBOARD_URL}\n"
        "  FastAPI + WebSocket + JWT + TLS",
        C.CYAN
    )
    headers = {"Authorization": f"Bearer {token}"}

    endpoints = [
        ("GET",  "/api/status",             "System Health Check"),
        ("GET",  "/api/incidents",           "List Open Incidents"),
        ("POST", "/api/config/mode",         "Toggle Autonomous/HITL Mode"),
        ("GET",  "/api/graph/INC-SAMPLE",   "Incident Subgraph"),
        ("POST", "/api/scenario",            "Trigger Test Scenario"),
    ]

    section("Проверка API Endpoints", "🌐", C.CYAN)
    for method, endpoint, desc in endpoints:
        url = DASHBOARD_URL + endpoint
        try:
            if method == "GET":
                r = requests.get(url, timeout=3, verify=False, headers=headers)
            else:
                r = requests.post(url, json={}, timeout=3, verify=False, headers=headers)
            status_icon = C.GREEN + "✓" + C.RESET if r.status_code < 400 else C.YELLOW + "⚠" + C.RESET
            print(f"  {status_icon} {method:<4} {endpoint:<35} HTTP {r.status_code}  {C.DIM}{desc}{C.RESET}")
        except Exception as e:
            print(f"  {C.DIM}  ✗ {method:<4} {endpoint:<35} Error: {str(e)[:40]}{C.RESET}")

    section("WebSocket Real-Time Stream", "📡", C.CYAN)
    step(f"WebSocket endpoint: wss://localhost:8888/ws", "ok")
    step("Поддерживаемые типы событий:", "info")
    ws_events = [
        "incident_created     — новый инцидент зафиксирован",
        "incident_updated     — LLM завершил анализ",
        "auto_executed        — действие автономно исполнено",
        "forensic_plan_*      — обновления криминалистического плана",
        "finding_added        — новая криминалистическая находка",
    ]
    for ev in ws_events:
        print(f"      • {C.CYAN}{ev}{C.RESET}")

    section("Forensic API Endpoints (v2.0)", "🔬", C.GREEN)
    forensic_endpoints = [
        ("GET",  "/api/forensic/plan/{plan_id}",             "ForensicPlan + TodoItems + Findings"),
        ("GET",  "/api/forensic/incident/{incident_id}",     "Plan for Incident"),
        ("GET",  "/api/forensic/accuracy/{plan_id}",         "Accuracy Report"),
        ("POST", "/api/forensic/plan/{plan_id}/approve",     "Approve Pending Action"),
    ]
    for method, endpoint, desc in forensic_endpoints:
        print(f"  {C.GREEN}✓{C.RESET} {method:<4} {endpoint:<45} {C.DIM}{desc}{C.RESET}")

    print()
    step(f"Dashboard доступен по адресу: {C.CYAN}{DASHBOARD_URL}{C.RESET}", "ok")
    step("Credentials: admin / admin", "info")


# ── Phase 7: Security Architecture — 4 границы защиты ───────────────────────

def phase_security_architecture() -> None:
    """Демонстрация архитектуры безопасности."""
    banner(
        "  SECURITY ARCHITECTURE — DEFENSE IN DEPTH\n"
        "  4 слоя защиты Forensic Layer",
        C.RED
    )

    boundaries = [
        (
            "#1 ForensicActionVerifier",
            "Программный фильтр",
            ["SAFE / REQUIRES_APPROVAL / FORBIDDEN классификация",
             "Обнаружение Shell-инъекций: ; && | ` $()",
             "Предотвращение Path Traversal (../)",
             "Default-Deny политика"]
        ),
        (
            "#2 MCP Server API Surface",
            "Ограничение поверхности атаки",
            ["Только 11 read-only функций",
             "Нет rm, dd, chmod, mkfs, shell-доступа",
             "Строго типизированные Pydantic модели",
             "LLM никогда не получает сырой shell-вывод"]
        ),
        (
            "#3 Sandbox Filesystem",
            "Изоляция на уровне ядра",
            ["/evidence монтируется с флагом :ro",
             "OS-уровневый запрет записи",
             "--read-only контейнер",
             "tmpfs для временных файлов"]
        ),
        (
            "#4 Sandbox Network",
            "Сетевая изоляция Docker",
            ["network: none — нет входящих/исходящих",
             "Нет DNS, нет C2 эксфильтрации",
             "--cap-drop ALL",
             "--pids-limit 256, CPU/RAM лимиты"]
        ),
    ]

    for boundary, mechanism, details in boundaries:
        print(f"\n  {C.RED}┌─ Граница {boundary}{C.RESET}")
        print(f"  {C.RED}│{C.RESET}  Механизм: {C.YELLOW}{mechanism}{C.RESET}")
        for d in details:
            print(f"  {C.RED}│{C.RESET}  • {d}")
        print(f"  {C.RED}└{'─' * 60}{C.RESET}")


# ── Phase 8: Neo4j Graph Schema ───────────────────────────────────────────────

def phase_graph_schema() -> None:
    """Демонстрация схемы графа Neo4j."""
    banner(
        "  NEO4J GRAPH SCHEMA\n"
        "  16 типов узлов, 25+ типов рёбер",
        C.CYAN
    )

    node_labels = [
        ("Employee",       "Core", "Сотрудник: UID, dept, clearance"),
        ("Device",         "Core", "Рабочая станция, сервер"),
        ("File",           "Core", "Файловые артефакты"),
        ("IPAddress",      "Core", "IP-адреса (внутренние/внешние)"),
        ("Email",          "Core", "Корпоративные письма"),
        ("Message",        "Core", "Сообщения в мессенджерах"),
        ("Call",           "Core", "Транскрипты звонков"),
        ("LogEvent",       "Core", "Системные/app логи"),
        ("Incident",       "Core", "Коррелированные инциденты"),
        ("Department",     "Org",  "Подразделения компании"),
        ("Role",           "Org",  "Должности"),
        ("ClearanceLevel", "Org",  "Уровни допуска"),
        ("ForensicPlan",   "Forensic", "План расследования v2.0"),
        ("TodoItem",       "Forensic", "Шаг расследования"),
        ("Finding",        "Forensic", "Криминалистическая находка"),
        ("ToolExecution",  "Forensic", "Лог выполнения MCP-инструмента"),
    ]

    section("Узлы (Node Labels)", "🔵", C.CYAN)
    for label, domain, desc in node_labels:
        domain_color = C.CYAN if domain == "Core" else C.YELLOW if domain == "Org" else C.GREEN
        print(f"    {domain_color}{label:<20}{C.RESET} [{domain:<8}] {desc}")

    key_rels = [
        ("SENT_EMAIL",        "Employee → Email"),
        ("USES_DEVICE",       "Employee → Device"),
        ("ACCESSED_FILE",     "Employee → File"),
        ("INVOLVED_IN",       "Employee → Incident"),
        ("HAS_FORENSIC_PLAN", "Incident → ForensicPlan"),
        ("PRODUCED",          "ForensicPlan → Finding"),
        ("CONTRADICTS",       "Finding ↔ Finding"),
        ("HAS_VERSION",       "ForensicPlan → ForensicPlan (snapshot)"),
    ]

    section("Ключевые рёбра (Relationships)", "🔗", C.CYAN)
    for rel, connects in key_rels:
        print(f"    {C.YELLOW}[:{rel}]{C.RESET:<35} {connects}")


# ── Главная функция ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Paladin v2.0 — Полный демонстрационный скрипт"
    )
    parser.add_argument(
        "--phase",
        choices=["all", "checks", "ingestion", "sap", "llm", "autonomous",
                 "forensic", "dashboard", "security", "schema"],
        default="all",
        help="Какую фазу запустить (default: all)"
    )
    parser.add_argument(
        "--timeout",
        type=int, default=5,
        help="Operator timeout в секундах (default=5 для авто-демо)"
    )
    parser.add_argument(
        "--watch",
        type=int, default=90,
        help="Сколько секунд мониторить инциденты в фазе LLM (default=90)"
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Не запускать Paladin (уже запущен)"
    )
    parser.add_argument(
        "--no-forensic",
        action="store_true",
        help="Пропустить forensic pipeline (долгое ожидание LLM)"
    )
    args = parser.parse_args()

    # ── Заставка ──────────────────────────────────────────────────────────────
    banner(
        f"  ⛨  PALADIN v2.0 — AUTONOMOUS CORPORATE SECURITY SYSTEM\n"
        f"  Полный демонстрационный скрипт для видеозаписи\n"
        f"  Фаза: {args.phase.upper()} | Operator Timeout: {args.timeout}s\n"
        f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        C.CYAN
    )

    # ── Предполётные проверки ─────────────────────────────────────────────────
    checks = preflight_checks()
    ollama_url = checks["ollama_url"]

    # ── Только schema / sap / security — не нужен запущенный Paladin ─────────
    standalone_phases = {"sap", "security", "schema"}

    if args.phase in standalone_phases:
        if args.phase == "sap":
            phase_sap_demo()
        elif args.phase == "security":
            phase_security_architecture()
        elif args.phase == "schema":
            phase_graph_schema()
        return

    # ── Forensic-only фаза ────────────────────────────────────────────────────
    if args.phase == "forensic":
        if not args.no_forensic:
            asyncio.run(phase_forensic(ollama_url))
        else:
            step("Forensic фаза пропущена (--no-forensic).", "warn")
        return

    # ── Запуск Paladin ────────────────────────────────────────────────────────
    paladin_proc = None
    token = None

    if not args.no_start:
        section("Запуск Paladin Orchestrator", "🚀", C.GREEN)
        paladin_proc = start_paladin(ollama_url, args.timeout)
        step(f"Paladin запущен (PID={paladin_proc.pid})", "ok")
        token = wait_for_api(timeout_sec=60)
        if not token:
            step("Не удалось получить токен. Завершение.", "error")
            if paladin_proc:
                paladin_proc.terminate()
            sys.exit(1)
        wait_for_demo_start(token)
    else:
        # Уже запущен — просто логинимся
        section("Подключение к уже запущенному Paladin", "🔗", C.GREEN)
        token = wait_for_api(timeout_sec=20)
        if not token:
            step("Не удалось подключиться к API.", "error")
            sys.exit(1)
        wait_for_demo_start(token)

    step(f"Dashboard: {DASHBOARD_URL}", "ok")

    try:
        # ── Фазы демо ─────────────────────────────────────────────────────────
        run_all = args.phase == "all"

        if run_all or args.phase == "schema":
            phase_graph_schema()
            pause(2)

        if run_all or args.phase == "sap":
            phase_sap_demo()
            pause(2)

        if run_all or args.phase == "security":
            phase_security_architecture()
            pause(2)

        if run_all or args.phase == "ingestion":
            phase_ingestion(token, demo_mode=(args.phase == "all"))
            pause(3, "очередь обрабатывается")

        if run_all or args.phase == "llm":
            found_incidents = phase_llm_monitor(token, watch_seconds=args.watch)
            pause(2)

        if run_all or args.phase == "autonomous":
            phase_autonomous(token)
            pause(3)

        if (run_all or args.phase == "dashboard"):
            phase_dashboard(token)
            pause(2)

        if (run_all or args.phase == "forensic") and not args.no_forensic:
            asyncio.run(phase_forensic(ollama_url))

        # ── Финальный итог ────────────────────────────────────────────────────
        banner(
            "  ✅  ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА\n"
            "  Все слои системы Paladin v2.0 продемонстрированы.\n"
            f"  Dashboard: {DASHBOARD_URL}  |  admin / admin",
            C.GREEN
        )

        if paladin_proc:
            step("Paladin продолжает работать. Нажмите Ctrl+C для остановки.", "info")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    except KeyboardInterrupt:
        banner("  ⏹  ДЕМО ПРЕРВАНО ПОЛЬЗОВАТЕЛЕМ", C.YELLOW)
    finally:
        if paladin_proc:
            step("Останавливаем Paladin...", "wait")
            paladin_proc.terminate()
            try:
                paladin_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                paladin_proc.kill()
            step("Paladin остановлен.", "ok")


if __name__ == "__main__":
    main()
