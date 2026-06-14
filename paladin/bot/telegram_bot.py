"""
Paladin Telegram Bot — Security Operations Assistant.
Connects to Neo4j and Ollama to answer operator queries
about incidents, employees, and system status.
"""
from __future__ import annotations

import asyncio
import html
from typing import Callable, Any, Awaitable, Optional

import structlog
from aiogram import Bot, Dispatcher, Router, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ChatAction
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, BotCommand, BotCommandScopeDefault

from paladin.config.settings import settings

log = structlog.get_logger(__name__)

router = Router()

# ── System prompt for the security analyst LLM ────────────────────────────────

TELEGRAM_SYSTEM_PROMPT = """You are Paladin Security Assistant — an AI assistant for a corporate security operations team.
You have access to real-time data from the Paladin security monitoring system.

Rules:
1. Answer concisely and factually based on the provided context data.
2. If asked about incidents, employees, or system status — use the context provided.
3. If the context has no relevant data, say so honestly.
4. Use emoji for visual clarity: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW.
5. Respond in the same language as the user's question (Russian or English).
6. Format output for Telegram (keep it readable, use line breaks).
7. Do not invent data that is not in the context.
"""


# ── Access control middleware ──────────────────────────────────────────────────

class AccessMiddleware:
    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        allowed = settings.telegram_allowed_user_ids
        if allowed and event.from_user and event.from_user.id not in allowed:
            await event.answer("⛔ Access denied. Your user ID is not authorized.")
            return
        return await handler(event, data)


# ── Commands ───────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def cmd_start(msg: Message) -> None:
    await msg.answer(
        "🛡️ <b>Paladin Security Assistant</b>\n\n"
        "I am the Paladin security system AI assistant.\n"
        "You can ask me questions about active incidents, "
        "employees, or the system status.\n\n"
        "<b>Commands:</b>\n"
        "/start — show this help message\n"
        "/status — show system component status\n"
        "/incidents — list active incidents\n"
        "/ask &lt;question&gt; — ask the LLM security advisor\n\n"
        "Or simply type your question below.",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("status"))
async def cmd_status(msg: Message, neo4j: Any, llm: Any) -> None:
    lines = ["⚙️ <b>Paladin System Status</b>\n"]

    # Neo4j ping
    try:
        await neo4j.get_open_incidents(limit=1)
        lines.append("✅ Neo4j — online")
    except Exception as e:
        lines.append(f"❌ Neo4j — {html.escape(str(e)[:100])}")

    # Ollama ping
    try:
        await llm.generate("ping", system="Reply with: pong")
        lines.append("✅ Ollama — online")
    except Exception as e:
        lines.append(f"❌ Ollama — {html.escape(str(e)[:100])}")

    lines.append(f"\n🔧 Mode: <code>{settings.run_mode.value}</code>")
    lines.append(f"🤖 Model: <code>{settings.ollama_model}</code>")
    lines.append(f"⚡ Auto-execute: <code>{settings.auto_execute_enabled}</code>")
    lines.append(f"⏱ Operator timeout: <code>{settings.operator_timeout_seconds}s</code>")

    await msg.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@router.message(Command("incidents"))
async def cmd_incidents(msg: Message, neo4j: Any) -> None:
    await msg.bot.send_chat_action(msg.chat.id, ChatAction.TYPING)

    try:
        incidents = await neo4j.get_open_incidents(limit=10)
    except Exception as e:
        await msg.answer(f"❌ Error fetching incidents: {html.escape(str(e)[:200])}")
        return

    if not incidents:
        await msg.answer("✅ No active incidents.")
        return

    lines = [f"🚨 <b>Active Incidents ({len(incidents)})</b>\n"]
    for inc in incidents:
        sev = inc.get("severity", "?")
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "🟢")
        status = inc.get("action_status", "?")
        involved = ", ".join(inc.get("involved", [])[:3])
        if len(inc.get("involved", [])) > 3:
            involved += f" +{len(inc['involved']) - 3}"

        lines.append(
            f"{icon} <b>{html.escape(inc.get('title', '?'))}</b>\n"
            f"   ID: <code>{inc.get('incident_id', '?')}</code>\n"
            f"   Severity: {sev} | Score: {inc.get('score', 0)}\n"
            f"   Action: {inc.get('action_proposed', '—')} ({status})\n"
            f"   Involved: {html.escape(involved) if involved else '—'}\n"
        )

    full_text = "\n".join(lines)
    for chunk in _split_message(full_text, 4000):
        await msg.answer(chunk, parse_mode=ParseMode.HTML)


# ── Free-text query handler ───────────────────────────────────────────────────

@router.message(F.text)
async def handle_query(msg: Message, neo4j: Any, llm: Any) -> None:
    query = msg.text.strip()

    # Skip very short messages
    if len(query) < 3:
        await msg.answer("Please provide a more detailed query.")
        return

    user_id = msg.from_user.id if msg.from_user else 0
    log.info("telegram_query", user_id=user_id, query=query[:80])

    await msg.bot.send_chat_action(msg.chat.id, ChatAction.TYPING)

    # ── Gather context from Neo4j ──────────────────────────────────────────
    context_parts = []

    # Active incidents
    try:
        incidents = await neo4j.get_open_incidents(limit=15)
        if incidents:
            inc_lines = []
            for inc in incidents:
                sev = inc.get("severity", "?")
                involved = ", ".join(inc.get("involved", []))
                summary = (inc.get("llm_summary") or "")[:200]
                inc_lines.append(
                    f"- [{sev}] {inc.get('title', '?')} | Score: {inc.get('score', 0)} | "
                    f"Action: {inc.get('action_proposed', '—')} ({inc.get('action_status', '?')}) | "
                    f"Involved: {involved}\n  Summary: {summary}"
                )
            context_parts.append(
                f"=== ACTIVE INCIDENTS ({len(incidents)}) ===\n" + "\n".join(inc_lines)
            )
        else:
            context_parts.append("=== ACTIVE INCIDENTS ===\nNo active incidents.")
    except Exception as e:
        log.warning("incidents_fetch_error", error=str(e))
        context_parts.append(f"=== ACTIVE INCIDENTS ===\nError fetching: {e}")

    # Recent action log
    try:
        actions = await neo4j.get_action_log(limit=10)
        if actions:
            act_lines = []
            for act in actions:
                act_lines.append(
                    f"- {act.get('action', '?')} on {act.get('title', '?')} "
                    f"[{act.get('severity', '?')}] — status: {act.get('status', '?')}"
                )
            context_parts.append(
                "=== RECENT ACTIONS ===\n" + "\n".join(act_lines)
            )
    except Exception as e:
        log.warning("actions_fetch_error", error=str(e))

    # System info
    context_parts.append(
        f"=== SYSTEM INFO ===\n"
        f"Mode: {settings.run_mode.value}\n"
        f"Auto-execute: {settings.auto_execute_enabled}\n"
        f"Operator timeout: {settings.operator_timeout_seconds}s\n"
        f"LLM Model: {settings.ollama_model}"
    )

    context = "\n\n".join(context_parts)

    # ── Ask LLM ────────────────────────────────────────────────────────────
    prompt = (
        f"Operator question: {query}\n\n"
        f"=== PALADIN SYSTEM CONTEXT ===\n{context}\n\n"
        f"Answer the operator's question based on the above real-time system data."
    )

    try:
        answer = await llm.generate(prompt, system=TELEGRAM_SYSTEM_PROMPT)
        answer = answer.strip()
        if not answer:
            answer = "⚠️ LLM returned an empty response. Please try rephrasing your question."
    except Exception as e:
        log.error("llm_error", error=str(e))
        answer = f"❌ LLM Error: {html.escape(str(e)[:300])}"

    for chunk in _split_message(answer, 4000):
        await msg.answer(chunk)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _split_message(text: str, limit: int = 4000) -> list[str]:
    if len(text) <= limit:
        return [text]
    parts = []
    while text:
        parts.append(text[:limit])
        text = text[limit:]
    return parts


# ── Bot factory ────────────────────────────────────────────────────────────────

def create_bot() -> Bot:
    return Bot(
        token=settings.telegram_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


def create_dispatcher(neo4j: Any, llm: Any) -> Dispatcher:
    dp = Dispatcher()
    dp.message.middleware(AccessMiddleware())
    dp.include_router(router)

    # Inject dependencies into handler context
    dp["neo4j"] = neo4j
    dp["llm"] = llm
    return dp


async def set_commands(bot: Bot) -> None:
    cmds = [
        BotCommand(command="start", description="Welcome and help message"),
        BotCommand(command="status", description="Paladin system status"),
        BotCommand(command="incidents", description="List of active incidents"),
    ]
    await bot.set_my_commands(cmds, scope=BotCommandScopeDefault())
