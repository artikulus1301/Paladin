"""
Telegram bot via Aiogram 3.
Handles text messages, shows typing indicator, streams pipeline result.
"""
from __future__ import annotations

import asyncio
import html
from typing import Callable, Any, Awaitable

import structlog
from aiogram import Bot, Dispatcher, Router, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ChatAction
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, BotCommand, BotCommandScopeDefault
from aiogram.utils.markdown import hbold, hcode

from config.settings import settings
from app.pipeline.rag_pipeline import RAGPipeline, PipelineResult

log = structlog.get_logger(__name__)

router = Router()


# ── Access control middleware ──────────────────────────────────────────────────
class AccessMiddleware:
    async def __call__(
        self,
        handler: Callable[[Message, dict[str, Any]], Awaitable[Any]],
        event: Message,
        data: dict[str, Any],
    ) -> Any:
        allowed = settings.allowed_user_ids
        if allowed and event.from_user and event.from_user.id not in allowed:
            await event.answer("⛔ Access denied.")
            return
        return await handler(event, data)


# ── Commands ───────────────────────────────────────────────────────────────────
@router.message(CommandStart())
async def cmd_start(msg: Message) -> None:
    await msg.answer(
        f"👋 {hbold('RAG Knowledge Bot')}\n\n"
        "Задайте любой вопрос — я найду информацию в интернете, "
        "сохраню знания в граф Neo4j и верифицирую ответ.\n\n"
        f"{hbold('Команды:')}\n"
        "/start — это сообщение\n"
        "/status — статус компонентов\n"
        "/clear — очистить историю верификатора\n",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("status"))
async def cmd_status(msg: Message, pipeline: RAGPipeline) -> None:
    lines = ["⚙️ <b>System Status</b>\n"]
    # Quick Neo4j ping
    try:
        records = await pipeline.neo4j.search_relevant(
            pipeline.analyzer.analyze("test"), limit=1
        )
        lines.append("✅ Neo4j — online")
    except Exception as e:
        lines.append(f"❌ Neo4j — {e}")

    # Ollama ping
    try:
        await pipeline.llm.generate("ping", system="Reply with: pong")
        lines.append("✅ Ollama — online")
    except Exception as e:
        lines.append(f"❌ Ollama — {e}")

    lines.append(f"📊 Entropy history: {len(pipeline.verifier._entropy_history)} samples")
    await msg.answer("\n".join(lines), parse_mode=ParseMode.HTML)


@router.message(Command("clear"))
async def cmd_clear(msg: Message, pipeline: RAGPipeline) -> None:
    pipeline.verifier._entropy_history.clear()
    await msg.answer("🗑 Verifier history cleared.")


# ── Main query handler ─────────────────────────────────────────────────────────
@router.message(F.text)
async def handle_query(msg: Message, pipeline: RAGPipeline) -> None:
    user_id = msg.from_user.id if msg.from_user else 0
    query = msg.text.strip()

    if len(query) < 3:
        await msg.answer("Пожалуйста, введите более развёрнутый запрос.")
        return

    log.info("user_query", user_id=user_id, query=query[:80])

    # Send typing indicator
    await msg.bot.send_chat_action(msg.chat.id, ChatAction.TYPING)

    # Show progress message
    progress_msg = await msg.answer(
        "🔍 Анализирую запрос...\n"
        "⏳ Ищу в знаниях и интернете..."
    )

    try:
        result: PipelineResult = await pipeline.run(query)
        await _send_result(msg, progress_msg, result)
    except Exception as exc:
        log.exception("pipeline_error", error=str(exc))
        await progress_msg.edit_text(
            f"❌ Произошла ошибка при обработке запроса.\n"
            f"<code>{html.escape(str(exc)[:200])}</code>",
            parse_mode=ParseMode.HTML,
        )


async def _send_result(
    original: Message, progress_msg: Message, result: PipelineResult
) -> None:
    answer = result.answer.strip()

    # Build footer
    badges = []
    if result.used_graph:
        badges.append("🗃 Граф")
    if result.used_internet:
        badges.append("🌐 Интернет")
    if result.fallback_used:
        badges.append("⚠️ Fallback")
    if result.verification.passed:
        badges.append("✅ Верифицирован")
    else:
        badges.append("⚠️ Не верифицирован")

    footer = "  ·  ".join(badges)

    # Telegram has 4096 char limit — split if needed
    full_text = f"{answer}\n\n<i>{footer}</i>"
    chunks = _split_message(full_text, 4000)

    await progress_msg.edit_text(chunks[0], parse_mode=ParseMode.HTML)
    for chunk in chunks[1:]:
        await original.answer(chunk, parse_mode=ParseMode.HTML)


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
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )


def create_dispatcher(pipeline: RAGPipeline) -> Dispatcher:
    dp = Dispatcher()
    dp.message.middleware(AccessMiddleware())
    dp.include_router(router)

    # Inject pipeline into handler context
    dp["pipeline"] = pipeline
    return dp


async def set_commands(bot: Bot) -> None:
    cmds = [
        BotCommand(command="start", description="Приветствие и помощь"),
        BotCommand(command="status", description="Статус компонентов"),
        BotCommand(command="clear", description="Очистить историю верификатора"),
    ]
    await bot.set_my_commands(cmds, scope=BotCommandScopeDefault())
