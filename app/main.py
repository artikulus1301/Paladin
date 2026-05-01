"""
Application entrypoint.
Initialises all services, wires DI, and starts the Aiogram polling loop.
"""
from __future__ import annotations

import asyncio
import sys

import structlog
from aiogram import Bot

from config.settings import settings
from app.pipeline.spacy_analyzer import SpaCyAnalyzer
from app.graph.neo4j_client import Neo4jClient
from app.agent.internet_agent import InternetAgent
from app.pipeline.ollama_client import OllamaClient
from app.verifier.verifier import AnswerVerifier
from app.pipeline.rag_pipeline import RAGPipeline
from app.bot import create_bot, create_dispatcher, set_commands

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


async def main() -> None:
    log.info("startup", model=settings.ollama_model)

    # ── Initialise services ────────────────────────────────────────────────────
    neo4j = Neo4jClient()
    await neo4j.connect()

    agent = InternetAgent()
    await agent.start()

    llm = OllamaClient()
    await llm.start()

    analyzer = SpaCyAnalyzer()  # lazy-loads model on first call
    verifier = AnswerVerifier()

    pipeline = RAGPipeline(
        analyzer=analyzer,
        neo4j=neo4j,
        agent=agent,
        llm=llm,
        verifier=verifier,
    )

    # ── Telegram bot ───────────────────────────────────────────────────────────
    bot: Bot = create_bot()
    dp = create_dispatcher(pipeline)
    await set_commands(bot)

    log.info("bot_starting", polling=True)
    try:
        await dp.start_polling(bot, allowed_updates=["message"])
    finally:
        log.info("shutdown")
        await agent.stop()
        await llm.stop()
        await neo4j.close()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
