"""
Main RAG pipeline orchestrator.
Ties together: SpaCy → Neo4j → InternetAgent → Neo4j save → Qwen → Verifier → Neo4j enrich
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

import structlog

from app.pipeline.spacy_analyzer import SpaCyAnalyzer, AnalysisResult
from app.graph.neo4j_client import Neo4jClient
from app.agent.internet_agent import InternetAgent, AgentResponse
from app.pipeline.ollama_client import OllamaClient
from app.verifier.verifier import AnswerVerifier, VerificationResult

log = structlog.get_logger(__name__)


@dataclass
class PipelineResult:
    answer: str
    verification: VerificationResult
    used_graph: bool
    used_internet: bool
    fallback_used: bool
    language: str


class RAGPipeline:
    def __init__(
        self,
        analyzer: SpaCyAnalyzer,
        neo4j: Neo4jClient,
        agent: InternetAgent,
        llm: OllamaClient,
        verifier: AnswerVerifier,
    ) -> None:
        self.analyzer = analyzer
        self.neo4j = neo4j
        self.agent = agent
        self.llm = llm
        self.verifier = verifier

    async def run(self, user_query: str) -> PipelineResult:
        log.info("pipeline_start", query=user_query[:80])

        # ── Step 1: SpaCy analysis ─────────────────────────────────────────────
        analysis: AnalysisResult = await asyncio.to_thread(
            self.analyzer.analyze, user_query
        )

        # ── Step 2: Neo4j search ───────────────────────────────────────────────
        graph_records = await self.neo4j.search_relevant(analysis)
        graph_context = self.neo4j.format_context(graph_records)
        used_graph = bool(graph_records)

        # ── Step 3: Internet search ────────────────────────────────────────────
        web_response: AgentResponse = await self.agent.search(user_query)
        web_context = web_response.combined_text
        used_internet = bool(web_response.results)

        # ── Step 4: Save new concepts to Neo4j (background) ───────────────────
        if web_response.results:
            asyncio.ensure_future(
                self._enrich_graph_from_web(analysis, web_response)
            )

        # ── Step 5: Generate answer with Qwen ─────────────────────────────────
        prompt = OllamaClient.build_rag_prompt(user_query, graph_context, web_context)
        answer = await self.llm.generate(prompt)

        # ── Step 6: Verify answer ──────────────────────────────────────────────
        verification = await asyncio.to_thread(self.verifier.verify, answer)
        fallback_used = False

        if not verification.passed:
            log.warning("verification_failed", reason=verification.reason)
            # Fallback: ask Qwen to reformat raw web content
            reformat_prompt = OllamaClient.build_reformat_prompt(
                user_query, web_context
            )
            answer = await self.llm.generate(
                reformat_prompt,
                system=(
                    "You are an editor. Rewrite the provided web content to directly "
                    "answer the user's question. Do not add extra information."
                ),
            )
            fallback_used = True

        # ── Step 7: Post-process answer through SpaCy and enrich Neo4j ─────────
        if fallback_used:
            asyncio.ensure_future(
                self._enrich_graph_from_answer(answer)
            )

        log.info(
            "pipeline_done",
            used_graph=used_graph,
            used_internet=used_internet,
            fallback=fallback_used,
            answer_len=len(answer),
        )

        return PipelineResult(
            answer=answer,
            verification=verification,
            used_graph=used_graph,
            used_internet=used_internet,
            fallback_used=fallback_used,
            language=analysis.language,
        )

    # ── background helpers ─────────────────────────────────────────────────────
    async def _enrich_graph_from_web(
        self, query_analysis: AnalysisResult, web_response: AgentResponse
    ) -> None:
        try:
            all_triplets = list(query_analysis.triplets)
            descriptions: dict[str, str] = {}

            for result in web_response.results:
                if not result.content:
                    continue
                page_analysis = await asyncio.to_thread(
                    self.analyzer.analyze, result.content[:3000]
                )
                all_triplets.extend(page_analysis.triplets)
                for ent in page_analysis.entities:
                    if ent.text not in descriptions:
                        descriptions[ent.text] = ent.lemma

            if all_triplets:
                await self.neo4j.save_concepts(
                    all_triplets, descriptions, source=web_response.results[0].url
                )
        except Exception as exc:
            log.error("graph_enrich_error", error=str(exc))

    async def _enrich_graph_from_answer(self, answer: str) -> None:
        try:
            analysis = await asyncio.to_thread(self.analyzer.analyze, answer)
            if analysis.triplets:
                await self.neo4j.save_concepts(
                    analysis.triplets, {}, source="llm_answer"
                )
        except Exception as exc:
            log.error("graph_enrich_answer_error", error=str(exc))
