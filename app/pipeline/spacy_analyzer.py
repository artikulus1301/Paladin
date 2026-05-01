"""
SpaCy-based morphological and semantic analyzer.
Detects language, extracts entities, lemmas, noun chunks, and semantic triplets.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

import spacy
import structlog
from spacy.language import Language

log = structlog.get_logger(__name__)

# ── model registry ────────────────────────────────────────────────────────────
_MODELS = {
    "ru": "ru_core_news_sm",
    "en": "en_core_web_sm",
    "xx": "xx_ent_wiki_sm",
}


@lru_cache(maxsize=4)
def _load_model(lang: str) -> Language:
    model_name = _MODELS.get(lang, _MODELS["xx"])
    log.info("loading_spacy_model", model=model_name, lang=lang)
    return spacy.load(model_name)


# ── data classes ──────────────────────────────────────────────────────────────
@dataclass
class Entity:
    text: str
    label: str       # NER label (PERSON, ORG, GPE, …)
    lemma: str
    start: int
    end: int


@dataclass
class Triplet:
    """Semantic (subject, predicate, object) extracted from dependency tree."""
    subject: str
    predicate: str
    obj: str
    confidence: float = 1.0


@dataclass
class AnalysisResult:
    original: str
    language: str
    tokens: list[str]
    lemmas: list[str]
    entities: list[Entity]
    noun_chunks: list[str]
    triplets: list[Triplet]
    keywords: list[str]       # top lemmas for Neo4j search
    doc: object = field(default=None, repr=False)


# ── language detection ────────────────────────────────────────────────────────
_RU_RE = re.compile(r"[а-яёА-ЯЁ]")
_EN_RE = re.compile(r"[a-zA-Z]")


def _detect_language(text: str) -> str:
    ru = len(_RU_RE.findall(text))
    en = len(_EN_RE.findall(text))
    if ru > en:
        return "ru"
    if en > 0:
        return "en"
    return "xx"


# ── triplet extraction ────────────────────────────────────────────────────────
def _extract_triplets(doc) -> list[Triplet]:
    triplets: list[Triplet] = []
    for token in doc:
        # Pattern: nsubj → ROOT (verb) → dobj/attr/prep
        if token.dep_ in {"ROOT", "relcl"} and token.pos_ in {"VERB", "AUX"}:
            subj = _find_child(token, {"nsubj", "nsubjpass"})
            obj = _find_child(token, {"dobj", "attr", "pobj", "xcomp", "nmod"})
            if subj and obj:
                triplets.append(Triplet(
                    subject=_span_text(subj),
                    predicate=token.lemma_,
                    obj=_span_text(obj),
                ))
    return triplets


def _find_child(token, deps: set) -> Optional[object]:
    for child in token.children:
        if child.dep_ in deps:
            return child
    return None


def _span_text(token) -> str:
    return " ".join([t.text for t in token.subtree if not t.is_punct])


# ── keyword extraction ────────────────────────────────────────────────────────
_STOP_POS = {"AUX", "CCONJ", "SCONJ", "PUNCT", "SPACE", "DET"}


def _extract_keywords(doc, top_n: int = 10) -> list[str]:
    seen: set[str] = set()
    keywords: list[str] = []
    for token in doc:
        if token.is_stop or token.is_punct or token.pos_ in _STOP_POS:
            continue
        lemma = token.lemma_.lower().strip()
        if len(lemma) < 2 or lemma in seen:
            continue
        seen.add(lemma)
        keywords.append(lemma)
        if len(keywords) >= top_n:
            break
    return keywords


# ── main API ──────────────────────────────────────────────────────────────────
class SpaCyAnalyzer:
    """Thread-safe wrapper — delegates Russian to Natasha, other languages to SpaCy."""

    def __init__(self) -> None:
        self._natasha = None  # lazy-loaded on first Russian query

    def _get_natasha(self):
        if self._natasha is None:
            from app.pipeline.natasha_analyzer import NatashaAnalyzer
            self._natasha = NatashaAnalyzer()
        return self._natasha

    def analyze(self, text: str) -> AnalysisResult:
        lang = _detect_language(text)

        # ── Russian → Natasha (native support) ────────────────────────────────
        if lang == "ru":
            return self._get_natasha().analyze(text)

        # ── English / other → SpaCy ───────────────────────────────────────────
        nlp = _load_model(lang)
        doc = nlp(text)

        entities = [
            Entity(
                text=ent.text,
                label=ent.label_,
                lemma=ent.lemma_ if hasattr(ent, "lemma_") else ent.text.lower(),
                start=ent.start_char,
                end=ent.end_char,
            )
            for ent in doc.ents
        ]

        try:
            noun_chunks = list({chunk.text.lower() for chunk in doc.noun_chunks})
        except NotImplementedError:
            # Fallback for languages that do not implement noun_chunks (e.g., Russian)
            noun_chunks = []

        triplets = _extract_triplets(doc)
        keywords = _extract_keywords(doc)

        result = AnalysisResult(
            original=text,
            language=lang,
            tokens=[t.text for t in doc if not t.is_space],
            lemmas=[t.lemma_ for t in doc if not t.is_space],
            entities=entities,
            noun_chunks=noun_chunks,
            triplets=triplets,
            keywords=keywords,
            doc=doc,
        )
        log.debug(
            "analysis_done",
            lang=lang,
            n_entities=len(entities),
            n_triplets=len(triplets),
            keywords=keywords[:5],
        )
        return result
