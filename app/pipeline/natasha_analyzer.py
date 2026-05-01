"""
Natasha-based NLP analyzer for Russian text.
Provides morphology, NER, syntax parsing, noun chunk and triplet extraction
with native Russian language support.
"""
from __future__ import annotations

from typing import Optional

import structlog
from natasha import (
    Segmenter,
    MorphVocab,
    NewsEmbedding,
    NewsMorphTagger,
    NewsSyntaxParser,
    NewsNERTagger,
    NamesExtractor,
    Doc,
)

from app.pipeline.spacy_analyzer import AnalysisResult, Entity, Triplet

log = structlog.get_logger(__name__)

# ── Russian stop-words (compact set for keyword filtering) ─────────────────────
_RU_STOP_WORDS = frozenset({
    "и", "в", "во", "не", "что", "он", "на", "я", "с", "со", "как", "а",
    "то", "все", "она", "так", "его", "но", "да", "ты", "к", "у", "же",
    "вы", "за", "бы", "по", "только", "её", "мне", "было", "вот", "от",
    "меня", "ещё", "нет", "о", "из", "ему", "теперь", "когда", "даже",
    "ну", "вдруг", "ли", "если", "уже", "или", "ни", "быть", "был",
    "него", "до", "вас", "нибудь", "опять", "уж", "вам", "ведь", "там",
    "потом", "себя", "ничего", "ей", "может", "они", "тут", "где", "есть",
    "надо", "ней", "для", "мы", "тебя", "их", "чем", "была", "сам", "чтоб",
    "без", "будто", "чего", "раз", "тоже", "себе", "под", "будет", "ж",
    "тогда", "кто", "этот", "того", "потому", "этого", "какой", "совсем",
    "ним", "здесь", "этом", "один", "почти", "мой", "тем", "чтобы", "нее",
    "сейчас", "были", "куда", "зачем", "всех", "никогда", "можно", "при",
    "наконец", "два", "об", "другой", "хоть", "после", "над", "больше",
    "тот", "через", "эти", "нас", "про", "всего", "них", "какая", "много",
    "разве", "три", "эту", "моя", "впрочем", "хорошо", "свою", "этой",
    "перед", "иногда", "лучше", "чуть", "том", "нельзя", "такой", "им",
    "более", "всегда", "конечно", "всю", "между", "это", "быть",
})

_STOP_POS = {"AUX", "CCONJ", "SCONJ", "PUNCT", "SPACE", "DET", "ADP", "PART", "PRON"}

# Map Natasha NER labels to SpaCy-compatible labels
_NER_LABEL_MAP = {
    "PER": "PERSON",
    "LOC": "GPE",
    "ORG": "ORG",
}


class NatashaAnalyzer:
    """
    Russian-specialized NLP analyzer using the Natasha library.
    Initialises models once; thread-safe for read-only analysis.
    """

    def __init__(self) -> None:
        log.info("natasha_init_start")
        self._segmenter = Segmenter()
        self._morph_vocab = MorphVocab()
        self._emb = NewsEmbedding()
        self._morph_tagger = NewsMorphTagger(self._emb)
        self._syntax_parser = NewsSyntaxParser(self._emb)
        self._ner_tagger = NewsNERTagger(self._emb)
        self._names_extractor = NamesExtractor(self._morph_vocab)
        log.info("natasha_init_done")

    def analyze(self, text: str) -> AnalysisResult:
        """Full NLP analysis of Russian text using Natasha pipeline."""
        doc = Doc(text)

        # ── pipeline steps ─────────────────────────────────────────────────────
        doc.segment(self._segmenter)
        doc.tag_morph(self._morph_tagger)

        # Lemmatize each token
        for token in doc.tokens:
            token.lemmatize(self._morph_vocab)

        doc.parse_syntax(self._syntax_parser)
        doc.tag_ner(self._ner_tagger)

        # Normalise named entity spans
        for span in doc.spans:
            span.normalize(self._morph_vocab)

        # ── tokens & lemmas ────────────────────────────────────────────────────
        tokens = [t.text for t in doc.tokens if t.text.strip()]
        lemmas = [t.lemma for t in doc.tokens if t.text.strip() and t.lemma]

        # ── entities ───────────────────────────────────────────────────────────
        entities = []
        for span in doc.spans:
            label = _NER_LABEL_MAP.get(span.type, span.type)
            lemma = span.normal if span.normal else span.text.lower()
            entities.append(Entity(
                text=span.text,
                label=label,
                lemma=lemma,
                start=span.start,
                end=span.stop,
            ))

        # ── noun chunks (from syntax tree) ─────────────────────────────────────
        noun_chunks = self._extract_noun_chunks(doc)

        # ── triplets (subject-predicate-object from syntax tree) ───────────────
        triplets = self._extract_triplets(doc)

        # ── keywords ───────────────────────────────────────────────────────────
        keywords = self._extract_keywords(doc)

        result = AnalysisResult(
            original=text,
            language="ru",
            tokens=tokens,
            lemmas=lemmas,
            entities=entities,
            noun_chunks=noun_chunks,
            triplets=triplets,
            keywords=keywords,
            doc=doc,
        )

        log.debug(
            "natasha_analysis_done",
            n_entities=len(entities),
            n_triplets=len(triplets),
            n_noun_chunks=len(noun_chunks),
            keywords=keywords[:5],
        )
        return result

    # ── noun chunk extraction ──────────────────────────────────────────────────
    def _extract_noun_chunks(self, doc: Doc) -> list[str]:
        """
        Extract noun phrases from Natasha syntax tree.
        Groups NOUN/PROPN heads with their dependents (amod, det, nmod, case).
        """
        chunks: set[str] = set()

        for sent in doc.sents:
            # Build id→token lookup for this sentence
            token_map = {t.id: t for t in sent.tokens}

            for token in sent.tokens:
                if token.pos not in ("NOUN", "PROPN"):
                    continue

                # Collect this noun and its left dependents
                phrase_tokens = []
                for dep_token in sent.tokens:
                    if dep_token.head_id == token.id and dep_token.rel in (
                        "amod", "det", "nmod", "nummod", "case", "flat:name",
                        "flat", "appos",
                    ):
                        phrase_tokens.append(dep_token)

                phrase_tokens.append(token)

                # Sort by position in text
                phrase_tokens.sort(key=lambda t: t.start)
                chunk_text = " ".join(t.text for t in phrase_tokens).lower()

                if len(chunk_text) > 2:
                    chunks.add(chunk_text)

        return list(chunks)

    # ── triplet extraction ─────────────────────────────────────────────────────
    def _extract_triplets(self, doc: Doc) -> list[Triplet]:
        """
        Extract (subject, predicate, object) triplets from Natasha syntax tree.
        Looks for VERB roots with nsubj and obj/obl children.
        """
        triplets: list[Triplet] = []

        for sent in doc.sents:
            token_map = {t.id: t for t in sent.tokens}

            for token in sent.tokens:
                if token.pos not in ("VERB", "AUX"):
                    continue

                subj = self._find_dep(sent, token.id, {"nsubj", "nsubj:pass"})
                obj = self._find_dep(sent, token.id, {"obj", "obl", "iobj", "xcomp", "nmod"})

                if subj and obj:
                    subj_text = self._subtree_text(sent, subj)
                    obj_text = self._subtree_text(sent, obj)
                    predicate = token.lemma if token.lemma else token.text.lower()

                    triplets.append(Triplet(
                        subject=subj_text,
                        predicate=predicate,
                        obj=obj_text,
                    ))

        return triplets

    @staticmethod
    def _find_dep(sent, head_id: str, dep_rels: set[str]) -> Optional[object]:
        """Find first child token with matching dependency relation."""
        for token in sent.tokens:
            if token.head_id == head_id and token.rel in dep_rels:
                return token
        return None

    @staticmethod
    def _subtree_text(sent, root_token) -> str:
        """Collect all tokens in the subtree rooted at root_token."""
        subtree_ids: set[str] = {root_token.id}
        changed = True
        while changed:
            changed = False
            for token in sent.tokens:
                if token.head_id in subtree_ids and token.id not in subtree_ids:
                    subtree_ids.add(token.id)
                    changed = True

        subtree_tokens = sorted(
            [t for t in sent.tokens if t.id in subtree_ids],
            key=lambda t: t.start,
        )
        return " ".join(t.text for t in subtree_tokens if t.pos != "PUNCT")

    # ── keyword extraction ─────────────────────────────────────────────────────
    def _extract_keywords(self, doc: Doc, top_n: int = 10) -> list[str]:
        """Extract meaningful lemmas as keywords for Neo4j search."""
        seen: set[str] = set()
        keywords: list[str] = []

        for token in doc.tokens:
            if token.pos in _STOP_POS:
                continue
            lemma = (token.lemma or token.text).lower().strip()
            if len(lemma) < 2 or lemma in seen or lemma in _RU_STOP_WORDS:
                continue
            seen.add(lemma)
            keywords.append(lemma)
            if len(keywords) >= top_n:
                break

        return keywords
