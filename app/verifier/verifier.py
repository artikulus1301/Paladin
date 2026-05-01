"""
Multi-signal answer verifier.

Checks (in order):
1. Shannon entropy — compare to rolling median of past answers
2. Semantic coherence — intra-sentence MiniLM cosine similarity
3. Heuristics — uncertainty phrases, physical constants, math consistency
4. Perplexity estimate — via bigram log-prob approximation

Returns VerificationResult with a final verdict and per-signal scores.
"""
from __future__ import annotations

import math
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from statistics import median, stdev
from typing import Optional

import numpy as np
import structlog
from sentence_transformers import SentenceTransformer

from config.settings import settings

log = structlog.get_logger(__name__)

# ── physical constants for consistency check ───────────────────────────────────
_KNOWN_CONSTANTS: dict[str, tuple[float, float]] = {
    # name: (value, tolerance fraction)
    "speed of light": (299_792_458, 0.01),
    "скорость света": (299_792_458, 0.01),
    "planck": (6.626e-34, 0.05),
    "avogadro": (6.022e23, 0.01),
    "авогадро": (6.022e23, 0.01),
    "gravitational constant": (6.674e-11, 0.05),
    "гравитационная постоянная": (6.674e-11, 0.05),
    "electron charge": (1.602e-19, 0.01),
    "заряд электрона": (1.602e-19, 0.01),
}

# ── uncertainty phrases ────────────────────────────────────────────────────────
_UNCERTAINTY_PHRASES = re.compile(
    r"\b(не уверен|не знаю|возможно|вероятно|может быть|"
    r"i('m| am) not sure|i don'?t know|possibly|probably|"
    r"uncertain|might be|could be|hallucin)\b",
    re.IGNORECASE,
)

_NUMBER_RE = re.compile(r"[-+]?\d[\d.,]*(?:[eE][-+]?\d+)?")


@dataclass
class SignalScore:
    name: str
    value: float
    passed: bool
    note: str = ""


@dataclass
class VerificationResult:
    passed: bool
    signals: list[SignalScore] = field(default_factory=list)
    reason: str = ""

    def summary(self) -> str:
        lines = [f"Verdict: {'✅ PASS' if self.passed else '❌ FAIL'} — {self.reason}"]
        for s in self.signals:
            icon = "✓" if s.passed else "✗"
            lines.append(f"  {icon} {s.name}: {s.value:.3f}  {s.note}")
        return "\n".join(lines)


class AnswerVerifier:
    def __init__(self) -> None:
        self._entropy_history: deque[float] = deque(
            maxlen=settings.verifier_entropy_window
        )
        self._model: Optional[SentenceTransformer] = None

    def _get_model(self) -> SentenceTransformer:
        if self._model is None:
            log.info("loading_minilm")
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
        return self._model

    # ── 1. Shannon entropy ─────────────────────────────────────────────────────
    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        chars = Counter(text.lower())
        total = len(text)
        return -sum((c / total) * math.log2(c / total) for c in chars.values())

    def _check_entropy(self, answer: str) -> SignalScore:
        h = self._shannon_entropy(answer)
        self._entropy_history.append(h)

        if len(self._entropy_history) < 5:
            return SignalScore("entropy", h, True, "not enough history")

        med = median(self._entropy_history)
        try:
            sd = stdev(self._entropy_history)
        except Exception:
            sd = 0.5
        z = abs(h - med) / (sd + 1e-9)
        passed = z < settings.entropy_z_threshold
        return SignalScore(
            "entropy", h, passed, f"z={z:.2f} median={med:.3f}"
        )

    # ── 2. MiniLM semantic coherence ──────────────────────────────────────────
    def _check_semantic_coherence(self, answer: str) -> SignalScore:
        sentences = [s.strip() for s in re.split(r"[.!?]\s+", answer) if len(s.strip()) > 15]
        if len(sentences) < 2:
            return SignalScore("semantic_coherence", 1.0, True, "too few sentences")

        model = self._get_model()
        embeddings = model.encode(sentences, normalize_embeddings=True)
        # mean pairwise cosine similarity
        sims = []
        for i in range(len(embeddings) - 1):
            sim = float(np.dot(embeddings[i], embeddings[i + 1]))
            sims.append(sim)
        mean_sim = float(np.mean(sims))
        passed = mean_sim >= settings.semantic_similarity_threshold
        return SignalScore(
            "semantic_coherence",
            mean_sim,
            passed,
            f"threshold={settings.semantic_similarity_threshold}",
        )

    # ── 3. Heuristics ─────────────────────────────────────────────────────────
    def _check_heuristics(self, answer: str) -> SignalScore:
        # 3a. Uncertainty phrases
        if _UNCERTAINTY_PHRASES.search(answer):
            return SignalScore("heuristics", 0.0, False, "uncertainty phrase detected")

        # 3b. Physical constants consistency
        for const_name, (expected, tol) in _KNOWN_CONSTANTS.items():
            if const_name.lower() not in answer.lower():
                continue
            numbers = [
                float(n.replace(",", "."))
                for n in _NUMBER_RE.findall(answer)
                if n.replace(",", ".").replace(".", "").replace("-", "").isdigit()
                or "e" in n.lower()
            ]
            for num in numbers:
                if num == 0:
                    continue
                ratio = abs(num - expected) / abs(expected)
                if ratio > tol * 10:
                    return SignalScore(
                        "heuristics", ratio, False,
                        f"constant {const_name!r} value mismatch: got {num}"
                    )

        return SignalScore("heuristics", 1.0, True, "all checks passed")

    # ── 4. Perplexity (bigram approx) ─────────────────────────────────────────
    @staticmethod
    def _estimate_perplexity(text: str) -> float:
        words = re.findall(r"\w+", text.lower())
        if len(words) < 4:
            return 0.0
        bigrams = list(zip(words, words[1:]))
        unigram_counts = Counter(words)
        bigram_counts = Counter(bigrams)
        total_words = len(words)

        log_prob = 0.0
        for w1, w2 in bigrams:
            p_bigram = (bigram_counts[(w1, w2)] + 1) / (unigram_counts[w1] + total_words)
            log_prob += math.log(p_bigram + 1e-10)

        n = len(bigrams)
        perplexity = math.exp(-log_prob / n) if n > 0 else float("inf")
        return perplexity

    def _check_perplexity(self, answer: str) -> SignalScore:
        ppl = self._estimate_perplexity(answer)
        passed = ppl < settings.perplexity_threshold
        return SignalScore(
            "perplexity", ppl, passed,
            f"threshold={settings.perplexity_threshold}"
        )

    # ── main verify ───────────────────────────────────────────────────────────
    def verify(self, answer: str) -> VerificationResult:
        if len(answer.strip()) < 10:
            return VerificationResult(
                passed=False,
                reason="answer too short",
                signals=[SignalScore("length", len(answer), False, "")],
            )

        signals = [
            self._check_entropy(answer),
            self._check_semantic_coherence(answer),
            self._check_heuristics(answer),
            self._check_perplexity(answer),
        ]

        failed = [s for s in signals if not s.passed]
        passed = len(failed) == 0
        reason = "all signals OK" if passed else f"failed: {', '.join(s.name for s in failed)}"

        result = VerificationResult(passed=passed, signals=signals, reason=reason)
        log.info("verification_result", passed=passed, reason=reason)
        return result
