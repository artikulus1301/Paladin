"""
Paladin Action Verifier — extended from Richter.
Richter checked answer quality (entropy, semantics, perplexity).
Paladin checks ACTION ADMISSIBILITY:
  1. Action exists in the allowed list
  2. Action level matches incident severity
  3. Action is not directed at protected accounts/infrastructure
If any check fails → reject and request LLM alternative.
Also retains Richter's answer quality checks for LLM output validation.
"""
from __future__ import annotations

import math
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from statistics import median, stdev
from typing import Optional

import structlog

from paladin.config.settings import settings
from paladin.verifier.action_registry import (
    ACTIONS, ActionDefinition, ActionLevel,
    get_action, get_max_action_level,
)

log = structlog.get_logger(__name__)


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ActionCheckResult:
    """Result of action admissibility verification."""
    approved: bool
    action: str
    level: str
    reason: str
    requires_confirmation: bool = False
    timeout_minutes: Optional[int] = None


@dataclass
class QualitySignal:
    name: str
    value: float
    passed: bool
    note: str = ""


@dataclass
class VerificationResult:
    """Combined action + quality verification."""
    action_check: ActionCheckResult
    quality_signals: list[QualitySignal] = field(default_factory=list)
    overall_passed: bool = True
    reason: str = ""

    def summary(self) -> str:
        lines = []
        # Action check
        icon = "✅" if self.action_check.approved else "❌"
        lines.append(f"{icon} Action: {self.action_check.action} — {self.action_check.reason}")
        if self.action_check.requires_confirmation:
            lines.append(f"   ⚠️ Requires operator confirmation (timeout: {self.action_check.timeout_minutes}min)")
        # Quality signals
        for s in self.quality_signals:
            si = "✓" if s.passed else "✗"
            lines.append(f"  {si} {s.name}: {s.value:.3f}  {s.note}")
        return "\n".join(lines)


class ActionVerifier:
    """
    Verifies both action admissibility and LLM response quality.
    """

    def __init__(self) -> None:
        self._entropy_history: deque[float] = deque(
            maxlen=settings.verifier_entropy_window
        )

    def verify_action(
        self,
        proposed_action: str,
        severity: str,
        target_entities: list[str],
        llm_response: str,
    ) -> VerificationResult:
        """
        Full verification pipeline:
        1. Check action exists
        2. Check action level vs severity
        3. Check protected entities
        4. Check LLM response quality
        """
        # ── Step 1: Action exists? ────────────────────────────────────────────
        action_def = get_action(proposed_action)
        if action_def is None:
            action_check = ActionCheckResult(
                approved=False,
                action=proposed_action,
                level="UNKNOWN",
                reason=f"Action '{proposed_action}' does not exist in registry. "
                       f"Allowed: {list(ACTIONS.keys())}",
            )
            return VerificationResult(
                action_check=action_check,
                overall_passed=False,
                reason="invalid_action",
            )

        # ── Step 2: Action level vs severity ──────────────────────────────────
        max_level = get_max_action_level(severity)
        if action_def.level > max_level:
            action_check = ActionCheckResult(
                approved=False,
                action=proposed_action,
                level=action_def.level.name,
                reason=(
                    f"Action {proposed_action} (level={action_def.level.name}) "
                    f"exceeds maximum for severity {severity} "
                    f"(max={max_level.name})"
                ),
            )
            return VerificationResult(
                action_check=action_check,
                overall_passed=False,
                reason="action_level_exceeded",
            )

        # ── Step 3: Protected entities ────────────────────────────────────────
        protected = settings.protected_account_list
        targeted_protected = [e for e in target_entities if e in protected]
        if targeted_protected and action_def.level >= ActionLevel.FLAG:
            action_check = ActionCheckResult(
                approved=False,
                action=proposed_action,
                level=action_def.level.name,
                reason=(
                    f"Cannot apply {proposed_action} to protected entities: "
                    f"{targeted_protected}"
                ),
            )
            return VerificationResult(
                action_check=action_check,
                overall_passed=False,
                reason="protected_entity",
            )

        # ── Action approved ───────────────────────────────────────────────────
        action_check = ActionCheckResult(
            approved=True,
            action=proposed_action,
            level=action_def.level.name,
            reason=f"Action {proposed_action} approved for severity {severity}",
            requires_confirmation=action_def.requires_confirmation,
            timeout_minutes=action_def.timeout_minutes,
        )

        # ── Step 4: LLM response quality ─────────────────────────────────────
        quality_signals = self._check_quality(llm_response)
        quality_passed = all(s.passed for s in quality_signals)

        return VerificationResult(
            action_check=action_check,
            quality_signals=quality_signals,
            overall_passed=True,  # Action is the primary gate
            reason="approved" if quality_passed else "approved_with_quality_warnings",
        )

    # ── Quality checks (from Richter) ─────────────────────────────────────────

    def _check_quality(self, text: str) -> list[QualitySignal]:
        if len(text.strip()) < 10:
            return [QualitySignal("length", len(text), False, "response too short")]
        return [
            self._check_entropy(text),
            self._check_perplexity(text),
        ]

    def _check_entropy(self, text: str) -> QualitySignal:
        h = self._shannon_entropy(text)
        self._entropy_history.append(h)
        if len(self._entropy_history) < 5:
            return QualitySignal("entropy", h, True, "not enough history")
        med = median(self._entropy_history)
        try:
            sd = stdev(self._entropy_history)
        except Exception:
            sd = 0.5
        z = abs(h - med) / (sd + 1e-9)
        passed = z < settings.entropy_z_threshold
        return QualitySignal("entropy", h, passed, f"z={z:.2f} median={med:.3f}")

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        chars = Counter(text.lower())
        total = len(text)
        return -sum((c / total) * math.log2(c / total) for c in chars.values())

    def _check_perplexity(self, text: str) -> QualitySignal:
        ppl = self._estimate_perplexity(text)
        passed = ppl < settings.perplexity_threshold
        return QualitySignal("perplexity", ppl, passed, f"threshold={settings.perplexity_threshold}")

    @staticmethod
    def _estimate_perplexity(text: str) -> float:
        words = re.findall(r"\w+", text.lower())
        if len(words) < 4:
            return 0.0
        bigrams = list(zip(words, words[1:]))
        unigram_counts = Counter(words)
        bigram_counts = Counter(bigrams)
        total = len(words)
        log_prob = 0.0
        for w1, w2 in bigrams:
            p = (bigram_counts[(w1, w2)] + 1) / (unigram_counts[w1] + total)
            log_prob += math.log(p + 1e-10)
        n = len(bigrams)
        return math.exp(-log_prob / n) if n > 0 else float("inf")
