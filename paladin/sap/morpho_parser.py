"""
SAP Stage 1 — Morpho-semantic parser.
Extends Richter's SpaCy + Natasha analyzers with security-specific vocabulary.
Extracts entities, sentiment, risk_score from text content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import structlog

# Reuse Richter analyzers directly
from app.pipeline.spacy_analyzer import SpaCyAnalyzer, AnalysisResult

log = structlog.get_logger(__name__)

# ── Security-specific vocabulary ──────────────────────────────────────────────

SECURITY_TERMS_EN = {
    # Data exfiltration
    "exfiltration": 0.8, "leak": 0.7, "stolen": 0.9, "breach": 0.8,
    "unauthorized": 0.7, "copy to personal": 0.8, "download": 0.3,
    "export": 0.4, "transfer": 0.3, "usb": 0.5, "thumb drive": 0.6,
    "encrypt": 0.3, "archive": 0.2, "password": 0.4,
    # Access / credentials
    "credentials": 0.5, "admin": 0.4, "root": 0.5, "privilege": 0.6,
    "escalation": 0.7, "bypass": 0.7, "backdoor": 0.9, "exploit": 0.8,
    "brute force": 0.8, "login failed": 0.4, "lockout": 0.6,
    # Finance
    "wire transfer": 0.6, "bank account": 0.5, "invoice": 0.3,
    "payment": 0.2, "offshore": 0.7, "laundering": 0.9,
    # Social engineering
    "urgent": 0.3, "immediately": 0.3, "verify": 0.3,
    "click here": 0.6, "reset password": 0.5, "confirm identity": 0.5,
    # Insider threat
    "competitor": 0.5, "recruiter": 0.4, "offer": 0.2,
    "delete messages": 0.7, "don't tell": 0.6, "off the record": 0.6,
    "signal": 0.3, "personal email": 0.5, "personal drive": 0.6,
    # Malware
    "mimikatz": 0.95, "nmap": 0.6, "wireshark": 0.5, "netcat": 0.7,
    "psexec": 0.7, "powershell -enc": 0.8, "reverse shell": 0.9,
}

SECURITY_TERMS_RU = {
    "утечка": 0.7, "украсть": 0.9, "взлом": 0.8, "несанкционированный": 0.7,
    "скопировать": 0.4, "скачать": 0.3, "экспорт": 0.4,
    "пароль": 0.4, "учётные данные": 0.5, "привилегии": 0.6,
    "эскалация": 0.7, "бэкдор": 0.9, "эксплойт": 0.8,
    "перевод": 0.4, "счёт": 0.3, "оффшор": 0.7,
    "срочно": 0.3, "немедленно": 0.3, "подтвердите": 0.4,
    "конкурент": 0.5, "рекрутер": 0.4, "удалить сообщения": 0.7,
    "личная почта": 0.5, "личный диск": 0.6,
    "конфиденциально": 0.3, "не говори никому": 0.7,
}


@dataclass
class SecurityAnalysis:
    """Extended analysis result with security-specific scoring."""
    base: AnalysisResult
    security_terms_found: list[tuple[str, float]]  # (term, weight)
    text_risk_score: float        # 0.0 - 1.0
    sentiment_label: str          # neutral, suspicious, urgent, conspiratorial
    is_security_relevant: bool


class MorphoParser:
    """
    Wraps Richter's SpaCy/Natasha analyzers and extends with
    security-domain vocabulary scoring.
    """

    def __init__(self) -> None:
        self._analyzer = SpaCyAnalyzer()
        self._all_terms = {**SECURITY_TERMS_EN, **SECURITY_TERMS_RU}

    def analyze(self, text: str) -> SecurityAnalysis:
        """Full morpho-semantic analysis with security scoring."""
        base = self._analyzer.analyze(text)
        terms_found = self._scan_security_terms(text)
        text_risk = self._compute_risk_score(terms_found, base)
        sentiment = self._classify_sentiment(text, terms_found)

        return SecurityAnalysis(
            base=base,
            security_terms_found=terms_found,
            text_risk_score=text_risk,
            sentiment_label=sentiment,
            is_security_relevant=text_risk > 0.2 or len(terms_found) > 0,
        )

    def _scan_security_terms(self, text: str) -> list[tuple[str, float]]:
        """Find security-relevant terms in text."""
        text_lower = text.lower()
        found = []
        for term, weight in self._all_terms.items():
            if term in text_lower:
                found.append((term, weight))
        # Sort by weight descending
        found.sort(key=lambda x: x[1], reverse=True)
        return found

    def _compute_risk_score(
        self, terms: list[tuple[str, float]], base: AnalysisResult
    ) -> float:
        """Combine term weights into a single risk score [0, 1]."""
        if not terms:
            return 0.0
        # Weighted average with diminishing returns
        total = sum(w for _, w in terms)
        count = len(terms)
        raw = total / (count + 2)  # +2 to dampen single-term spikes
        # Boost for multiple terms
        multi_boost = min(count * 0.05, 0.3)
        return min(round(raw + multi_boost, 3), 1.0)

    def _classify_sentiment(
        self, text: str, terms: list[tuple[str, float]]
    ) -> str:
        """Simple rule-based sentiment classification for security context."""
        text_lower = text.lower()
        if any(t in text_lower for t in ["urgent", "immediately", "срочно", "немедленно"]):
            return "urgent"
        if any(t in text_lower for t in ["don't tell", "delete", "secret", "не говори", "удалить"]):
            return "conspiratorial"
        if any(w > 0.6 for _, w in terms):
            return "suspicious"
        return "neutral"
