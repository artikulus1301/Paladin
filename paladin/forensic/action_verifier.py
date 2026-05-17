"""
Forensic Action Verifier — Security boundary #1.

Programmatic filter between the LLM agent and the SIFT MCP Server.
Every MCP request is classified into one of three categories:
  SAFE            → auto-execute, no operator notification
  REQUIRES_APPROVAL → Human-in-the-Loop with 60s timeout, auto-DENY on expiry
  FORBIDDEN       → immediate block, escalation to operator

Default rule: if an action doesn't match SAFE or REQUIRES_APPROVAL → FORBIDDEN.
Explicit allow, implicit deny.

Each decision is logged to PostgreSQL for audit trail.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import structlog
from pydantic import BaseModel

log = structlog.get_logger(__name__)


# ── Categories ────────────────────────────────────────────────────────────────

class VerifierCategory(str, Enum):
    SAFE = "SAFE"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    FORBIDDEN = "FORBIDDEN"


class VerifierDecision(str, Enum):
    APPROVED = "APPROVED"
    QUEUED = "QUEUED"
    BLOCKED = "BLOCKED"


class ForensicVerifierResult(BaseModel):
    """Result of forensic action verification."""
    category: VerifierCategory
    decision: VerifierDecision
    reason: str
    action_requested: str
    parameters_hash: str
    timestamp: str
    incident_id: Optional[str] = None
    forensic_plan_id: Optional[str] = None
    operator_id: Optional[str] = None


# ── Shell injection patterns ──────────────────────────────────────────────────

_SHELL_INJECTION_PATTERNS = [
    re.compile(r"[;]"),                    # command chaining
    re.compile(r"&&"),                     # logical AND chaining
    re.compile(r"\|\|"),                   # logical OR chaining
    re.compile(r"\|(?!\|)"),              # pipe (but not ||)
    re.compile(r"\$\("),                   # command substitution $(...)
    re.compile(r"`"),                       # backtick command substitution
    re.compile(r">\s*/"),                  # output redirection to root
    re.compile(r"<\s*/"),                  # input redirection from root
    re.compile(r"\beval\b"),              # eval
    re.compile(r"\bexec\b"),              # exec
    re.compile(r"\bsource\b"),            # source
    re.compile(r"\bsh\b"),                # sh
    re.compile(r"\bbash\b"),              # bash
    re.compile(r"\bpython\b"),            # python interpreter
    re.compile(r"\bperl\b"),              # perl interpreter
    re.compile(r"\bruby\b"),              # ruby interpreter
]

# Path traversal patterns
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\.(/|\\)"),            # ../  or ..\
    re.compile(r"\.\.%2[fF]"),            # URL-encoded ../
    re.compile(r"%2[eE]%2[eE]"),          # double URL-encoded ..
]

# ── Safe function prefixes (read-only operations) ────────────────────────────

_SAFE_PREFIXES = frozenset([
    "get_", "compute_", "extract_", "analyze_",
    "parse_", "scan_", "list_", "read_", "search_",
    "build_supertimeline",
])

# ── Functions requiring approval ──────────────────────────────────────────────

_APPROVAL_PREFIXES = frozenset([
    "mount_", "quarantine_", "write_output_",
])

# ── Allowed evidence paths ────────────────────────────────────────────────────

_ALLOWED_PATH_ROOTS = [
    "/evidence/",
    "/cases/",
    "/output/",
]


class ForensicActionVerifier:
    """
    Security boundary between agent and MCP Server.
    Classifies every action into SAFE / REQUIRES_APPROVAL / FORBIDDEN.
    """

    def __init__(self, pg_store=None) -> None:
        self._pg_store = pg_store
        self._stats = {
            "safe": 0,
            "requires_approval": 0,
            "forbidden": 0,
        }

    def verify(
        self,
        function_name: str,
        parameters: dict,
        incident_id: str | None = None,
        plan_id: str | None = None,
    ) -> ForensicVerifierResult:
        """
        Verify a single MCP function call.
        Returns the category and decision.
        """
        params_hash = self._hash_params(parameters)
        now = datetime.now(timezone.utc).isoformat()

        # ── Check 1: Shell injection in any parameter value ───────────────
        injection_found = self._check_shell_injection(parameters)
        if injection_found:
            result = ForensicVerifierResult(
                category=VerifierCategory.FORBIDDEN,
                decision=VerifierDecision.BLOCKED,
                reason=f"Shell injection pattern detected: {injection_found}",
                action_requested=function_name,
                parameters_hash=params_hash,
                timestamp=now,
                incident_id=incident_id,
                forensic_plan_id=plan_id,
            )
            self._stats["forbidden"] += 1
            log.warning("forensic_verifier_blocked",
                        function=function_name, reason=result.reason)
            return result

        # ── Check 2: Path traversal in any path parameter ─────────────────
        traversal_found = self._check_path_traversal(parameters)
        if traversal_found:
            result = ForensicVerifierResult(
                category=VerifierCategory.FORBIDDEN,
                decision=VerifierDecision.BLOCKED,
                reason=f"Path traversal attempt detected: {traversal_found}",
                action_requested=function_name,
                parameters_hash=params_hash,
                timestamp=now,
                incident_id=incident_id,
                forensic_plan_id=plan_id,
            )
            self._stats["forbidden"] += 1
            log.warning("forensic_verifier_blocked",
                        function=function_name, reason=result.reason)
            return result

        # ── Check 3: Path must be within allowed roots ────────────────────
        path_violation = self._check_path_boundaries(parameters)
        if path_violation:
            result = ForensicVerifierResult(
                category=VerifierCategory.FORBIDDEN,
                decision=VerifierDecision.BLOCKED,
                reason=f"Path outside allowed boundaries: {path_violation}",
                action_requested=function_name,
                parameters_hash=params_hash,
                timestamp=now,
                incident_id=incident_id,
                forensic_plan_id=plan_id,
            )
            self._stats["forbidden"] += 1
            log.warning("forensic_verifier_blocked",
                        function=function_name, reason=result.reason)
            return result

        # ── Check 4: Classify function by prefix ──────────────────────────
        category = self._classify_function(function_name, parameters)

        if category == VerifierCategory.SAFE:
            decision = VerifierDecision.APPROVED
            reason = f"Function '{function_name}' is read-only and targets allowed paths"
            self._stats["safe"] += 1
            log.debug("forensic_verifier_safe", function=function_name)
        elif category == VerifierCategory.REQUIRES_APPROVAL:
            decision = VerifierDecision.QUEUED
            reason = f"Function '{function_name}' requires operator approval (60s timeout)"
            self._stats["requires_approval"] += 1
            log.info("forensic_verifier_approval_required", function=function_name)
        else:
            # Default: FORBIDDEN
            decision = VerifierDecision.BLOCKED
            reason = f"Function '{function_name}' is not in the allowed list — default FORBIDDEN"
            self._stats["forbidden"] += 1
            log.warning("forensic_verifier_blocked",
                        function=function_name, reason=reason)

        return ForensicVerifierResult(
            category=category,
            decision=decision,
            reason=reason,
            action_requested=function_name,
            parameters_hash=params_hash,
            timestamp=now,
            incident_id=incident_id,
            forensic_plan_id=plan_id,
        )

    def _classify_function(
        self, function_name: str, parameters: dict
    ) -> VerifierCategory:
        """Classify function into SAFE / REQUIRES_APPROVAL / FORBIDDEN."""
        fn = function_name.lower()

        # Check safe prefixes
        for prefix in _SAFE_PREFIXES:
            if fn.startswith(prefix):
                # Safe only if targeting /evidence (read-only) or /cases
                paths = self._extract_paths(parameters)
                if all(self._is_read_safe_path(p) for p in paths) or not paths:
                    return VerifierCategory.SAFE

        # Check approval prefixes
        for prefix in _APPROVAL_PREFIXES:
            if fn.startswith(prefix):
                return VerifierCategory.REQUIRES_APPROVAL

        # Check if writing to /output (requires approval)
        paths = self._extract_paths(parameters)
        for p in paths:
            if p.startswith("/output/"):
                return VerifierCategory.REQUIRES_APPROVAL

        # Default: FORBIDDEN (explicit allow, implicit deny)
        return VerifierCategory.FORBIDDEN

    def _check_shell_injection(self, parameters: dict) -> str | None:
        """Check all string parameter values for shell injection patterns."""
        for key, value in parameters.items():
            if not isinstance(value, str):
                continue
            for pattern in _SHELL_INJECTION_PATTERNS:
                match = pattern.search(value)
                if match:
                    return f"param '{key}' contains '{match.group()}'"
        return None

    def _check_path_traversal(self, parameters: dict) -> str | None:
        """Check all string parameter values for path traversal."""
        for key, value in parameters.items():
            if not isinstance(value, str):
                continue
            for pattern in _PATH_TRAVERSAL_PATTERNS:
                match = pattern.search(value)
                if match:
                    return f"param '{key}' contains '{match.group()}'"
        return None

    def _check_path_boundaries(self, parameters: dict) -> str | None:
        """Ensure all path-like parameters are within allowed roots."""
        paths = self._extract_paths(parameters)
        for p in paths:
            if not any(p.startswith(root) for root in _ALLOWED_PATH_ROOTS):
                return p
        return None

    @staticmethod
    def _extract_paths(parameters: dict) -> list[str]:
        """Extract file path values from parameters."""
        path_keys = {"path", "image_path", "memory_image", "pcap_path",
                     "file_path", "memory_path", "output_path"}
        paths = []
        for key, value in parameters.items():
            if key in path_keys and isinstance(value, str) and value:
                paths.append(value)
        return paths

    @staticmethod
    def _is_read_safe_path(path: str) -> bool:
        """Check if path is in a read-safe location."""
        return path.startswith("/evidence/") or path.startswith("/cases/")

    @staticmethod
    def _hash_params(parameters: dict) -> str:
        """Create a deterministic hash of parameters for logging."""
        canonical = json.dumps(parameters, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @property
    def stats(self) -> dict:
        return dict(self._stats)
