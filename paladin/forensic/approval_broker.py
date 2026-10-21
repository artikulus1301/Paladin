"""
Approval Broker — Human-in-the-Loop gate for REQUIRES_APPROVAL MCP calls.

When the ForensicActionVerifier returns QUEUED, the MCP server parks the call
here. The operator approves or denies it from the dashboard; if nobody answers
within `forensic_approval_timeout` seconds the request is auto-DENIED.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

import structlog

from paladin.config.settings import settings

log = structlog.get_logger(__name__)


@dataclass
class ApprovalRequest:
    request_id: str
    function: str
    parameters: dict
    reason: str
    incident_id: Optional[str]
    plan_id: Optional[str]
    created_at: str
    future: asyncio.Future = field(repr=False)

    def public(self) -> dict:
        return {
            "request_id": self.request_id,
            "function": self.function,
            "parameters": self.parameters,
            "reason": self.reason,
            "incident_id": self.incident_id,
            "plan_id": self.plan_id,
            "created_at": self.created_at,
        }


@dataclass
class ApprovalDecision:
    approved: bool
    operator: Optional[str]
    reason: str


class ApprovalBroker:
    """Tracks pending approval requests and resolves them on operator input or timeout."""

    def __init__(self, timeout: int | None = None,
                 broadcast_fn: Callable[[dict], Awaitable[None]] | None = None) -> None:
        self._timeout = timeout if timeout is not None else settings.forensic_approval_timeout
        self._broadcast = broadcast_fn
        self._pending: dict[str, ApprovalRequest] = {}

    async def request(self, function: str, parameters: dict, reason: str,
                      incident_id: str | None = None,
                      plan_id: str | None = None) -> ApprovalDecision:
        """Park a call until the operator decides. Auto-deny on timeout."""
        req = ApprovalRequest(
            request_id=f"APR-{uuid.uuid4().hex[:10]}",
            function=function,
            parameters=parameters,
            reason=reason,
            incident_id=incident_id,
            plan_id=plan_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            future=asyncio.get_running_loop().create_future(),
        )
        self._pending[req.request_id] = req
        log.info("forensic_approval_requested", request_id=req.request_id,
                 function=function, timeout=self._timeout)

        if self._broadcast:
            await self._broadcast({
                "type": "forensic_approval_required",
                "timeout_seconds": self._timeout,
                **req.public(),
            })

        try:
            return await asyncio.wait_for(asyncio.shield(req.future), timeout=self._timeout)
        except asyncio.TimeoutError:
            log.warning("forensic_approval_timeout", request_id=req.request_id,
                        function=function)
            if self._broadcast:
                await self._broadcast({"type": "forensic_approval_resolved",
                                       "request_id": req.request_id,
                                       "approved": False, "reason": "timeout"})
            return ApprovalDecision(False, None, f"auto-denied after {self._timeout}s timeout")
        finally:
            self._pending.pop(req.request_id, None)

    def resolve(self, request_id: str, approved: bool, operator: str) -> bool:
        """Operator decision. Returns False if the request is unknown or already resolved."""
        req = self._pending.get(request_id)
        if req is None or req.future.done():
            return False
        req.future.set_result(ApprovalDecision(
            approved, operator, "approved by operator" if approved else "denied by operator"))
        log.info("forensic_approval_resolved", request_id=request_id,
                 approved=approved, operator=operator)
        return True

    def pending(self) -> list[dict]:
        return [r.public() for r in self._pending.values()]
