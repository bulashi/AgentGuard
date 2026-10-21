from __future__ import annotations

from typing import Any, Protocol

from backend.agent_runtime.contracts import (
    AgentContext,
    AgentRole,
    PlanDecision,
    ToolIntent,
)


class PlannerError(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        status_code: int = 502,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code
        self.evidence = evidence or {}


class Planner(Protocol):
    name: str

    def plan(self, role: AgentRole, context: AgentContext) -> PlanDecision: ...


class DeterministicPlanner:
    """Fixed plans whose authority-relevant fields ignore untrusted prompt text."""

    name = "deterministic"

    def plan(self, role: AgentRole, context: AgentContext) -> PlanDecision:
        intents: tuple[ToolIntent, ...]
        if role == "knowledge":
            intents = (
                ToolIntent(
                    service="knowledge-service",
                    name="knowledge.read_associated",
                    parameters={"ticket_id": context.ticket_id},
                ),
            )
        elif role == "case":
            intents = (
                ToolIntent(
                    service="ticket-service",
                    name="ticket.read",
                    parameters={"ticket_id": context.ticket_id},
                ),
                ToolIntent(
                    service="notification-service",
                    name="notification.send_template",
                    parameters={
                        "customer_id": context.customer_id,
                        "template_id": "REFUND_SUCCESS",
                    },
                ),
            )
        elif role == "refund":
            intents = (
                ToolIntent(
                    service="refund-service",
                    name="refund.create",
                    parameters={
                        "ticket_id": context.ticket_id,
                        "customer_id": context.customer_id,
                        "amount_fen": context.refund_amount_fen,
                    },
                ),
            )
        else:
            intents = ()
        return PlanDecision(
            planner="deterministic",
            intents=intents,
            evidence={"source": "fixed-role-plan", "prompt_text_consumed": False},
        )

