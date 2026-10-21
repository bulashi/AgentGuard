from __future__ import annotations

from typing import Any

ROOT_REFUND_SINGLE_MAX_FEN = 20_000
ROOT_NOTIFICATION_TEMPLATE_ID = "REFUND_SUCCESS"


def build_root_capabilities(
    *, ticket_id: str, customer_id: str, refund_total_fen: int
) -> list[dict[str, Any]]:
    """Build the fixed server policy; callers cannot add tools or resources."""
    return [
        {
            "service": "ticket-service",
            "tool": "ticket.read",
            "version": "v1",
            "resources": {"ticket_ids": [ticket_id]},
            "constraints": {},
        },
        {
            "service": "knowledge-service",
            "tool": "knowledge.read_associated",
            "version": "v1",
            "resources": {"ticket_ids": [ticket_id]},
            "constraints": {},
        },
        {
            "service": "refund-service",
            "tool": "refund.create",
            "version": "v1",
            "resources": {"ticket_ids": [ticket_id], "customer_ids": [customer_id]},
            "constraints": {
                "single_max_fen": min(ROOT_REFUND_SINGLE_MAX_FEN, refund_total_fen)
            },
        },
        {
            "service": "notification-service",
            "tool": "notification.send_template",
            "version": "v1",
            "resources": {"customer_ids": [customer_id]},
            "constraints": {"template_ids": [ROOT_NOTIFICATION_TEMPLATE_ID]},
        },
    ]

