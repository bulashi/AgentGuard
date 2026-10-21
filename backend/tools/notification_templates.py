"""Server-owned notification text bound to a committed business result."""

from __future__ import annotations

from typing import Any

REFUND_SUCCESS = {
    "template_id": "REFUND_SUCCESS",
    "version": "v1",
    "title": "退款办理结果通知",
    "content_template": (
        "尊敬的客户{customer_id}：您的工单{ticket_id}已办理退款，退款金额{amount_yuan}元。"
        "退款编号：{refund_id}。如需进一步协助，请通过原客服渠道联系。"
    ),
}


def notification_catalog() -> list[dict[str, str]]:
    return [dict(REFUND_SUCCESS)]


def render_refund_success(
    refund: dict[str, Any], *, tenant_id: str, task_id: str, customer_id: str
) -> str:
    amount = refund.get("amount_fen")
    if (
        refund.get("status") != "COMMITTED"
        or refund.get("tenant_id") != tenant_id
        or refund.get("task_id") != task_id
        or refund.get("customer_id") != customer_id
        or not isinstance(refund.get("refund_id"), str)
        or not refund["refund_id"]
        or not isinstance(refund.get("ticket_id"), str)
        or not refund["ticket_id"]
        or type(amount) is not int
        or not 1 <= amount <= 9_007_199_254_740_991
    ):
        raise ValueError("notification requires the matching committed refund")
    return REFUND_SUCCESS["content_template"].format(
        customer_id=customer_id,
        ticket_id=refund["ticket_id"],
        amount_yuan=f"{amount // 100}.{amount % 100:02d}",
        refund_id=refund["refund_id"],
    )
