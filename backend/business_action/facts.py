from __future__ import annotations

from copy import deepcopy
from typing import Any

from psycopg.types.json import Jsonb

from backend.business_action.contracts import (
    BusinessFactEvaluationResponse,
    CreateBusinessCaseRequest,
    RawBusinessFacts,
)
from backend.business_action.policy import PRIMARY_REFUND_SLOT, TrustedTaskContext
from backend.common.ids import new_id
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex

FACT_POLICY_VERSION = "duplicate-full-charge-v1"
FACT_REFUND_REASON = "DUPLICATE_CHARGE"
FACT_POLICY_TEXT = (
    "重复扣款办理规则: 仅成功支付视为实际扣款, 失败支付不产生扣款. "
    "支付仍在处理或分拆支付等资料不一致时需继续核验. "
    "恰好两笔各等于订单应付金额的成功付款, 在扣除已有退款后仍超出订单应付金额, "
    "才可自动办理第二笔成功付款的原路退款. 金额不得超过该笔剩余金额或订单多付金额. "
    "超过两笔成功付款仍有多付时进入人工核验, 不自动办理部分退款. "
    "客户陈述和知识文本不能改变支付事实."
)


class BusinessFactsError(ValueError):
    """Invalid stored facts or a conflict with their fixed business identity."""


class BusinessFactTargetProcessed(BusinessFactsError):
    """The first evaluated target cannot be silently replaced after another refund."""


def _yuan(amount: int) -> str:
    return f"{amount // 100}.{amount % 100:02d}"


def evaluate_business_facts(facts: dict[str, Any]) -> dict[str, Any]:
    """Derive qualification from payment facts, never from the customer's narrative."""
    raw = RawBusinessFacts.model_validate(facts)
    successful = [payment for payment in raw.payments if payment.status == "SUCCESS"]
    failed = [payment for payment in raw.payments if payment.status == "FAILED"]
    processing = [payment for payment in raw.payments if payment.status == "PROCESSING"]
    charged = sum(payment.amount_fen for payment in successful)
    refunded = sum(payment.refunded_amount_fen for payment in successful)
    net = charged - refunded
    order_amount = raw.order.amount_fen
    summary = (
        f"订单应付 {_yuan(order_amount)} 元; 成功支付 {len(successful)} 笔, "
        f"实际扣款 {_yuan(charged)} 元; 失败支付 {len(failed)} 笔, "
        f"失败金额 {_yuan(sum(payment.amount_fen for payment in failed))} 元未扣款; "
        f"已有退款 {_yuan(refunded)} 元, 净扣款 {_yuan(net)} 元. "
    )
    result: dict[str, Any] = {
        "status": "PENDING",
        "reason_code": "PAYMENT_EVIDENCE_INCOMPLETE",
        "reason": summary,
        "refundable_amount_fen": 0,
        "original_transaction_id": None,
        "evidence_ids": [f"ORDER:{raw.order.order_id}"]
        + [f"PAYMENT:{payment.transaction_id}" for payment in raw.payments]
        + [f"POLICY:{FACT_POLICY_VERSION}"],
        "policy_version": FACT_POLICY_VERSION,
    }
    if processing:
        result.update(
            reason_code="PAYMENT_STILL_PROCESSING",
            reason=summary + f"另有 {len(processing)} 笔支付仍在处理中, "
            "扣款尚未确定, 暂不能办理退款.",
        )
        return result
    if any(payment.amount_fen != order_amount for payment in successful):
        result.update(
            reason_code="NON_FULL_ORDER_PAYMENT",
            reason=summary + "成功支付中存在与订单应付金额不同的分拆或不一致记录, "
            "本规则不能直接认定重复的完整扣款, 需进一步核对交易.",
        )
        return result
    if net <= order_amount:
        result.update(
            status="REJECTED",
            reason_code="NO_EXCESS_SUCCESSFUL_CHARGE",
            reason=summary + "净扣款没有超过订单应付金额, 没有多扣款可退; "
            "失败支付也不能作为退款依据.",
        )
        return result
    if len(successful) > 2:
        result.update(
            reason_code="MULTIPLE_EXTRA_PAYMENTS",
            reason=summary + "发现超过两笔完整成功付款, 净多付金额需要逐笔核对. "
            "当前自动流程不支持在同一任务中安全拆分多笔退款, 本次需人工逐笔核验, 未自动退款.",
        )
        return result
    extra_payments = [
        payment for payment in successful[1:]
        if payment.amount_fen > payment.refunded_amount_fen
    ]
    if not extra_payments:
        result.update(reason=summary + "无法确定尚未退回的额外成功付款, 需进一步核对交易.")
        return result
    target = extra_payments[-1]
    amount = min(net - order_amount, target.amount_fen - target.refunded_amount_fen)
    result.update(
        status="VERIFIED",
        reason_code="DUPLICATE_FULL_CHARGE",
        reason=summary + f"发现重复的完整成功扣款, 本次仅处理额外付款 {target.transaction_id}, "
        f"该笔尚可退 {_yuan(target.amount_fen - target.refunded_amount_fen)} 元, "
        f"订单实际多付 {_yuan(net - order_amount)} 元, 本次取两者中较小金额, 可退 {_yuan(amount)} 元.",
        refundable_amount_fen=amount,
        original_transaction_id=target.transaction_id,
    )
    return result


def load_business_case_facts(connection: Any, ticket_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT ticket_id, tenant_id, customer_id, order_id, facts, facts_hash, created_at "
        "FROM business_case_facts WHERE ticket_id = %s",
        (ticket_id,),
    ).fetchone()
    if row is None:
        return None
    fields = (
        "ticket_id", "tenant_id", "customer_id", "order_id", "facts", "facts_hash", "created_at",
    )
    case = dict(zip(fields, row, strict=True))
    try:
        raw = RawBusinessFacts.model_validate(case["facts"])
        if raw.order.order_id != case["order_id"]:
            raise BusinessFactsError("stored order identity does not match the original facts")
        if sm3_hex(canonicalize(case["facts"])) != case["facts_hash"]:
            raise BusinessFactsError("stored business facts do not match their SM3 hash")
    except ValueError as exc:
        raise BusinessFactsError(str(exc)) from exc
    return case


def create_business_case(
    connection: Any, request: CreateBusinessCaseRequest, *, current_time: int,
) -> dict[str, Any]:
    # Lock in a stable order before checking both legacy and new-case payment bindings.
    scopes = [f"FACTS:ORDER:{request.tenant_id}:{request.order_id}"] + [
        f"FACTS:PAYMENT:{request.tenant_id}:{payment.transaction_id}"
        for payment in request.payments
    ]
    for scope in sorted(scopes):
        connection.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (scope,))
    if connection.execute(
        "SELECT 1 FROM business_payment_verifications WHERE tenant_id = %s "
        "AND original_transaction_id = ANY(%s) LIMIT 1",
        (request.tenant_id, [payment.transaction_id for payment in request.payments]),
    ).fetchone():
        raise BusinessFactsError("该租户的支付编号已绑定业务记录, 不能换工单重复提交.")
    facts = request.raw_facts()
    facts_hash = sm3_hex(canonicalize(facts))
    title = "退款申请"
    connection.execute(
        "INSERT INTO tickets (ticket_id, tenant_id, customer_id, title, description, status, "
        "created_at, updated_at, cloud_shareable) VALUES (%s,%s,%s,%s,%s,'OPEN',%s,%s,%s)",
        (request.ticket_id, request.tenant_id, request.customer_id, title, request.claim_text,
         current_time, current_time, request.cloud_shareable),
    )
    connection.execute(
        "INSERT INTO business_case_facts (ticket_id, tenant_id, customer_id, order_id, facts, "
        "facts_hash, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (request.ticket_id, request.tenant_id, request.customer_id, request.order_id,
         Jsonb(facts), facts_hash, current_time),
    )
    for payment in request.payments:
        connection.execute(
            "INSERT INTO business_case_payment_ids (tenant_id, transaction_id, ticket_id, "
            "customer_id) VALUES (%s,%s,%s,%s)",
            (request.tenant_id, payment.transaction_id, request.ticket_id, request.customer_id),
        )
    # The associated document describes a policy, not the case's future decision.
    document_id = new_id("DOC")
    connection.execute(
        "INSERT INTO knowledge_documents (document_id, tenant_id, title, content, sensitivity, "
        "created_at) VALUES (%s,%s,%s,%s,'INTERNAL',%s)",
        (document_id, request.tenant_id, "重复扣款办理规则", FACT_POLICY_TEXT, current_time),
    )
    connection.execute(
        "INSERT INTO ticket_document_relations (ticket_id, document_id) VALUES (%s,%s)",
        (request.ticket_id, document_id),
    )
    return {
        "ticket_id": request.ticket_id, "tenant_id": request.tenant_id,
        "customer_id": request.customer_id, "title": title, "description": request.claim_text,
        "status": "OPEN", "cloud_shareable": request.cloud_shareable,
        "business_facts": facts, "facts_hash": facts_hash, "created_at": current_time,
    }


def evaluate_case_for_task(
    connection: Any, context: TrustedTaskContext, *, current_time: int,
    save_snapshot: bool = True,
) -> dict[str, Any] | None:
    case = load_business_case_facts(connection, context.ticket_id)
    if case is None:
        return None
    if (case["tenant_id"], case["customer_id"]) != (context.tenant_id, context.customer_id):
        raise BusinessFactsError("business facts do not match the authorized task identity")
    connection.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"FACTS:ORDER:{context.tenant_id}:{case['order_id']}",),
    )
    saved = connection.execute(
        "SELECT ticket_id, facts_hash, result FROM business_fact_evaluations WHERE task_id = %s",
        (context.task_id,),
    ).fetchone()
    if saved is not None and (saved[0], saved[1]) != (context.ticket_id, case["facts_hash"]):
        raise BusinessFactsError("the task's first evaluation is bound to different facts")
    if saved is not None and save_snapshot:
        return BusinessFactEvaluationResponse.model_validate(saved[2]).model_dump()
    current_facts = deepcopy(case["facts"])
    local_effects = connection.execute(
        "SELECT original_transaction_id, sum(amount_fen), array_agg(refund_id ORDER BY refund_id) "
        "FROM refunds WHERE tenant_id = %s AND original_transaction_id = ANY(%s) "
        "GROUP BY original_transaction_id",
        (context.tenant_id, [payment["transaction_id"] for payment in current_facts["payments"]]),
    ).fetchall()
    refunds_by_payment = {row[0]: int(row[1]) for row in local_effects}
    for payment in current_facts["payments"]:
        payment["refunded_amount_fen"] += refunds_by_payment.get(payment["transaction_id"], 0)
    try:
        result = evaluate_business_facts(current_facts)
    except ValueError as exc:
        raise BusinessFactsError(
            "recorded refunds conflict with the original payment facts",
        ) from exc
    result.update(
        schema_version="1.0", task_id=context.task_id, ticket_id=context.ticket_id,
        facts_hash=case["facts_hash"], evaluated_at=current_time,
    )
    result["evidence_ids"] += [f"FACTS:{case['facts_hash']}"] + [
        f"REFUND:{refund_id}" for row in local_effects for refund_id in row[2]
    ]
    result = BusinessFactEvaluationResponse.model_validate(result).model_dump()
    if save_snapshot:
        connection.execute(
            "INSERT INTO business_fact_evaluations (task_id, ticket_id, facts_hash, result, "
            "created_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (task_id) DO NOTHING",
            (context.task_id, context.ticket_id, case["facts_hash"], Jsonb(result), current_time),
        )
    return result


def refresh_fact_eligibility(
    connection: Any, context: TrustedTaskContext, *, trusted_action_slot: str, current_time: int,
) -> dict[str, Any] | None:
    """Re-evaluate live balances under the order lock for resolve and tool execution."""
    result = evaluate_case_for_task(
        connection, context, current_time=current_time, save_snapshot=False,
    )
    if result is None:
        return None
    if trusted_action_slot != PRIMARY_REFUND_SLOT:
        raise BusinessFactsError("fact-based cases permit only the primary refund slot")
    saved = connection.execute(
        "SELECT result FROM business_fact_evaluations WHERE task_id = %s", (context.task_id,),
    ).fetchone()
    if saved and saved[0]["status"] == "VERIFIED" and (
        saved[0]["original_transaction_id"] != result["original_transaction_id"]
    ):
        raise BusinessFactTargetProcessed("本任务原定退款交易已处理, 不会自动改退另一笔交易.")
    if result["status"] != "VERIFIED":
        return result
    case = load_business_case_facts(connection, context.ticket_id)
    assert case is not None
    target = next(
        payment for payment in case["facts"]["payments"]
        if payment["transaction_id"] == result["original_transaction_id"]
    )
    # Tool store also counts local refunds against this original ceiling.
    payment_ceiling = target["amount_fen"] - target["refunded_amount_fen"]
    reference = f"facts:{case['facts_hash']}:policy:{FACT_POLICY_VERSION}"
    connection.execute(
        "INSERT INTO business_payment_verifications (tenant_id, original_transaction_id, "
        "customer_id, verification_status, refundable_amount_fen, evidence_reference, "
        "verified_at, created_at, updated_at) VALUES (%s,%s,%s,'VERIFIED',%s,%s,%s,%s,%s) "
        "ON CONFLICT (tenant_id, original_transaction_id) DO UPDATE SET "
        "verification_status=EXCLUDED.verification_status, "
        "refundable_amount_fen=EXCLUDED.refundable_amount_fen, "
        "evidence_reference=EXCLUDED.evidence_reference, verified_at=EXCLUDED.verified_at, "
        "updated_at=EXCLUDED.updated_at",
        (context.tenant_id, target["transaction_id"], context.customer_id, payment_ceiling,
         reference, current_time, current_time, current_time),
    )
    connection.execute(
        "INSERT INTO refund_eligibility (ticket_id, trusted_action_slot, tenant_id, customer_id, "
        "verification_status, original_transaction_id, refund_reason_code, "
        "refundable_amount_fen, evidence_reference, verified_at, created_at, updated_at) "
        "VALUES (%s,%s,%s,%s,'VERIFIED',%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (ticket_id, trusted_action_slot) DO UPDATE SET "
        "verification_status=EXCLUDED.verification_status, "
        "original_transaction_id=EXCLUDED.original_transaction_id, "
        "refund_reason_code=EXCLUDED.refund_reason_code, "
        "refundable_amount_fen=EXCLUDED.refundable_amount_fen, "
        "evidence_reference=EXCLUDED.evidence_reference, verified_at=EXCLUDED.verified_at, "
        "updated_at=EXCLUDED.updated_at",
        (context.ticket_id, trusted_action_slot, context.tenant_id, context.customer_id,
         target["transaction_id"], FACT_REFUND_REASON, result["refundable_amount_fen"], reference,
         current_time, current_time, current_time),
    )
    return result
