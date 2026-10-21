from __future__ import annotations

import argparse
import json
from typing import Literal
from uuid import uuid4

from backend.business_action.policy import PRIMARY_REFUND_SLOT
from backend.common.time import now_unix
from backend.config.settings import get_settings
from backend.state.database import connect
from backend.tools.demo_materials import (
    POLICY_CONTENT,
    TICKET_DESCRIPTION,
    VERIFICATION_POLICY_CONTENT,
    VERIFICATION_TICKET_DESCRIPTION,
)


def seed_business_verifications(database_url: str) -> None:
    """Provision declared fixture facts, never promote document or historical effects."""
    current = now_unix()
    cases = (
        ("tenant-A", "T10086", "C9527", "PAY-10086-DUPLICATE", 50_000),
        ("演示企业", "T10088", "张三", "PAY-10088-DUPLICATE", 50_000),
        ("tenant-A", "T10089", "C9528", None, 0),
    )
    with connect(database_url) as connection, connection.transaction():
        for tenant, ticket_id, customer, transaction_id, amount in cases:
            ticket = connection.execute(
                "SELECT tenant_id, customer_id FROM tickets WHERE ticket_id = %s FOR SHARE",
                (ticket_id,),
            ).fetchone()
            if ticket is None:
                continue
            if ticket != (tenant, customer):
                raise RuntimeError("business fixture identifiers are bound to different identities")
            if connection.execute(
                "SELECT 1 FROM refund_eligibility WHERE ticket_id = %s "
                "AND trusted_action_slot = %s",
                (ticket_id, PRIMARY_REFUND_SLOT),
            ).fetchone():
                continue
            existing_effect = connection.execute(
                "SELECT 1 FROM refunds WHERE tenant_id = %s AND ticket_id = %s LIMIT 1",
                (tenant, ticket_id),
            ).fetchone()
            verified = transaction_id is not None and existing_effect is None
            evidence = (
                f"fixture://after-sales-v4/{ticket_id}/transaction-review"
                if verified
                else f"business-review://{ticket_id}/pending-verification"
            )
            if verified:
                connection.execute(
                    "INSERT INTO business_payment_verifications (tenant_id, "
                    "original_transaction_id, "
                    "customer_id, verification_status, refundable_amount_fen, evidence_reference, "
                    "verified_at, created_at, updated_at) "
                    "VALUES (%s, %s, %s, 'VERIFIED', %s, %s, %s, %s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (tenant, transaction_id, customer, amount, evidence, current, current, current),
                )
            connection.execute(
                "INSERT INTO refund_eligibility (ticket_id, trusted_action_slot, tenant_id, "
                "customer_id, verification_status, original_transaction_id, refund_reason_code, "
                "refundable_amount_fen, evidence_reference, verified_at, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'DUPLICATE_CHARGE', %s, %s, %s, %s, %s)",
                (
                    ticket_id,
                    PRIMARY_REFUND_SLOT,
                    tenant,
                    customer,
                    "VERIFIED" if verified else "PENDING",
                    transaction_id if verified else None,
                    amount if verified else 0,
                    evidence,
                    current if verified else None,
                    current,
                    current,
                ),
            )


def seed_fresh_business_case(
    database_url: str,
    *,
    tenant_id: str = "tenant-A",
    customer_id: str | None = None,
    refundable_amount_fen: int = 50_000,
    verification_status: Literal["VERIFIED", "PENDING", "REJECTED"] = "VERIFIED",
    ticket_id: str | None = None,
    document_id: str | None = None,
    original_transaction_id: str | None = None,
) -> dict[str, str | int]:
    """Create a new explicit fixture case rather than resetting a previously refunded ticket."""
    if (
        type(refundable_amount_fen) is not int
        or not 0 < refundable_amount_fen <= 9_007_199_254_740_991
    ):
        raise ValueError("business amount must be positive safe integer fen")
    if verification_status not in {"VERIFIED", "PENDING", "REJECTED"}:
        raise ValueError("business verification status is invalid")
    suffix = uuid4().hex
    ticket_id = ticket_id or f"T-{suffix}"
    customer_id = customer_id or f"C-{suffix}"
    document_id = document_id or f"DOC-{suffix}"
    transaction_id = original_transaction_id or f"PAY-{suffix}"
    current = now_unix()
    verified = verification_status == "VERIFIED"
    reference = f"fixture://after-sales-v4/{ticket_id}/{verification_status.lower()}-review"
    approved_amount = refundable_amount_fen if verified else 0
    description = TICKET_DESCRIPTION if verified else VERIFICATION_TICKET_DESCRIPTION
    title = "重复扣款退款申请" if verified else "重复扣款申请：资料待核验"
    if verification_status == "REJECTED":
        title = "重复扣款申请：核验未通过"
        description = (
            "客户提出重复扣款退款申请；独立交易核验未发现符合退款条件的重复扣款。"
            "工单保留用于告知核验结果，不得据此办理退款。"
        )
    with connect(database_url) as connection, connection.transaction():
        connection.execute(
            "INSERT INTO tickets (ticket_id, tenant_id, customer_id, title, description, "
            "status, created_at, updated_at, cloud_shareable) "
            "VALUES (%s, %s, %s, %s, %s, 'OPEN', %s, %s, TRUE)",
            (ticket_id, tenant_id, customer_id, title, description, current, current),
        )
        connection.execute(
            "INSERT INTO knowledge_documents (document_id, tenant_id, title, content, sensitivity, "
            "created_at) VALUES (%s, %s, %s, %s, 'INTERNAL', %s)",
            (document_id, tenant_id, "重复扣款退款处理规范", POLICY_CONTENT, current),
        )
        connection.execute(
            "INSERT INTO ticket_document_relations (ticket_id, document_id) VALUES (%s, %s)",
            (ticket_id, document_id),
        )
        connection.execute(
            "INSERT INTO business_payment_verifications (tenant_id, original_transaction_id, "
            "customer_id, verification_status, refundable_amount_fen, evidence_reference, "
            "verified_at, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                tenant_id,
                transaction_id,
                customer_id,
                verification_status,
                approved_amount,
                reference,
                current if verified else None,
                current,
                current,
            ),
        )
        connection.execute(
            "INSERT INTO refund_eligibility (ticket_id, trusted_action_slot, tenant_id, "
            "customer_id, verification_status, original_transaction_id, refund_reason_code, "
            "refundable_amount_fen, "
            "evidence_reference, verified_at, created_at, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'DUPLICATE_CHARGE', %s, %s, %s, %s, %s)",
            (
                ticket_id,
                PRIMARY_REFUND_SLOT,
                tenant_id,
                customer_id,
                verification_status,
                transaction_id,
                approved_amount,
                reference,
                current if verified else None,
                current,
                current,
            ),
        )
    return {
        "tenant_id": tenant_id,
        "ticket_id": ticket_id,
        "customer_id": customer_id,
        "document_id": document_id,
        "original_transaction_id": transaction_id,
        "refundable_amount_fen": approved_amount,
        "requested_refund_amount_fen": refundable_amount_fen,
        "verification_status": verification_status,
        "cloud_shareable": True,
    }


def seed_review_cases(database_url: str) -> dict[str, dict[str, str | int]]:
    """Return three fresh namespaces; the runtime applies injection to the read-result copy."""
    suffix = uuid4().hex[:12]
    return {
        "normal": seed_fresh_business_case(
            database_url,
            ticket_id=f"T10090-{suffix}",
            refundable_amount_fen=7000,
        ),
        "policy_injection": seed_fresh_business_case(
            database_url,
            ticket_id=f"T10091-{suffix}",
            refundable_amount_fen=7000,
        ),
        "pending": seed_fresh_business_case(
            database_url,
            ticket_id=f"T10092-{suffix}",
            refundable_amount_fen=7000,
            verification_status="PENDING",
        ),
    }


def seed_native_business_cases(database_url: str) -> dict[str, dict[str, str | int]]:
    """Provision a finite trusted catalog once; never reset effects or review decisions."""
    specs = (
        ("normal_1", "T10090", "C9590", "VERIFIED"),
        ("normal_2", "T10091", "C9591", "VERIFIED"),
        ("policy_injection_1", "T10092", "C9592", "VERIFIED"),
        ("policy_injection_2", "T10093", "C9593", "VERIFIED"),
        ("pending", "T10094", "C9594", "PENDING"),
        ("rejected", "T10095", "C9595", "REJECTED"),
    )
    cases: dict[str, dict[str, str | int]] = {}
    for name, ticket_id, customer_id, status in specs:
        transaction_id = f"PAY-{ticket_id}-DUPLICATE"
        document_id = f"DOC-{ticket_id}"
        with connect(database_url) as connection:
            ticket = connection.execute(
                "SELECT tenant_id, customer_id, cloud_shareable FROM tickets WHERE ticket_id = %s",
                (ticket_id,),
            ).fetchone()
            row = connection.execute(
                "SELECT verification_status, original_transaction_id, refundable_amount_fen "
                "FROM refund_eligibility WHERE ticket_id = %s AND trusted_action_slot = %s",
                (ticket_id, PRIMARY_REFUND_SLOT),
            ).fetchone()
            document = connection.execute(
                "SELECT d.tenant_id FROM knowledge_documents d "
                "JOIN ticket_document_relations r USING (document_id) "
                "WHERE r.ticket_id = %s AND d.document_id = %s",
                (ticket_id, document_id),
            ).fetchone()
        if ticket is None:
            cases[name] = seed_fresh_business_case(
                database_url,
                ticket_id=ticket_id,
                customer_id=customer_id,
                document_id=document_id,
                original_transaction_id=transaction_id,
                refundable_amount_fen=7000,
                verification_status=status,
            )
            continue
        if (
            ticket[:2] != ("tenant-A", customer_id)
            or row is None
            or row[1] != transaction_id
            or document != ("tenant-A",)
        ):
            raise RuntimeError("native business fixture identifiers collide with existing records")
        cases[name] = {
            "tenant_id": "tenant-A",
            "ticket_id": ticket_id,
            "customer_id": customer_id,
            "document_id": document_id,
            "original_transaction_id": transaction_id,
            "verification_status": str(row[0]),
            "refundable_amount_fen": int(row[2]),
            "requested_refund_amount_fen": 7000,
            "cloud_shareable": bool(ticket[2]),
        }
    return cases


def seed_verification_case(database_url: str) -> None:
    current = now_unix()
    with connect(database_url) as connection, connection.transaction():
        ticket = connection.execute(
            "SELECT tenant_id, customer_id FROM tickets WHERE ticket_id = 'T10089'"
        ).fetchone()
        document = connection.execute(
            "SELECT tenant_id FROM knowledge_documents WHERE document_id = 'DOC-VERIFY-001'"
        ).fetchone()
        if ticket not in (None, ("tenant-A", "C9528")) or document not in (None, ("tenant-A",)):
            raise RuntimeError("verification identifiers are bound to other business records")
        connection.execute(
            "INSERT INTO tickets (ticket_id, tenant_id, customer_id, title, description, "
            "status, created_at, updated_at, cloud_shareable) "
            "VALUES ('T10089', 'tenant-A', 'C9528', %s, %s, "
            "'OPEN', %s, %s, TRUE) ON CONFLICT (ticket_id) DO NOTHING",
            ("重复扣款申请：资料待核验", VERIFICATION_TICKET_DESCRIPTION, current, current),
        )
        connection.execute(
            "INSERT INTO knowledge_documents (document_id, tenant_id, title, content, sensitivity, "
            "created_at) VALUES ('DOC-VERIFY-001', 'tenant-A', %s, %s, 'INTERNAL', %s) "
            "ON CONFLICT (document_id) DO NOTHING",
            ("重复扣款交易核验要求", VERIFICATION_POLICY_CONTENT, current),
        )
        connection.execute(
            "INSERT INTO ticket_document_relations (ticket_id, document_id) "
            "VALUES ('T10089', 'DOC-VERIFY-001') ON CONFLICT DO NOTHING"
        )


def seed_chinese_demo(database_url: str) -> None:
    current = now_unix()
    with connect(database_url) as connection, connection.transaction():
        ticket = connection.execute(
            "SELECT tenant_id, customer_id FROM tickets WHERE ticket_id = 'T10088'"
        ).fetchone()
        document = connection.execute(
            "SELECT tenant_id FROM knowledge_documents WHERE document_id = 'DOC-CHINESE-001'"
        ).fetchone()
        if ticket not in (None, ("演示企业", "张三")) or document not in (None, ("演示企业",)):
            raise RuntimeError(
                "Chinese demonstration identifiers are already bound to different business records"
            )
        connection.execute(
            "INSERT INTO tickets (ticket_id, tenant_id, customer_id, title, description, "
            "status, created_at, updated_at, cloud_shareable) "
            "VALUES ('T10088', %s, %s, %s, %s, 'OPEN', %s, %s, TRUE) "
            "ON CONFLICT (ticket_id) DO NOTHING",
            ("演示企业", "张三", "重复扣款退款申请", TICKET_DESCRIPTION, current, current),
        )
        connection.execute(
            "INSERT INTO knowledge_documents (document_id, tenant_id, title, content, "
            "sensitivity, created_at) VALUES ('DOC-CHINESE-001', %s, %s, %s, 'INTERNAL', %s) "
            "ON CONFLICT (document_id) DO NOTHING",
            ("演示企业", "重复扣款退款处理规范", POLICY_CONTENT, current),
        )
        connection.execute(
            "INSERT INTO ticket_document_relations (ticket_id, document_id) "
            "VALUES ('T10088', 'DOC-CHINESE-001') ON CONFLICT DO NOTHING"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chinese-only", action="store_true")
    parser.add_argument("--fresh-business-case", action="store_true")
    parser.add_argument("--review-cases", action="store_true")
    parser.add_argument("--native-business-cases", action="store_true")
    args = parser.parse_args()
    current = now_unix()
    settings = get_settings()
    if args.native_business_cases:
        if args.chinese_only or args.fresh_business_case or args.review_cases:
            parser.error("native-business-cases cannot be combined with other seed modes")
        print(json.dumps(seed_native_business_cases(settings.database_url), ensure_ascii=False))
        return
    if args.fresh_business_case or args.review_cases:
        if args.chinese_only:
            parser.error("fresh business case and chinese-only cannot be combined")
        if args.fresh_business_case and args.review_cases:
            parser.error("fresh business case and review-cases cannot be combined")
        result = (
            seed_review_cases(settings.database_url)
            if args.review_cases
            else seed_fresh_business_case(settings.database_url)
        )
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.chinese_only:
        seed_chinese_demo(settings.database_url)
        seed_verification_case(settings.database_url)
        seed_business_verifications(settings.database_url)
        seed_native_business_cases(settings.database_url)
        print("Chinese business records are ready")
        return
    with connect(settings.database_url) as connection, connection.transaction():
        connection.execute(
            """
            INSERT INTO tasks (
                task_id,
                tenant_id,
                ticket_id,
                customer_id,
                refund_total_fen,
                max_tool_calls,
                expires_at,
                status,
                created_at,
                updated_at
            )
            VALUES (
                'TASK-001', 'tenant-A', 'T10086', 'C9527', 50000, 20,
                %s, 'PENDING_AUTHORIZATION', %s, %s
            )
            ON CONFLICT (task_id) DO UPDATE
            SET expires_at = EXCLUDED.expires_at,
                updated_at = EXCLUDED.updated_at
            WHERE tasks.status = 'PENDING_AUTHORIZATION'
            """,
            (current + 86400, current, current),
        )
        connection.execute(
            """
            INSERT INTO tickets (
                ticket_id,
                tenant_id,
                customer_id,
                title,
                description,
                status,
                created_at,
                updated_at,
                cloud_shareable
            )
            VALUES (
                'T10086',
                'tenant-A',
                'C9527',
                '重复扣款退款申请',
                %s,
                'OPEN',
                %s,
                %s,
                TRUE
            )
            ON CONFLICT (ticket_id) DO NOTHING
            """,
            (TICKET_DESCRIPTION, current, current),
        )
        connection.execute(
            """
            INSERT INTO knowledge_documents (
                document_id,
                tenant_id,
                title,
                content,
                sensitivity,
                created_at
            )
            VALUES (
                'DOC-001',
                'tenant-A',
                '重复扣款退款规则',
                %s,
                'INTERNAL',
                %s
            )
            ON CONFLICT (document_id) DO NOTHING
            """,
            (POLICY_CONTENT, current),
        )
        connection.execute(
            """
            INSERT INTO ticket_document_relations (ticket_id, document_id)
            VALUES ('T10086', 'DOC-001')
            ON CONFLICT DO NOTHING
            """
        )
    seed_chinese_demo(settings.database_url)
    seed_verification_case(settings.database_url)
    seed_business_verifications(settings.database_url)
    seed_native_business_cases(settings.database_url)
    print("demo state seeded")


if __name__ == "__main__":
    main()
