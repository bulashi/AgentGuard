"""Fresh Holder Proof checks on an already revoked, persisted refund chain."""

from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import Field, field_validator

from backend.authorization.contracts import IDENTIFIER_PATTERN, StrictContract
from backend.common.enums import ReceiptStatus
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import MAX_SAFE_INTEGER
from backend.state.database import connect
from backend.ui_api.security_proof import attempt, bound_source
from backend.ui_api.service import UiApiError, UiService


class VerifyRevokedRequest(StrictContract):
    confirmed: Literal[True]

    @field_validator("confirmed", mode="before")
    @classmethod
    def explicit_boolean(cls, value: Any) -> Any:
        if value is not True:
            raise ValueError("explicit confirmation is required")
        return value


class BusinessObservation(StrictContract):
    refund_rows: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    notification_rows: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    refund_amount_fen: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class RevocationVerificationResponse(StrictContract):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    credential_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    status: Literal["PASS", "FAIL"]
    reason_code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z][A-Z0-9_]*$")
    request_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    holder_key_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    holder_proof_valid: bool
    chain_signature_valid: bool
    receipt_valid: bool
    record_binding_valid: bool
    execution_id: str | None
    receipt_id: str | None
    before: BusinessObservation
    after: BusinessObservation
    budget_unchanged: bool
    new_holder_proof: Literal[True] = True
    observed_at_ms: int = Field(ge=0, le=MAX_SAFE_INTEGER)


def refund_chain(ui: UiService, task_id: str, credential_id: str) -> list[dict[str, Any]]:
    snapshot = ui.store.task_snapshot(task_id)
    if snapshot is None:
        raise UiApiError("CROSS_TASK", "任务不存在", status_code=404)
    credentials = {row["credential_id"]: row for row in snapshot["credentials"]}
    if len(credentials) != len(snapshot["credentials"]) or snapshot["task"]["task_id"] != task_id:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "任务与凭证快照不一致")
    target = credentials.get(credential_id)
    if target is None:
        raise UiApiError("CROSS_TASK", "凭证不属于当前任务", status_code=404)
    if target.get("revoked_at") is None:
        raise UiApiError("REVOCATION_NOT_COMMITTED", "请先撤销所选凭证", status_code=409)
    now = now_unix()
    candidates = []
    for leaf in credentials.values():
        if leaf["holder_agent_id"] != "agent-refund":
            continue
        chain, current, visited = [], leaf, set()
        while current:
            identifier = current["credential_id"]
            if identifier in visited:
                raise UiApiError("CONTROLLED_RESULT_INVALID", "凭证链存在循环")
            visited.add(identifier)
            chain.insert(0, current)
            current = credentials.get(current["parent_credential_id"])
        if (
            len(chain) == 3
            and chain[0]["parent_credential_id"] is None
            and [row["holder_agent_id"] for row in chain]
            == ["agent-coordinator", "agent-case", "agent-refund"]
            and credential_id in visited
            and all(row["not_before"] <= now < row["expires_at"] for row in chain)
            and any(cap["tool"] == "refund.create" for cap in leaf["capabilities"])
        ):
            candidates.append(chain)
    if not candidates:
        raise UiApiError(
            "REVOCATION_PROBE_CHAIN_UNAVAILABLE",
            "当前任务没有处于有效时间窗的受影响退款授权链，请使用新授权任务验证",  # noqa: RUF001
            status_code=409,
        )
    chain = sorted(candidates, key=lambda rows: rows[-1]["credential_id"])[0]
    ids = [row["credential_id"] for row in chain]
    with connect(ui.store.database_url) as connection:
        stored = connection.execute(
            "SELECT credential_id, signed_object FROM credentials "
            "WHERE task_id = %s AND credential_id = ANY(%s)",
            (task_id, ids),
        ).fetchall()
    objects = dict(stored)
    if set(objects) != set(ids):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "受控凭证原文缺失")
    return [objects[identifier] for identifier in ids]


def persisted_refund_action(ui: UiService, chain: list[dict[str, Any]]) -> str | None:
    """Reuse only a committed action bound to this task, chain, refund and receipt."""
    task_id = chain[0]["payload"]["task_id"]
    snapshot = ui.store.task_snapshot(task_id)
    if snapshot is None or snapshot["task"]["task_id"] != task_id:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "撤销验证的任务快照不一致")
    refunds = snapshot["business_effects"]["refunds"]
    if not refunds:
        return None
    chain_hash = sm3_hex(canonicalize(chain))
    for execution in snapshot["executions"]:
        if (
            execution["tool_service"] != "refund-service"
            or execution["tool_name"] != "refund.create"
            or execution["state"] != "COMMITTED"
            or execution["decision"] != "ALLOW"
            or execution["receipt_status"] != ReceiptStatus.SIGNED
            or execution["credential_chain_hash"] != chain_hash
            or not execution.get("business_action_id")
        ):
            continue
        matching_refund = any(
            refund["execution_id"] == execution["execution_id"]
            and refund["refund_id"] == execution["business_effect_id"]
            and refund["status"] == "COMMITTED"
            for refund in refunds
        )
        matching_receipt = any(
            receipt["execution_id"] == execution["execution_id"]
            and receipt["receipt_type"] == "EXECUTION_RESULT"
            and receipt["decision"] == "ALLOW"
            and receipt["receipt_status"] == ReceiptStatus.SIGNED
            and receipt["signature"]["valid"] is True
            and bound_source(receipt, "RECEIPT_EXECUTION_BINDING_V1")
            for receipt in snapshot["receipts"]
        )
        if matching_refund and matching_receipt:
            return execution["business_action_id"]
    raise UiApiError("CONTROLLED_RESULT_INVALID", "已退款记录无法与当前授权链及签名回执核对")


def verify_revoked(ui: UiService, task_id: str, credential_id: str) -> dict[str, Any]:

    if ui.store.has_pending_workflows():
        raise UiApiError("SECURITY_PROOF_BUSY", "请等待当前协作结束后再验证", status_code=409)
    chain = refund_chain(ui, task_id, credential_id)
    action_id = persisted_refund_action(ui, chain)
    observed = attempt(ui, chain, "legal_control", business_action_id=action_id)
    gateway = observed["gateway"]
    receipt = gateway.get("receipt")
    passed = bool(
        observed["holder_proof_valid"]
        and observed["chain_valid"]
        and observed["receipt_valid"]
        and observed["record_binding_valid"]
        and observed["budget_unchanged"]
        and observed["refund_delta"] == observed["notification_delta"] == 0
        and observed["http_status"] == 403
        and gateway.get("state") == "DENIED"
        and gateway.get("decision") == "DENY"
        and gateway.get("reason_code") in {"KEY_REVOKED", "ANCESTOR_REVOKED"}
    )
    business_fields = ("refund_rows", "notification_rows", "refund_amount_fen")
    result = RevocationVerificationResponse(
        task_id=task_id,
        credential_id=credential_id,
        status="PASS" if passed else "FAIL",
        reason_code=gateway.get("reason_code") or "CONTROLLED_RESULT_INVALID",
        request_id=observed["request"]["request_id"],
        request_hash=sm3_hex(canonicalize(observed["request"])),
        holder_key_id=observed["request"]["holder_key_id"],
        holder_proof_valid=observed["holder_proof_valid"],
        chain_signature_valid=observed["chain_valid"],
        receipt_valid=observed["receipt_valid"],
        record_binding_valid=observed["record_binding_valid"],
        execution_id=gateway.get("execution_id"),
        receipt_id=receipt["payload"]["receipt_id"] if isinstance(receipt, dict) else None,
        before={key: observed["before"][key] for key in business_fields},
        after={key: observed["after"][key] for key in business_fields},
        budget_unchanged=observed["budget_unchanged"],
        observed_at_ms=int(time.time() * 1000),
    )
    return result.model_dump(mode="json")
