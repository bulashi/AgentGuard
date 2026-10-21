from __future__ import annotations

from copy import deepcopy
from typing import Any

HASH = "0" * 64
SIG = "0" * 128
TS = 1_760_000_000


def signature(purpose: str, key_id: str) -> dict[str, Any]:
    return {
        "algorithm": "SM2",
        "key_id": key_id,
        "key_purpose": purpose,
        "encoding": "SM2_RS_HEX_128_LOWERCASE",
        "value": SIG,
        "signed_at": TS,
    }


def root_credential() -> dict[str, Any]:
    return {
        "payload": {
            "schema_version": "1.0",
            "credential_id": "cred-root-001",
            "credential_type": "ROOT",
            "issuer": {"subject_id": "authorization-authority", "key_id": "auth-key-01"},
            "holder": {"agent_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"},
            "tenant_id": "tenant-A",
            "task_id": "TASK-001",
            "verifier_audience": "secure-tool-gateway",
            "capabilities": [
                {
                    "service": "refund-service",
                    "tool": "refund.create",
                    "version": "v1",
                    "resources": {"ticket_ids": ["T10086"], "customer_ids": ["C9527"]},
                    "constraints": {"single_max_fen": 20_000},
                }
            ],
            "quotas": {"refund_total_fen": 50_000, "max_tool_calls": 20},
            "not_before": TS,
            "expires_at": TS + 1_800,
            "delegation_depth": 2,
            "parent_credential_id": None,
            "parent_credential_hash": None,
            "issued_at": TS,
        },
        "signature": signature("AUTHORIZATION_ROOT_SIGNING", "auth-key-01"),
    }


def delegation_credential() -> dict[str, Any]:
    value = deepcopy(root_credential())
    value["payload"].update(
        {
            "credential_id": "cred-child-001",
            "credential_type": "DELEGATION",
            "issuer": {"subject_id": "agent-coordinator", "key_id": "agent-coordinator-key-01"},
            "holder": {"agent_id": "agent-refund", "key_id": "agent-refund-key-01"},
            "quotas": {"refund_total_fen": 20_000, "max_tool_calls": 10},
            "expires_at": TS + 900,
            "delegation_depth": 1,
            "parent_credential_id": "cred-root-001",
            "parent_credential_hash": HASH,
        }
    )
    value["signature"] = signature("AGENT_HOLDER_SIGNING", "agent-coordinator-key-01")
    return value


def holder_proof(
    *,
    tool_service: str = "refund-service",
    tool_name: str = "refund.create",
    business_action_id: str | None = "action-refund-001",
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    del parameters
    return {
        "payload": {
            "schema_version": "1.0",
            "credential_chain_hash": HASH,
            "task_id": "TASK-001",
            "tool_service": tool_service,
            "tool_name": tool_name,
            "tool_version": "v1",
            "canonical_parameter_hash": HASH,
            "request_id": "REQ-001",
            "issued_at": TS,
            "business_action_id": business_action_id,
        },
        "signature": signature("AGENT_HOLDER_SIGNING", "agent-refund-key-01"),
    }


def request_envelope() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "credential_chain": [root_credential(), delegation_credential()],
        "task_id": "TASK-001",
        "tool_service": "refund-service",
        "tool_name": "refund.create",
        "tool_version": "v1",
        "canonical_parameters": {
            "ticket_id": "T10086",
            "customer_id": "C9527",
            "amount_fen": 10_000,
        },
        "request_id": "REQ-001",
        "issued_at": TS,
        "holder_key_id": "agent-refund-key-01",
        "business_action_id": "action-refund-001",
        "holder_proof": holder_proof(),
    }


def valid_schema_instances() -> dict[str, dict[str, Any]]:
    return {
        "capability-credential.schema.json": root_credential(),
        "delegation-credential.schema.json": delegation_credential(),
        "business-action.schema.json": {
            "schema_version": "1.0",
            "business_action_id": "action-refund-001",
            "action_scope_key": HASH,
            "tenant_id": "tenant-A",
            "task_id": "TASK-001",
            "tool_service": "refund-service",
            "tool_name": "refund.create",
            "trusted_action_slot": "refund-slot-1",
            "created_at": TS,
            "status": "ACTIVE",
        },
        "request-envelope.schema.json": request_envelope(),
        "request-context.schema.json": {
            "schema_version": "1.0",
            "execution_id": "EXEC-001",
            "request_id": "REQ-001",
            "request_hash": HASH,
            "credential_chain_hash": HASH,
            "tenant_id": "tenant-A",
            "task_id": "TASK-001",
            "holder_agent_id": "agent-refund",
            "holder_key_id": "agent-refund-key-01",
            "tool_service": "refund-service",
            "tool_name": "refund.create",
            "tool_version": "v1",
            "canonical_parameters": {
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "amount_fen": 10_000,
            },
            "parameter_hash": HASH,
            "business_action_id": "action-refund-001",
            "issued_at": TS,
            "established_at": TS,
        },
        "holder-proof.schema.json": holder_proof(),
        "validated-tool-command.schema.json": {
            "schema_version": "1.0",
            "execution_id": "EXEC-001",
            "tenant_id": "tenant-A",
            "task_id": "TASK-001",
            "tool_service": "refund-service",
            "tool_name": "refund.create",
            "tool_version": "v1",
            "validated_parameters": {
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "amount_fen": 10_000,
            },
            "business_action_id": "action-refund-001",
            "business_idempotency_key": HASH,
            "parameter_hash": HASH,
        },
        "gateway-execution-envelope.schema.json": {
            "payload": {
                "schema_version": "1.0",
                "execution_id": "EXEC-001",
                "execution_attempt_id": "ATTEMPT-001",
                "request_hash": HASH,
                "tenant_id": "tenant-A",
                "task_id": "TASK-001",
                "tool_service": "refund-service",
                "tool_name": "refund.create",
                "tool_version": "v1",
                "canonical_validated_parameters": {
                    "ticket_id": "T10086",
                    "customer_id": "C9527",
                    "amount_fen": 10_000,
                },
                "business_action_id": "action-refund-001",
                "business_idempotency_key": HASH,
                "parameter_hash": HASH,
                "issued_at": TS,
                "expires_at": TS + 30,
                "gateway_key_id": "gateway-key-01",
            },
            "signature": signature("GATEWAY_EXECUTION_SIGNING", "gateway-key-01"),
        },
        "result-retrieval-request.schema.json": {
            "schema_version": "1.0",
            "credential_chain": [root_credential(), delegation_credential()],
            "holder_proof": holder_proof(
                tool_service="secure-tool-gateway",
                tool_name="gateway.result_retrieve",
                business_action_id=None,
            ),
            "task_id": "TASK-001",
            "execution_id": "EXEC-001",
            "receipt_id": None,
            "request_id": "REQ-RETRIEVE-001",
            "issued_at": TS,
        },
        "execution-receipt.schema.json": {
            "payload": {
                "schema_version": "1.0",
                "receipt_id": "RECEIPT-001",
                "receipt_type": "EXECUTION_RESULT",
                "execution_id": "EXEC-001",
                "request_id": "REQ-001",
                "request_hash": HASH,
                "credential_chain_hash": HASH,
                "tenant_id": "tenant-A",
                "task_id": "TASK-001",
                "tool_service": "refund-service",
                "tool_name": "refund.create",
                "tool_version": "v1",
                "parameter_hash": HASH,
                "decision": "ALLOW",
                "reason_code": "ALLOWED",
                "business_action_id": "action-refund-001",
                "business_idempotency_key": HASH,
                "business_effect_id": "refund-001",
                "business_result_hash": HASH,
                "budget_reserved": 0,
                "budget_committed": 10_000,
                "started_at": TS,
                "finished_at": TS + 1,
                "decision_at": TS,
                "business_effect_finalized_at": TS + 1,
                "receipt_issued_at": TS + 1,
                "receipt_signing_key_id": "receipt-key-01",
            },
            "signature": signature("EXECUTION_RECEIPT_SIGNING", "receipt-key-01"),
        },
        "rejected-audit-event.schema.json": {
            "schema_version": "1.0",
            "event_id": "EVENT-RAW-001",
            "raw_request_hash": HASH,
            "parser_stage": "DUPLICATE_KEY",
            "reason_code": "DUPLICATE_FIELD",
            "source_context": {"transport": "INTERNAL_TEST", "source_label": "schema-test"},
            "received_at": TS,
        },
        "audit-event.schema.json": {
            "schema_version": "1.0",
            "event_sequence": 1,
            "event_id": "EVENT-001",
            "execution_id": "EXEC-001",
            "event_type": "EXECUTION_COMMITTED",
            "timestamp": TS,
            "payload_hash": HASH,
            "evidence_reference": "RECEIPT-001",
            "previous_event_hash": HASH,
            "event_hash": HASH,
        },
        "audit-checkpoint.schema.json": {
            "payload": {
                "schema_version": "1.0",
                "checkpoint_sequence": 1,
                "latest_event_sequence": 1,
                "latest_event_hash": HASH,
                "timestamp": TS,
            },
            "signature": signature("AUDIT_CHECKPOINT_SIGNING", "audit-key-01"),
        },
    }
