from __future__ import annotations

from typing import Any

from jsonschema import ValidationError

from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.crypto.sm import signed_object_hash
from backend.crypto.strict_json import MAX_SAFE_INTEGER


def _matches(actual: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(actual, dict):
        return False
    return all(
        key in actual and type(actual[key]) is type(value) and actual[key] == value
        for key, value in expected.items()
    )


def _schema_valid(signed: Any, name: str, schemas: SchemaStore) -> bool:
    try:
        schemas.validate(name, signed)
    except ValidationError:
        return False
    return True


def _hash_matches(signed: Any, expected: Any) -> bool:
    if not isinstance(expected, str):
        return False
    try:
        return signed_object_hash(signed) == expected
    except (TypeError, ValueError):
        return False


def credential_source_verification(
    signed: Any, metadata: dict[str, Any], schemas: SchemaStore,
) -> dict[str, Any]:
    credential_type = metadata.get("credential_type")
    schema_name = {
        "ROOT": "capability-credential.schema.json",
        "DELEGATION": "delegation-credential.schema.json",
    }.get(credential_type) if isinstance(credential_type, str) else None
    schema_valid = schema_name is not None and _schema_valid(signed, schema_name, schemas)
    payload = signed.get("payload") if isinstance(signed, dict) else None
    signature = signed.get("signature") if isinstance(signed, dict) else None
    purpose = (
        KeyPurpose.AUTHORIZATION_ROOT_SIGNING
        if credential_type == "ROOT" else KeyPurpose.AGENT_HOLDER_SIGNING
    )
    row_fields = (
        "credential_id", "credential_type", "parent_credential_id", "parent_credential_hash",
        "not_before", "expires_at", "delegation_depth", "issued_at", "tenant_id", "task_id",
        "verifier_audience", "issuer_subject_id", "issuer_key_id", "holder_agent_id", "holder_key_id",
    )
    row_valid = schema_valid and all(key in metadata for key in row_fields) and _matches(payload, {
        key: metadata.get(key)
        for key in (
            "credential_id", "credential_type", "parent_credential_id",
            "parent_credential_hash", "not_before", "expires_at",
            "delegation_depth", "issued_at", "tenant_id", "task_id",
            "verifier_audience",
        )
    }) and _matches(payload.get("issuer"), {
        "subject_id": metadata.get("issuer_subject_id"),
        "key_id": metadata.get("issuer_key_id"),
    }) and _matches(payload.get("holder"), {
        "agent_id": metadata.get("holder_agent_id"),
        "key_id": metadata.get("holder_key_id"),
    }) and _matches(signature, {
        "key_id": metadata.get("issuer_key_id"),
        "key_purpose": purpose.value,
        "signed_at": metadata.get("issued_at"),
    })
    return {
        "schema_version": "1.0",
        "profile": "CREDENTIAL_ROW_BINDING_V1",
        "schema_valid": schema_valid,
        "stored_hash_valid": _hash_matches(signed, metadata.get("signed_object_hash")),
        "row_binding_valid": row_valid,
        "execution_binding_valid": None,
    }


def receipt_source_verification(
    signed: Any, metadata: dict[str, Any], execution: dict[str, Any], schemas: SchemaStore,
) -> dict[str, Any]:
    schema_valid = _schema_valid(signed, "execution-receipt.schema.json", schemas)
    payload = signed.get("payload") if isinstance(signed, dict) else None
    signature = signed.get("signature") if isinstance(signed, dict) else None
    row_fields = ("receipt_id", "execution_id", "receipt_type", "decision", "reason_code", "receipt_status")
    row_valid = schema_valid and all(key in metadata for key in row_fields) and _matches(payload, {
        key: metadata.get(key)
        for key in ("receipt_id", "execution_id", "receipt_type", "decision", "reason_code")
    }) and metadata.get("receipt_status") == "SIGNED" and _matches(signature, {
        "key_id": payload.get("receipt_signing_key_id"),
        "key_purpose": KeyPurpose.EXECUTION_RECEIPT_SIGNING.value,
        "signed_at": payload.get("receipt_issued_at"),
    })
    execution_fields = (
        "execution_id", "tenant_id", "task_id", "request_hash", "credential_chain_hash",
        "tool_service", "tool_name", "tool_version", "parameter_hash", "decision", "business_action_id",
        "created_at", "state", "reason_code", "business_effect_id", "business_result_hash", "result",
        "terminal_at", "terminal_state", "decision_at", "decision_value",
    )
    execution_valid = schema_valid and all(key in execution for key in execution_fields) and _matches(payload, {
        key: execution.get(key)
        for key in (
            "execution_id", "tenant_id", "task_id", "request_hash",
            "credential_chain_hash", "tool_service", "tool_name", "tool_version",
            "parameter_hash", "decision", "business_action_id",
        )
    }) and _matches(payload, {
        "started_at": execution.get("created_at"),
        "decision_at": execution.get("decision_at"),
    })
    if execution_valid:
        state = execution.get("state")
        decision = execution.get("decision")
        if state == "DENIED" and decision == "DENY":
            execution_valid = _matches(payload, {"reason_code": execution.get("reason_code")})
        elif state in ("COMMITTED", "RELEASED") and decision == "ALLOW":
            execution_valid = payload["reason_code"] == "ALLOWED"
        else:
            execution_valid = False

        created_at = execution.get("created_at")
        decision_at = execution.get("decision_at")
        terminal_at = execution.get("terminal_at")
        receipt_issued_at = payload.get("receipt_issued_at")
        # Mutable updated_at cannot establish when the execution became terminal.
        execution_valid = execution_valid and all(
            type(value) is int and 0 <= value <= MAX_SAFE_INTEGER
            for value in (created_at, decision_at, terminal_at, receipt_issued_at)
        ) and created_at <= decision_at <= terminal_at <= receipt_issued_at and _matches(execution, {
            "terminal_state": state, "decision_value": decision,
        }) and _matches(payload, {
            "finished_at": terminal_at,
            "business_effect_finalized_at": None if state == "DENIED" else terminal_at,
        })

        if state == "COMMITTED" and decision == "ALLOW":
            result = execution.get("result")
            result_hash = execution.get("business_result_hash")
            execution_valid = execution_valid and result is not None and _hash_matches(
                result, payload.get("business_result_hash"),
            ) and (result_hash is None or _matches(payload, {"business_result_hash": result_hash}))
            execution_valid = execution_valid and _matches(payload, {
                "business_effect_id": execution.get("business_effect_id"),
            })
        else:
            execution_valid = execution_valid and _matches(payload, {
                "business_effect_id": None, "business_result_hash": None,
            }) and execution.get("business_effect_id") is None and execution.get("business_result_hash") is None

    return {
        "schema_version": "1.0",
        "profile": "RECEIPT_EXECUTION_BINDING_V1",
        "schema_valid": schema_valid,
        "stored_hash_valid": _hash_matches(signed, metadata.get("receipt_hash")),
        "row_binding_valid": row_valid,
        "execution_binding_valid": execution_valid,
    }
