"""Real, bounded gateway probes with separately observed positive controls."""

from __future__ import annotations

import json
import re
import threading
import time
from typing import Any
from uuid import uuid4

import httpx
from pydantic import ValidationError

from backend.agent_runtime.security_proof import SecurityProofRequest
from backend.authorization.contracts import AuthorizeTaskRequest, CreateTaskRequest
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.ui_api.security_contracts import SecurityProofResponse
from scripts.native_web import is_link

_RUN_LOCK = threading.Lock()
_PROOF_ID = re.compile(r"PROOF-[0-9a-f]{32}\Z")


def observation(snapshot: dict[str, Any]) -> dict[str, Any]:
    budgets = [
        {"credential_id": credential["credential_id"], **budget}
        for credential in snapshot["credentials"]
        for budget in credential["budgets"]
    ]
    effects = snapshot["business_effects"]
    return {
        "observed_at_ms": int(time.time() * 1000),
        "scope": {"type": "task", "task_id": snapshot["task"]["task_id"]},
        "budgets": sorted(budgets, key=lambda item: (item["credential_id"], item["quota_type"])),
        "refund_rows": len(effects["refunds"]),
        "notification_rows": len(effects["notifications"]),
        "refund_amount_fen": sum(item["amount_fen"] for item in effects["refunds"]),
    }


def budget_unchanged(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return before["scope"] == after["scope"] and before["budgets"] == after["budgets"]


def bound_source(value: dict[str, Any], profile: str) -> bool:
    binding = value.get("source_verification", {})
    return (
        binding.get("profile") == profile
        and binding.get("schema_valid") is True
        and binding.get("stored_hash_valid") is True
        and binding.get("row_binding_valid") is True
        and (
            profile != "RECEIPT_EXECUTION_BINDING_V1"
            or binding.get("execution_binding_valid") is True
        )
    )


def attempt(
    ui: Any, chain: list[dict[str, Any]], kind: str, *, business_action_id: str | None = None,
) -> dict[str, Any]:
    from backend.ui_api.service import UiApiError

    candidate = {"credential_chain": chain, "kind": kind}
    if business_action_id is not None:
        candidate["business_action_id"] = business_action_id
    body = ui._post(
        ui.settings.refund_agent_url,
        "/agents/security-proof/request",
        candidate,
    )
    envelope = body.get("request")
    if (
        not isinstance(envelope, dict)
        or body.get("candidate_origin") != "deterministic_security_probe"
    ):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "probe omitted its signed request")
    task_id = chain[0]["payload"]["task_id"]
    returned_chain = envelope.get("credential_chain")
    if (
        envelope.get("task_id") != task_id
        or not isinstance(returned_chain, list)
        or canonicalize(returned_chain) != canonicalize(chain)
        or (
            business_action_id is not None
            and envelope.get("business_action_id") != business_action_id
        )
    ):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "probe request is not bound to this chain")
    holder_valid = ui.store.verify_security_request(envelope)
    before_snapshot = ui.store.task_snapshot(task_id)
    if before_snapshot is None:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "probe task disappeared")
    before = observation(before_snapshot)
    try:
        with httpx.Client(
            base_url=ui.settings.gateway_url,
            timeout=ui.settings.ui_request_timeout_seconds,
            trust_env=False,
        ) as client:
            response = client.post(
                "/gateway/dispatch",
                content=canonicalize(envelope),
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise UiApiError(
            "UPSTREAM_UNAVAILABLE", "gateway probe outcome is unknown", status_code=503
        ) from exc
    if response.status_code not in {200, 400, 403, 409}:
        raise UiApiError(
            "CONTROLLED_RESULT_INVALID", "gateway probe did not return a final decision"
        )
    try:
        gateway = response.json()
    except ValueError as exc:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "gateway probe returned non-JSON") from exc
    if not isinstance(gateway, dict):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "gateway probe returned a non-object")
    after_snapshot = ui.store.task_snapshot(task_id)
    if after_snapshot is None:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "probe observation was not found")
    after = observation(after_snapshot)
    by_id = {item["credential_id"]: item for item in after_snapshot["credentials"]}
    chain_valid = len(chain) == 3 and all(
        (item := by_id.get(signed["payload"]["credential_id"])) is not None
        and item["signature"]["valid"] is True
        and bound_source(item, "CREDENTIAL_ROW_BINDING_V1")
        and item["signed_object_hash"] == signed_object_hash(signed)
        for signed in chain
    )
    execution = next(
        (
            item
            for item in after_snapshot["executions"]
            if item["execution_id"] == gateway.get("execution_id")
        ),
        None,
    )
    receipt = next(
        (
            item
            for item in after_snapshot["receipts"]
            if item["execution_id"] == gateway.get("execution_id")
        ),
        None,
    )
    signed_receipt = gateway.get("receipt")
    receipt_valid = bool(
        receipt
        and isinstance(signed_receipt, dict)
        and receipt["signature"]["valid"] is True
        and bound_source(receipt, "RECEIPT_EXECUTION_BINDING_V1")
        and receipt["receipt_hash"] == signed_object_hash(signed_receipt)
    )
    binding_valid = bool(
        execution
        and receipt_valid
        and execution["request_hash"] == sm3_hex(canonicalize(envelope))
        and execution["parameter_hash"] == sm3_hex(canonicalize(envelope["canonical_parameters"]))
        and signed_receipt["payload"]["request_id"] == envelope["request_id"]
        and signed_receipt["payload"]["task_id"] == task_id
        and signed_receipt["payload"]["credential_chain_hash"] == sm3_hex(canonicalize(chain))
        and signed_receipt["payload"]["decision"] == gateway.get("decision")
        and signed_receipt["payload"]["reason_code"] == gateway.get("reason_code")
    )
    return {
        "kind": kind,
        "request": envelope,
        "http_status": response.status_code,
        "gateway": gateway,
        "holder_proof_valid": holder_valid,
        "chain_valid": chain_valid,
        "receipt_valid": receipt_valid,
        "record_binding_valid": binding_valid,
        "before": before,
        "after": after,
        "budget_unchanged": budget_unchanged(before, after),
        "refund_delta": after["refund_rows"] - before["refund_rows"],
        "notification_delta": after["notification_rows"] - before["notification_rows"],
    }


def run_proof(ui: Any, request: SecurityProofRequest) -> dict[str, Any]:
    from backend.ui_api.service import UiApiError

    ui._require_single_sign_mode()
    if ui.store.has_pending_workflows() or not _RUN_LOCK.acquire(blocking=False):
        raise UiApiError(
            "SECURITY_PROOF_BUSY",
            "finish the current operation before starting a probe",
            status_code=409,
        )
    try:
        business = ui._default_workflow_case()
        task = ui.create_task(
            CreateTaskRequest(
                tenant_id=business["tenant_id"],
                ticket_id=business["ticket_id"],
                customer_id=business["customer_id"],
                refund_total_fen=7000,
                max_tool_calls=1,
                expires_in_seconds=1800,
            )
        )
        task_id = task["task_id"]
        root = ui._post(
            ui.settings.authority_url,
            f"/tasks/{task_id}/authorize",
            AuthorizeTaskRequest(
                confirmed=True,
                confirmer_id="policy-refund-v1",
                holder_agent_id="agent-coordinator",
                holder_key_id="agent-coordinator-key-01",
                delegation_depth=2,
            ).model_dump(mode="json"),
            expected_status=201,
        )
        prepared = ui._post(
            ui.settings.coordinator_agent_url,
            "/agents/security-proof/prepare",
            {"credential_chain": [root]},
        )
        chain = prepared.get("credential_chain")
        if not isinstance(chain, list) or len(chain) != 3:
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", "probe response omitted the three-credential chain"
            )
        if canonicalize(chain[0]) != canonicalize(root):
            raise UiApiError(
                "CONTROLLED_RESULT_INVALID", "probe response changed the root credential"
            )
        attack = attempt(ui, chain, request.kind)
        expected_reason = (
            "RESOURCE_NOT_ALLOWED"
            if request.kind == "wrong_customer"
            else "PARAMETER_CONSTRAINT_VIOLATION"
        )
        denied_safely = (
            attack["holder_proof_valid"]
            and attack["chain_valid"]
            and attack["receipt_valid"]
            and attack["record_binding_valid"]
            and attack["budget_unchanged"]
            and len(attack["before"]["budgets"]) == 6
            and all(
                row["reserved"] == 0 and row["committed"] == 0
                for row in attack["before"]["budgets"]
            )
            and attack["gateway"].get("decision") == "DENY"
            and attack["gateway"].get("state") == "DENIED"
            and attack["gateway"].get("reason_code") == expected_reason
            and attack["refund_delta"] == 0
            and attack["notification_delta"] == 0
        )
        control = attempt(ui, chain, "legal_control") if denied_safely else None
        control_valid = bool(
            control
            and control["holder_proof_valid"]
            and control["chain_valid"]
            and control["receipt_valid"]
            and control["record_binding_valid"]
            and control["gateway"].get("decision") == "ALLOW"
            and control["gateway"].get("state") == "COMMITTED"
            and control["refund_delta"] == 1
            and control["notification_delta"] == 0
            and len(control["after"]["budgets"]) == 6
            and {row["quota_type"] for row in control["after"]["budgets"]}
            == {"refund_total_fen", "max_tool_calls"}
            and all(
                row["reserved"] == 0
                and row["committed"] == (7000 if row["quota_type"] == "refund_total_fen" else 1)
                for row in control["after"]["budgets"]
            )
        )
        report = {
            "schema_version": "1.0",
            "proof_id": "PROOF-" + uuid4().hex,
            "profile": "AGENTGUARD_DETERMINISTIC_SECURITY_PROOF_V1",
            "observation_kind": "operational_test_observation_not_signed_authorization",
            "candidate_origin": "deterministic_security_probe",
            "llm_required": False,
            "created_at_ms": int(time.time() * 1000),
            "kind": request.kind,
            "task_id": task_id,
            "tenant_id": business["tenant_id"],
            "ticket_id": business["ticket_id"],
            "customer_id": business["customer_id"],
            "refund_limit_fen": 7000,
            "status": "PASS" if denied_safely and control_valid else "FAIL",
            "attack": attack,
            "control": control,
            "checks": {
                "denied_without_effect": bool(denied_safely),
                "legal_control_committed": control_valid,
            },
        }
        save_report(ui, report)
        return project_report(report)
    finally:
        _RUN_LOCK.release()


def report_root(ui: Any):
    root = ui.artifact_root / "security-proofs" / "runs"
    if any(
        path.is_symlink() or (path.exists() and is_link(path))
        for path in (ui.artifact_root, root.parent, root)
    ):
        from backend.ui_api.service import UiApiError

        raise UiApiError(
            "RUNTIME_CONFIGURATION_INVALID", "proof storage cannot be a link", status_code=503
        )
    return root


def save_report(ui: Any, report: dict[str, Any]) -> None:
    root = report_root(ui)
    root.mkdir(parents=True, exist_ok=True)
    path = root / (report["proof_id"] + ".json")
    temporary = root / (report["proof_id"] + ".tmp")
    try:
        temporary.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def reports(ui: Any) -> dict[str, Any]:
    root = report_root(ui)
    if not root.exists():
        return {"items": []}
    items = []
    safe_paths = [
        path
        for path in root.glob("PROOF-*.json")
        if path.is_file() and not is_link(path) and _PROOF_ID.fullmatch(path.stem)
    ]
    for path in sorted(safe_paths, key=lambda item: item.stat().st_mtime, reverse=True)[:20]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(value, dict) and value.get("proof_id") == path.stem:
            try:
                items.append(
                    SecurityProofResponse.model_validate(project_report(value)).model_dump()
                )
            except (KeyError, TypeError, ValueError, ValidationError):
                continue
    return {"items": items}


def project_report(report: dict[str, Any]) -> dict[str, Any]:
    """The browser receives fingerprints, not reusable credentials or proof signatures."""

    def project_attempt(value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        projected = {
            key: value[key]
            for key in (
                "kind",
                "http_status",
                "holder_proof_valid",
                "chain_valid",
                "receipt_valid",
                "record_binding_valid",
                "before",
                "after",
                "budget_unchanged",
                "refund_delta",
                "notification_delta",
            )
        }
        envelope = value["request"]
        signature = envelope["holder_proof"]["signature"]
        projected["request"] = {
            key: envelope[key]
            for key in (
                "task_id",
                "tool_service",
                "tool_name",
                "tool_version",
                "canonical_parameters",
                "request_id",
                "issued_at",
                "holder_key_id",
                "business_action_id",
            )
        }
        projected["request"].update(
            {
                "request_hash": sm3_hex(canonicalize(envelope)),
                "credential_chain_hash": sm3_hex(canonicalize(envelope["credential_chain"])),
                "parameter_hash": sm3_hex(canonicalize(envelope["canonical_parameters"])),
                "credential_ids": [
                    item["payload"]["credential_id"] for item in envelope["credential_chain"]
                ],
                "holder_signature": {
                    key: signature[key]
                    for key in (
                        "algorithm",
                        "key_id",
                        "key_purpose",
                        "signed_at",
                    )
                }
                | {"fingerprint_sm3": sm3_hex(signature["value"].encode("ascii"))},
            }
        )
        gateway = value["gateway"]
        projected["gateway"] = {
            key: gateway.get(key)
            for key in (
                "decision",
                "state",
                "reason_code",
                "execution_id",
            )
        }
        receipt = gateway.get("receipt")
        if isinstance(receipt, dict):
            receipt_signature = receipt["signature"]
            projected["gateway"]["receipt"] = {
                "receipt_id": receipt["payload"]["receipt_id"],
                "receipt_hash": signed_object_hash(receipt),
                "request_id": receipt["payload"]["request_id"],
                "signature": {
                    key: receipt_signature[key]
                    for key in (
                        "algorithm",
                        "key_id",
                        "key_purpose",
                        "signed_at",
                    )
                }
                | {"fingerprint_sm3": sm3_hex(receipt_signature["value"].encode("ascii"))},
            }
        return projected

    public = {
        key: report[key]
        for key in (
            "schema_version",
            "proof_id",
            "profile",
            "observation_kind",
            "candidate_origin",
            "llm_required",
            "created_at_ms",
            "kind",
            "task_id",
            "tenant_id",
            "ticket_id",
            "customer_id",
            "refund_limit_fen",
            "status",
            "checks",
        )
    }
    public["attack"] = project_attempt(report["attack"])
    public["control"] = project_attempt(report["control"])
    return public
