"""Same-process continuation with real test SM2 proofs and in-memory tool effects.

These tests exercise runtime control flow and cryptography, not PostgreSQL recovery.
They never use deployed keys, models, HTTP services or the main database.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import backend.agent_runtime.service as runtime_module
from backend.agent_runtime.contracts import AgentContext, PlanDecision, ToolIntent
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.common.enums import KeyPurpose
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT, HOLDER_PROOF
from backend.crypto.sm import derive_public_key, sign_payload, sm3_hex, verify_payload

HOLDER_PRIVATE = "2" * 64  # Public unit-test scalar, never a deployed key.
RECEIPT_PRIVATE = "3" * 64
CHAIN = [{"payload": {
    "credential_id": "ROOT-runtime-recovery", "task_id": "TASK-runtime-recovery",
    "tenant_id": "tenant-A",
}}]
CONTEXT = AgentContext(
    ticket_id="T-test", customer_id="C-test", refund_amount_fen=7000,
    runtime_mode="deterministic",
)


class TestClock:
    __test__ = False

    def __init__(self) -> None:
        self.current = 0.0
        self.sleeps: list[float] = []

    def monotonic(self):
        return self.current

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.current += seconds


def runtime_for(role: str, public_file: Path) -> AgentRuntimeService:
    service = object.__new__(AgentRuntimeService)
    service.role = role
    service.agent_id, service.key_id = f"agent-{role}", f"agent-{role}-key-01"
    service.private_key, service.public_key = HOLDER_PRIVATE, derive_public_key(HOLDER_PRIVATE)
    service.settings = Settings(
        agent_role=role, agent_id=service.agent_id, agent_key_id=service.key_id,
        receipt_public_key_file=str(public_file), gateway_url="http://gateway.test",
        agent_request_timeout_seconds=5, recovery_deadline_seconds=5,
        workflow_timeout_seconds=10, recovery_interval_seconds=1,
    )
    return service


def signed_receipt(envelope: dict, execution_id: str, result: dict) -> dict:
    issued = envelope["issued_at"]
    effect_id = result.get("refund_id", result.get("notification_id"))
    payload = {
        "schema_version": "1.0", "receipt_id": f"RECEIPT-{execution_id}",
        "receipt_type": "EXECUTION_RESULT", "execution_id": execution_id,
        "request_id": envelope["request_id"], "request_hash": sm3_hex(canonicalize(envelope)),
        "credential_chain_hash": envelope["holder_proof"]["payload"]["credential_chain_hash"],
        "tenant_id": "tenant-A", "task_id": "TASK-runtime-recovery",
        "tool_service": envelope["tool_service"], "tool_name": envelope["tool_name"],
        "tool_version": envelope["tool_version"],
        "parameter_hash": envelope["holder_proof"]["payload"]["canonical_parameter_hash"],
        "decision": "ALLOW", "reason_code": "ALLOWED",
        "business_action_id": envelope["business_action_id"],
        "business_idempotency_key": "a" * 64 if envelope["business_action_id"] else None,
        "business_effect_id": effect_id, "business_result_hash": sm3_hex(canonicalize(result)),
        "budget_reserved": 1, "budget_committed": 1, "started_at": issued,
        "finished_at": issued + 1, "decision_at": issued,
        "business_effect_finalized_at": issued + 1,
        "receipt_issued_at": issued + 2, "receipt_signing_key_id": "receipt-key-01",
    }
    return {"payload": payload, "signature": sign_payload(
        payload, domain_separator=EXECUTION_RECEIPT, key_id="receipt-key-01",
        key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING, private_key_hex=RECEIPT_PRIVATE,
        public_key_hex=derive_public_key(RECEIPT_PRIVATE), signed_at=issued + 2,
    )}


class ContinuationHarness:
    def __init__(self, monkeypatch, tmp_path, *, fault: str):
        public_file = tmp_path / "receipt-test.public"
        public_file.write_text(derive_public_key(RECEIPT_PRIVATE), encoding="ascii")
        self.case = runtime_for("case", public_file)
        self.refund = runtime_for("refund", public_file)
        self.clock = TestClock()
        monkeypatch.setattr(runtime_module, "time", self.clock)
        self.fault = fault
        self.dispatched: list[str] = []
        self.effects = {"refund": [], "notification": []}
        self.plans: list[str] = []
        self.envelopes: dict[str, dict] = {}
        self.results: dict[str, dict] = {}
        self.receipts: dict[str, dict] = {}
        self.retrieval_requests: list[dict] = []
        self.refund_result_reads = 0
        self.refund_receipt_reads = 0
        monkeypatch.setattr(self.case, "_plan", self.plan)
        monkeypatch.setattr(self.refund, "_plan", self.plan)
        monkeypatch.setattr(self.case, "_delegate", lambda *_args, **_kwargs: {
            "payload": {"credential_id": "LEAF-refund", "task_id": "TASK-runtime-recovery"},
        })
        monkeypatch.setattr(self.case, "_run_child", lambda _url, chain, context, trace: (
            self.refund._run_refund(chain, context, trace)
        ))
        monkeypatch.setattr(self.case, "_post_json", self.post)
        monkeypatch.setattr(self.refund, "_post_json", self.post)

    def plan(self, role, context, _trace, *, stage, **_kwargs):
        self.plans.append(stage)
        if role == "refund":
            if self.fault == "decline":
                raise AgentRuntimeError(
                    "PLANNER_DECLINED", "unit explicit decline", status_code=409,
                )
            intent = ToolIntent(service="refund-service", name="refund.create", parameters={
                "ticket_id": context.ticket_id, "customer_id": context.customer_id,
                "amount_fen": context.refund_amount_fen,
            })
        elif stage == "case_read":
            intent = ToolIntent(service="ticket-service", name="ticket.read", parameters={
                "ticket_id": context.ticket_id,
            })
        else:
            assert stage == "case_notify"
            intent = ToolIntent(
                service="notification-service", name="notification.send_template",
                parameters={"customer_id": context.customer_id, "template_id": "REFUND_SUCCESS"},
            )
        return PlanDecision(planner="deterministic", intents=(intent,))

    def post(self, _base, path, body, **_kwargs):
        if path == "/business-actions/refund/resolve":
            return {"business_action_id": "ACTION-refund"}
        if path == "/business-actions/notification/resolve":
            assert body["related_business_effect_id"] == "REFUND-test"
            return {"business_action_id": "ACTION-notification"}
        if path == "/gateway/dispatch":
            tool = body["tool_name"]
            self.dispatched.append(tool)
            execution_id = f"EXEC-{len(self.dispatched)}"
            if tool == "ticket.read":
                result = {
                    "ticket_id": "T-test", "customer_id": "C-test", "tenant_id": "tenant-A",
                    "status": "OPEN",
                }
            elif tool == "refund.create":
                result = {
                    "refund_id": "REFUND-test", "amount_fen": 7000, "status": "COMMITTED",
                    "ticket_id": "T-test", "customer_id": "C-test", "tenant_id": "tenant-A",
                    "task_id": "TASK-runtime-recovery",
                }
                self.effects["refund"].append(result)
            else:
                assert tool == "notification.send_template"
                result = {
                    "notification_id": "NOTIFY-test", "status": "SENT",
                    "template_id": "REFUND_SUCCESS", "related_business_effect_id": "REFUND-test",
                    "customer_id": "C-test", "tenant_id": "tenant-A",
                    "task_id": "TASK-runtime-recovery",
                }
                self.effects["notification"].append(result)
            self.envelopes[execution_id], self.results[execution_id] = body, result
            receipt = signed_receipt(body, execution_id, result)
            self.receipts[execution_id] = receipt
            if tool == "refund.create" and self.fault in {
                "unknown", "never", "revoked", "released", "invalid-receipt", "wrong-receipt",
            }:
                error = AgentRuntimeError(
                    "TOOL_EXECUTION_UNKNOWN", "unit response loss", status_code=502,
                )
                error.execution_id, error.admission_outcome = execution_id, "NEW_EXECUTION"
                raise error
            return {
                "execution_id": execution_id, "decision": "ALLOW", "state": "COMMITTED",
                "admission_outcome": "NEW_EXECUTION",
                "receipt": None if tool == "refund.create" and self.fault == "receipt" else receipt,
            }
        assert path in {"/gateway/results/retrieve", "/gateway/receipts/retrieve"}
        execution_id = body["execution_id"]
        original = self.envelopes[execution_id]
        assert verify_payload(
            body["holder_proof"]["payload"], body["holder_proof"]["signature"],
            domain_separator=HOLDER_PROOF, expected_key_id=original["holder_key_id"],
            expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            public_key_hex=derive_public_key(HOLDER_PRIVATE),
        )
        self.retrieval_requests.append(body)
        if execution_id == "EXEC-2":
            if self.fault == "revoked":
                raise AgentRuntimeError("KEY_REVOKED", "unit revoked before retrieval")
            if path.endswith("results/retrieve"):
                self.refund_result_reads += 1
                if self.fault == "never" or (
                    self.fault == "unknown" and self.refund_result_reads == 1
                ):
                    raise AgentRuntimeError("RESULT_ACCESS_DENIED", "unit pending execution")
                if self.fault == "released":
                    return {"execution_id": execution_id, "state": "RELEASED", "result": None}
            else:
                self.refund_receipt_reads += 1
                if self.fault in {"unknown", "receipt"} and self.refund_receipt_reads == 1:
                    raise AgentRuntimeError("RESULT_ACCESS_DENIED", "unit pending receipt")
        if path.endswith("results/retrieve"):
            return {"execution_id": execution_id, "state": "COMMITTED",
                    "result": self.results[execution_id]}
        receipt = deepcopy(self.receipts[execution_id])
        if execution_id == "EXEC-2" and self.fault == "invalid-receipt":
            receipt["signature"]["value"] = "0" * 128
        if execution_id == "EXEC-2" and self.fault == "wrong-receipt":
            receipt["payload"]["parameter_hash"] = "0" * 64
            receipt["signature"] = sign_payload(
                receipt["payload"], domain_separator=EXECUTION_RECEIPT, key_id="receipt-key-01",
                key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING, private_key_hex=RECEIPT_PRIVATE,
                public_key_hex=derive_public_key(RECEIPT_PRIVATE),
                signed_at=receipt["payload"]["receipt_issued_at"],
            )
        return receipt

    def run(self):
        return self.case._run_case(CHAIN, CONTEXT, [])


@pytest.mark.parametrize("fault", ["unknown", "receipt"])
def test_recovered_refund_continues_to_one_notice_without_redispatch_or_replanning(
    fault, monkeypatch, tmp_path,
):
    harness = ContinuationHarness(monkeypatch, tmp_path, fault=fault)
    result = harness.run()
    assert result["notification"]["status"] == "SENT"
    assert harness.dispatched == ["ticket.read", "refund.create", "notification.send_template"]
    assert len(harness.effects["refund"]) == len(harness.effects["notification"]) == 1
    assert harness.plans == ["case_read", "refund", "case_notify"]
    assert harness.refund_receipt_reads == 2
    requests = harness.retrieval_requests
    assert len({item["request_id"] for item in requests}) == len(requests)
    assert all(
        item["holder_proof"]["payload"]["request_id"] == item["request_id"] for item in requests
    )
    assert 0 < harness.clock.current < 5


@pytest.mark.parametrize("fault,code", [
    ("never", "WORKFLOW_RECOVERY_TIMEOUT"), ("revoked", "KEY_REVOKED"),
    ("released", "CONTROLLED_RESULT_INVALID"), ("invalid-receipt", "CONTROLLED_RESULT_INVALID"),
    ("wrong-receipt", "CONTROLLED_RESULT_INVALID"),
])
def test_unconfirmed_or_untrusted_recovery_never_sends_a_success_notice(
    fault, code, monkeypatch, tmp_path,
):
    harness = ContinuationHarness(monkeypatch, tmp_path, fault=fault)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == code
    assert harness.dispatched == ["ticket.read", "refund.create"]
    assert len(harness.effects["refund"]) == 1 and harness.effects["notification"] == []
    assert harness.plans == ["case_read", "refund"]
    assert harness.clock.current <= 5


def test_planner_decline_is_never_retried_as_an_operational_recovery(monkeypatch, tmp_path):
    harness = ContinuationHarness(monkeypatch, tmp_path, fault="decline")
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "PLANNER_DECLINED"
    assert harness.dispatched == ["ticket.read"]
    assert harness.plans == ["case_read", "refund"]
    assert harness.effects == {"refund": [], "notification": []}
    assert harness.clock.sleeps == []


def test_late_recovery_cannot_continue_after_the_wait_deadline(monkeypatch, tmp_path):
    harness = ContinuationHarness(monkeypatch, tmp_path, fault="receipt")
    original = harness.post

    def late_receipt(base, path, body, **kwargs):
        response = original(base, path, body, **kwargs)
        if path == "/gateway/receipts/retrieve" and body["execution_id"] == "EXEC-2":
            harness.clock.current = 5
        return response

    monkeypatch.setattr(harness.refund, "_post_json", late_receipt)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "WORKFLOW_RECOVERY_TIMEOUT"
    assert harness.dispatched == ["ticket.read", "refund.create"]
    assert len(harness.effects["refund"]) == 1 and harness.effects["notification"] == []


def test_lost_gateway_response_without_execution_identity_does_not_guess_or_redispatch(
    monkeypatch, tmp_path,
):
    harness = ContinuationHarness(monkeypatch, tmp_path, fault="receipt")
    original = harness.post

    def lose_entire_response(base, path, body, **kwargs):
        response = original(base, path, body, **kwargs)
        if path == "/gateway/dispatch" and body["tool_name"] == "refund.create":
            raise AgentRuntimeError(
                "UPSTREAM_UNAVAILABLE", "unit transport timeout", status_code=502,
            )
        return response

    monkeypatch.setattr(harness.refund, "_post_json", lose_entire_response)
    with pytest.raises(AgentRuntimeError) as caught:
        harness.run()
    assert caught.value.reason_code == "UPSTREAM_UNAVAILABLE"
    assert harness.dispatched == ["ticket.read", "refund.create"]
    assert len(harness.effects["refund"]) == 1 and harness.effects["notification"] == []
    assert not any(item["execution_id"] == "EXEC-2" for item in harness.retrieval_requests)
    assert harness.clock.sleeps == []


@pytest.mark.parametrize("mode", [None, "deterministic", "local", "cloud"])
@pytest.mark.parametrize("change", [
    {"amount_fen": 6000}, {"amount_fen": 8000}, {"amount_fen": 7000.0},
    {"ticket_id": "OTHER"}, {"customer_id": "OTHER"}, {"amount_fen": None},
])
def test_mismatched_refund_proposal_is_rejected_before_action_registration_or_effect(
    mode, change, monkeypatch, tmp_path,
):
    service = runtime_for("refund", tmp_path / "unused.public")
    context = CONTEXT.model_copy(update={"runtime_mode": mode})
    parameters = {"ticket_id": "T-test", "customer_id": "C-test", "amount_fen": 7000} | change
    intent = ToolIntent(service="refund-service", name="refund.create", parameters=parameters)
    monkeypatch.setattr(service, "_plan", lambda *_args, **_kwargs: PlanDecision(
        planner="deterministic", intents=(intent,),
    ))
    mutations = []
    monkeypatch.setattr(
        service, "_post_json", lambda *_args, **_kwargs: mutations.append("resolve"),
    )
    monkeypatch.setattr(
        service, "_call_tool", lambda *_args, **_kwargs: mutations.append("dispatch"),
    )
    with pytest.raises(AgentRuntimeError) as caught:
        service._run_refund(CHAIN, context, [])
    assert caught.value.reason_code == "BUSINESS_RESULT_MISMATCH"
    assert mutations == []
    assert intent.parameters == parameters


def test_boolean_amount_cannot_equal_a_one_fen_request(monkeypatch, tmp_path):
    service = runtime_for("refund", tmp_path / "unused.public")
    context = CONTEXT.model_copy(update={"refund_amount_fen": 1})
    intent = ToolIntent(service="refund-service", name="refund.create", parameters={
        "ticket_id": "T-test", "customer_id": "C-test", "amount_fen": True,
    })
    monkeypatch.setattr(service, "_plan", lambda *_args, **_kwargs: PlanDecision(
        planner="deterministic", intents=(intent,),
    ))
    monkeypatch.setattr(service, "_post_json", lambda *_args, **_kwargs: pytest.fail("no effect"))
    with pytest.raises(AgentRuntimeError):
        service._run_refund(CHAIN, context, [])


@pytest.mark.parametrize("original_request", [True, False])
def test_receipt_keeps_original_request_identity_for_legal_idempotent_returns(
    original_request, tmp_path,
):
    public_file = tmp_path / "receipt-test.public"
    public_file.write_text(derive_public_key(RECEIPT_PRIVATE), encoding="ascii")
    service = runtime_for("refund", public_file)
    intent = ToolIntent(service="refund-service", name="refund.create", parameters={
        "ticket_id": "T-test", "customer_id": "C-test", "amount_fen": 7000,
    })
    first = service._tool_request(CHAIN, intent, business_action_id="ACTION-refund")
    current = service._tool_request(CHAIN, intent, business_action_id="ACTION-refund")
    result = {"refund_id": "REFUND-test", "amount_fen": 7000, "status": "COMMITTED"}
    receipt = signed_receipt(first, "EXEC-test", result)
    assert first["request_id"] != current["request_id"]
    if original_request:
        with pytest.raises(AgentRuntimeError):
            service._validate_execution_receipt(
                current, execution_id="EXEC-test", result=result, receipt=receipt,
                original_request=True,
            )
    else:
        service._validate_execution_receipt(
            current, execution_id="EXEC-test", result=result, receipt=receipt,
            original_request=False,
        )


@pytest.mark.parametrize("field,value", [
    ("execution_id", "EXEC-other"), ("task_id", "TASK-other"), ("tenant_id", "tenant-B"),
    ("credential_chain_hash", "0" * 64), ("parameter_hash", "0" * 64),
    ("business_action_id", "ACTION-other"), ("business_result_hash", "0" * 64),
    ("request_id", "REQ-other"), ("request_hash", "0" * 64),
])
def test_cryptographically_valid_receipt_with_wrong_execution_binding_is_rejected(
    field, value, tmp_path,
):
    public_file = tmp_path / "receipt-test.public"
    public_file.write_text(derive_public_key(RECEIPT_PRIVATE), encoding="ascii")
    service = runtime_for("refund", public_file)
    intent = ToolIntent(service="refund-service", name="refund.create", parameters={
        "ticket_id": "T-test", "customer_id": "C-test", "amount_fen": 7000,
    })
    envelope = service._tool_request(CHAIN, intent, business_action_id="ACTION-refund")
    result = {"refund_id": "REFUND-test", "amount_fen": 7000, "status": "COMMITTED"}
    receipt = signed_receipt(envelope, "EXEC-test", result)
    receipt["payload"][field] = value
    receipt["signature"] = sign_payload(
        receipt["payload"], domain_separator=EXECUTION_RECEIPT, key_id="receipt-key-01",
        key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING, private_key_hex=RECEIPT_PRIVATE,
        public_key_hex=derive_public_key(RECEIPT_PRIVATE),
        signed_at=receipt["payload"]["receipt_issued_at"],
    )
    with pytest.raises(AgentRuntimeError) as caught:
        service._validate_execution_receipt(
            envelope, execution_id="EXEC-test", result=result, receipt=receipt,
            original_request=True,
        )
    assert caught.value.reason_code == "CONTROLLED_RESULT_INVALID"
