from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.agent_runtime.app import make_app as agent_app
from backend.agent_runtime.security_proof import (
    ProofCandidateRequest,
    SecurityProofRequest,
    signed_candidate,
)
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.common.enums import KeyPurpose
from backend.common.internal_auth import InternalAuthenticator
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import verify_payload
from backend.ui_api.app import make_app as ui_app
from backend.ui_api.security_proof import attempt, budget_unchanged, reports
from backend.ui_api.service import UiApiError


@pytest.mark.parametrize(
    "invalid",
    [
        {"kind": "legal_control", "confirmed": True},
        {"kind": "wrong_customer", "confirmed": False},
        {"kind": "wrong_customer", "confirmed": 1},
        {"kind": "over_amount"},
        {"kind": "over_amount", "confirmed": True, "parameters": {"amount_fen": 99}},
        {"kind": "over_amount", "confirmed": True, "business_action_id": "ACTION-supplied"},
    ],
)
def test_public_probe_contract_cannot_become_a_general_signing_oracle(invalid):
    with pytest.raises(ValidationError):
        SecurityProofRequest.model_validate(invalid)


def runtime_and_chain(tmp_path: Path):
    # A public unit-test key exercises SM2; it is never a deployment identity.
    private = tmp_path / "unit-test.private"
    private.write_text("1" * 64, encoding="ascii")
    settings = Settings(
        agent_role="refund",
        agent_id="agent-refund",
        agent_key_id="agent-refund-key-01",
        agent_private_key_file=str(private),
    )
    runtime = AgentRuntimeService(settings)
    runtime._post_json = lambda *_args, **_kwargs: {"business_action_id": "ACTION-unit-proof"}
    chain = []
    for index, role in enumerate(("coordinator", "case", "refund")):
        chain.append(
            {
                "payload": {
                    "task_id": "TASK-unit-proof",
                    "credential_id": f"CRED-{index}",
                    "holder": {"agent_id": f"agent-{role}", "key_id": f"agent-{role}-key-01"},
                    "capabilities": [
                        {
                            "tool": "refund.create",
                            "resources": {"ticket_ids": ["T-unit"], "customer_ids": ["C-unit"]},
                            "constraints": {"single_max_fen": 7000},
                        }
                    ],
                }
            }
        )
    return runtime, chain


@pytest.mark.parametrize("kind", ["wrong_customer", "over_amount", "legal_control"])
def test_finite_candidate_has_a_real_sm2_proof_over_its_actual_parameters(tmp_path, kind):
    runtime, chain = runtime_and_chain(tmp_path)
    result = signed_candidate(runtime, ProofCandidateRequest(credential_chain=chain, kind=kind))
    envelope = result["request"]
    proof = envelope["holder_proof"]
    assert verify_payload(
        proof["payload"],
        proof["signature"],
        domain_separator=HOLDER_PROOF,
        expected_key_id=runtime.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=runtime.public_key,
    )
    changed = deepcopy(proof["payload"])
    changed["canonical_parameter_hash"] = "0" * 64
    assert not verify_payload(
        changed,
        proof["signature"],
        domain_separator=HOLDER_PROOF,
        expected_key_id=runtime.key_id,
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=runtime.public_key,
    )
    if kind == "wrong_customer":
        assert envelope["canonical_parameters"]["customer_id"] != "C-unit"
    elif kind == "over_amount":
        assert envelope["canonical_parameters"]["amount_fen"] == 7001
    else:
        assert envelope["canonical_parameters"] == {
            "ticket_id": "T-unit",
            "customer_id": "C-unit",
            "amount_fen": 7000,
        }
    assert chain[-1]["payload"]["capabilities"][0]["constraints"]["single_max_fen"] == 7000


def test_candidate_rejects_a_different_delegation_path(tmp_path):
    runtime, chain = runtime_and_chain(tmp_path)
    chain[1]["payload"]["holder"]["agent_id"] = "agent-knowledge"
    with pytest.raises(AgentRuntimeError, match="two real delegations"):
        signed_candidate(runtime, ProofCandidateRequest(credential_chain=chain, kind="over_amount"))


def test_persisted_revocation_action_uses_fresh_sm2_requests_without_resolving_again(tmp_path):
    runtime, chain = runtime_and_chain(tmp_path)
    resolver = Mock(side_effect=AssertionError("completed refund must not be resolved again"))
    runtime._post_json = resolver
    candidate = ProofCandidateRequest(
        credential_chain=chain, kind="legal_control", business_action_id="ACTION-already-committed",
    )
    requests = [signed_candidate(runtime, candidate)["request"] for _ in range(2)]
    resolver.assert_not_called()
    assert requests[0]["request_id"] != requests[1]["request_id"]
    for envelope in requests:
        proof = envelope["holder_proof"]
        assert envelope["business_action_id"] == "ACTION-already-committed"
        assert proof["payload"]["business_action_id"] == envelope["business_action_id"]
        assert proof["payload"]["request_id"] == envelope["request_id"]
        assert verify_payload(
            proof["payload"], proof["signature"], domain_separator=HOLDER_PROOF,
            expected_key_id=runtime.key_id,
            expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            public_key_hex=runtime.public_key,
        )


@pytest.mark.parametrize("kind,action", [
    ("wrong_customer", "ACTION-supplied"), ("over_amount", "ACTION-supplied"),
    ("legal_control", ""), ("legal_control", "invalid action"), ("legal_control", "a" * 129),
])
def test_persisted_action_cannot_widen_finite_attack_candidates(kind, action):
    with pytest.raises(ValidationError):
        ProofCandidateRequest(credential_chain=[{}], kind=kind, business_action_id=action)


def test_revocation_candidate_cannot_substitute_the_persisted_business_action():
    chain = [{"payload": {"task_id": "TASK-proof"}}]
    poster = Mock(return_value={
        "candidate_origin": "deterministic_security_probe",
        "request": {
            "task_id": "TASK-proof", "credential_chain": chain,
            "business_action_id": "ACTION-other-task",
        },
    })
    verifier = Mock(side_effect=AssertionError("mismatched candidate must not be dispatched"))
    ui = SimpleNamespace(
        _post=poster, settings=SimpleNamespace(refund_agent_url="http://agent.invalid"),
        store=SimpleNamespace(verify_security_request=verifier),
    )
    with pytest.raises(UiApiError) as failure:
        attempt(ui, chain, "legal_control", business_action_id="ACTION-this-task")
    assert failure.value.reason_code == "CONTROLLED_RESULT_INVALID"
    assert poster.call_args.args[2]["business_action_id"] == "ACTION-this-task"
    verifier.assert_not_called()


def test_probe_signing_route_requires_real_internal_identity_and_rejects_replay(tmp_path):
    runtime, chain = runtime_and_chain(tmp_path)
    keys = json.dumps({"ui-api->agent-refund": "2" * 64})
    settings = runtime.settings.model_copy(
        update={
            "internal_auth_required": True,
            "internal_auth_service_id": "agent-refund",
            "internal_auth_keys": keys,
            "internal_auth_nonce_root": str(tmp_path / "nonces"),
        }
    )
    client = TestClient(agent_app(settings=settings, service=runtime))
    body = canonicalize({"credential_chain": chain, "kind": "over_amount"})
    path = "/agents/security-proof/request"
    assert client.post(path, content=body).status_code == 403
    assert (
        client.post(path, content=body, headers={"X-AgentGuard-Internal": "ui-api"}).status_code
        == 403
    )
    sender = InternalAuthenticator(service_id="ui-api", keys_json=keys)
    headers = sender.request_headers(recipient="agent-refund", method="POST", path=path, body=body)
    assert client.post(path, content=body, headers=headers).status_code == 200
    assert client.post(path, content=body, headers=headers).status_code == 409


def test_public_endpoint_requires_operator_session_before_running_any_probe():
    settings = Settings(operator_auth_required=True, operator_session_secret="3" * 64)
    client = TestClient(ui_app(settings=settings), base_url="http://127.0.0.1:8090")
    body = {"kind": "wrong_customer", "confirmed": True}
    assert client.post("/api/security/proofs", json=body).status_code == 401
    assert client.get("/api/security/proofs").status_code == 401
    client.post("/api/operator-session", json={"launch_token": "3" * 64})
    assert (
        client.post(
            "/api/security/proofs", json=body, headers={"Origin": "https://other.invalid"}
        ).status_code
        == 403
    )
    assert client.post("/api/security/proofs", json={**body, "confirmed": False}).status_code == 422


def test_budget_unchanged_requires_equal_scope_and_all_observed_fields():
    before = {"scope": {"task_id": "T1"}, "budgets": [{"committed": 0, "version": 0}]}
    assert budget_unchanged(before, deepcopy(before))
    for changed in (
        {"scope": {"task_id": "T2"}, "budgets": before["budgets"]},
        {"scope": before["scope"], "budgets": [{"committed": 1, "version": 0}]},
        {"scope": before["scope"], "budgets": [{"committed": 0, "version": 1}]},
    ):
        assert not budget_unchanged(before, changed)


def test_invalid_history_and_links_never_appear_as_successful_proofs(tmp_path):
    ui = SimpleNamespace(artifact_root=tmp_path)
    root = tmp_path / "security-proofs/runs"
    root.mkdir(parents=True)
    (root / ("PROOF-" + "0" * 32 + ".json")).write_text("{}", encoding="utf-8")
    assert reports(ui) == {"items": []}


def test_public_json_schema_matches_pydantic_without_modifying_base_receipt():
    from backend.ui_api.security_contracts import SecurityProofResponse

    root = Path(__file__).parents[3]
    path = root / "protocol/extensions/deterministic-security-proof/v1/proof-projection.schema.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored.pop("$schema")
    stored.pop("$id")
    assert stored == SecurityProofResponse.model_json_schema()
    base = json.loads((root / "protocol/schemas/execution-receipt.schema.json").read_text("utf-8"))
    assert "audit_sequence" not in base["properties"]["payload"]["properties"]
