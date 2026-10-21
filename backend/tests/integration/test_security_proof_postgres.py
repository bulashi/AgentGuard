from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from jsonschema import Draft202012Validator

from backend.business_action.contracts import EvaluateRefundFactsRequest, ResolveRefundActionRequest
from backend.business_action.service import BusinessActionError, BusinessActionRegistryService
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import EXECUTION_RECEIPT
from backend.crypto.sm import sm3_hex
from backend.state.database import connect
from backend.tests.business_fixtures import verified_postgres_case
from backend.tests.unit.test_business_facts import case_request
from backend.ui_api.store import UiReadStore
from scripts.verify_business_workspace import public_only

pytestmark = [pytest.mark.integration, pytest.mark.security]
DATABASE_URL = os.getenv("AGENTGUARD_DATABASE_URL")
UI_DATABASE_URL = os.getenv("AGENTGUARD_UI_DATABASE_URL")
UI_URL = os.getenv("AGENTGUARD_UI_API_URL")
ARTIFACT_ROOT = os.getenv("AGENTGUARD_UI_ARTIFACT_ROOT")
if not all((DATABASE_URL, UI_DATABASE_URL, UI_URL, ARTIFACT_ROOT)):
    pytest.skip("isolated native proof stack is not active", allow_module_level=True)


@pytest.mark.parametrize(
    "kind,reason",
    [
        ("wrong_customer", "RESOURCE_NOT_ALLOWED"),
        ("over_amount", "PARAMETER_CONSTRAINT_VIOLATION"),
    ],
)
def test_valid_leaf_signature_cannot_turn_an_out_of_scope_candidate_into_a_refund(kind, reason):
    from backend.common.enums import KeyPurpose

    verified_postgres_case(DATABASE_URL)
    with httpx.Client(base_url=UI_URL, timeout=120, trust_env=False) as client:
        if os.getenv("AGENTGUARD_OPERATOR_AUTH_REQUIRED") == "true":
            anonymous = client.post("/api/security/proofs", json={"kind": kind, "confirmed": True})
            assert anonymous.status_code == 401
            session = client.post(
                "/api/operator-session",
                json={
                    "launch_token": os.environ["AGENTGUARD_OPERATOR_SESSION_SECRET"],
                },
            )
            assert session.status_code == 200
        response = client.post("/api/security/proofs", json={"kind": kind, "confirmed": True})
        assert response.status_code == 200, response.text
        report = response.json()
        public_only(report)
        schema = json.loads(
            (
                Path(__file__).parents[3]
                / "protocol/extensions/deterministic-security-proof/v1/proof-projection.schema.json"
            ).read_text("utf-8")
        )
        Draft202012Validator(schema).validate(report)
        assert report["status"] == "PASS", report
        assert report["llm_required"] is False
        assert report["candidate_origin"] == "deterministic_security_probe"
        attack, control = report["attack"], report["control"]
        assert attack["holder_proof_valid"] and attack["chain_valid"]
        assert attack["receipt_valid"] and attack["record_binding_valid"]
        assert attack["gateway"]["decision"] == "DENY"
        assert attack["gateway"]["reason_code"] == reason
        assert attack["before"]["budgets"] == attack["after"]["budgets"]
        assert attack["before"]["refund_rows"] == attack["after"]["refund_rows"] == 0
        assert attack["refund_delta"] == attack["notification_delta"] == 0
        assert control["gateway"]["decision"] == "ALLOW"
        assert control["gateway"]["state"] == "COMMITTED"
        assert control["refund_delta"] == 1
        assert control["after"]["refund_amount_fen"] == 7000
        assert control["request"]["request_id"] != attack["request"]["request_id"]
        assert len(control["after"]["budgets"]) == 6
        history = client.get("/api/security/proofs")
        assert history.status_code == 200
        assert any(item["proof_id"] == report["proof_id"] for item in history.json()["items"])
    original = json.loads(
        (Path(ARTIFACT_ROOT) / "security-proofs/runs" / (report["proof_id"] + ".json")).read_text(
            "utf-8"
        )
    )
    store = UiReadStore(UI_DATABASE_URL)
    for attempt in (original["attack"], original["control"]):
        request = attempt["request"]
        assert store.verify_security_request(request)
        assert request["holder_proof"]["signature"]["key_purpose"] == "AGENT_HOLDER_SIGNING"
        with connect(UI_DATABASE_URL) as connection:
            receipt = attempt["gateway"]["receipt"]
            assert store._verify_signed(
                connection,
                receipt,
                domain=EXECUTION_RECEIPT,
                expected_subject_id="receipt-service",
                purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
                trusted_registered_at=receipt["payload"]["receipt_issued_at"],
            )
        assert attempt["gateway"]["receipt"]["payload"]["request_hash"] == sm3_hex(
            canonicalize(request)
        )
        assert len(request["credential_chain"]) == 3
    with connect(DATABASE_URL) as connection:
        refunds = connection.execute(
            "SELECT count(*), SUM(amount_fen) FROM refunds WHERE task_id = %s", (report["task_id"],)
        ).fetchone()
        records = connection.execute(
            "SELECT decision::text, state::text FROM execution_records "
            "WHERE task_id = %s ORDER BY decision::text",
            (report["task_id"],),
        ).fetchall()
        assert refunds == (1, 7000)
        assert set(records) == {("DENY", "DENIED"), ("ALLOW", "COMMITTED")}


@pytest.mark.parametrize("level", [0, 1, 2], ids=["root", "intermediate", "leaf"])
@pytest.mark.parametrize("business_mode", ["legacy", "facts"])
def test_operator_revocation_and_fresh_agent_proof_have_real_denial_and_no_new_effect(
    level, business_mode,
):
    case = verified_postgres_case(DATABASE_URL) if business_mode == "legacy" else None
    with httpx.Client(base_url=UI_URL, timeout=120, trust_env=False) as client:
        session = client.post("/api/operator-session", json={
            "launch_token": os.environ["AGENTGUARD_OPERATOR_SESSION_SECRET"],
        })
        assert session.status_code == 200, session.text
        if business_mode == "facts":
            suffix = uuid4().hex
            document = case_request(
                tenant_id=f"tenant-facts-proof-{suffix}", customer_id=f"C-{suffix}",
                ticket_id=f"TFACT-{suffix}", order_id=f"ORDER-{suffix}",
            )
            for index, payment in enumerate(document["payments"]):
                payment["transaction_id"] = f"PAY-{index}-{suffix}"
            created = client.post("/api/business/cases", json=document)
            assert created.status_code == 201, created.text
            case = created.json()
            qualification_task = client.post("/api/tasks", json={
                "tenant_id": case["tenant_id"], "customer_id": case["customer_id"],
                "ticket_id": case["ticket_id"], "refund_total_fen": 7000,
                "max_tool_calls": 1, "expires_in_seconds": 1800,
            })
            assert qualification_task.status_code == 201, qualification_task.text
            qualification_id = qualification_task.json()["task_id"]
            authorized = client.post(f"/api/tasks/{qualification_id}/authorize", json={
                "confirmed": True, "confirmer_id": "policy-refund-v1",
                "holder_agent_id": "agent-coordinator",
                "holder_key_id": "agent-coordinator-key-01", "delegation_depth": 2,
            })
            assert authorized.status_code == 201, authorized.text
            evaluated = BusinessActionRegistryService(DATABASE_URL).evaluate_refund_facts(
                EvaluateRefundFactsRequest(task_id=qualification_id), current_time=now_unix(),
            )
            assert evaluated["status"] == "VERIFIED"
            assert evaluated["refundable_amount_fen"] == 7000
            BusinessActionRegistryService(DATABASE_URL).resolve_refund(
                ResolveRefundActionRequest(task_id=qualification_id), current_time=now_unix(),
            )
            with connect(DATABASE_URL) as connection:
                assert connection.execute(
                    "SELECT count(*) FROM refunds WHERE ticket_id = %s", (case["ticket_id"],),
                ).fetchone()[0] == 0
            selected = UiReadStore(UI_DATABASE_URL).list_business_tickets()[0]
            assert selected["ticket_id"] == case["ticket_id"]
            assert selected["can_refund"] is True
            assert selected["transaction_remaining_fen"] == 7000
        baseline = client.post(
            "/api/security/proofs", json={"kind": "over_amount", "confirmed": True},
        )
        assert baseline.status_code == 200, baseline.text
        report = baseline.json()
        assert report["status"] == "PASS"
        assert report["ticket_id"] == case["ticket_id"]
        task_id = report["task_id"]
        if business_mode == "facts":
            with pytest.raises(BusinessActionError) as processed:
                BusinessActionRegistryService(DATABASE_URL).resolve_refund(
                    ResolveRefundActionRequest(task_id=task_id), current_time=now_unix(),
                )
            assert processed.value.reason_code == "BUSINESS_ALREADY_PROCESSED"
        credential_id = report["control"]["request"]["credential_ids"][level]
        path = f"/api/tasks/{task_id}/credentials/{credential_id}"
        cancelled = client.post(
            path + "/revoke", json={"confirmed": True, "reason": "企业停止后续办理"},
        )
        assert cancelled.status_code == 200, cancelled.text
        command = cancelled.json()
        public_only(command)
        assert command["boundary"] == "DISPATCH_BOUNDARY_NO_ROLLBACK"
        assert command["descendant_count"] == 2 - level
        assert command["revoked_by"] == "native-operator"
        original_requests = set()
        for _ in range(2):
            response = client.post(path + "/verify-revoked", json={"confirmed": True})
            assert response.status_code == 200, response.text
            verification = response.json()
            public_only(verification)
            assert verification["status"] == "PASS", verification
            assert verification["reason_code"] == (
                "KEY_REVOKED" if level == 2 else "ANCESTOR_REVOKED"
            )
            assert verification["holder_proof_valid"] and verification["chain_signature_valid"]
            assert verification["receipt_valid"] and verification["record_binding_valid"]
            assert verification["before"] == verification["after"] == {
                "refund_rows": 1, "notification_rows": 0, "refund_amount_fen": 7000,
            }
            assert verification["budget_unchanged"] is True
            assert verification["request_id"] != report["control"]["request"]["request_id"]
            original_requests.add(verification["request_id"])
        assert len(original_requests) == 2
        again = client.post(
            path + "/revoke", json={"confirmed": True, "reason": "不覆盖原撤销原因"},
        )
        assert again.status_code == 200, again.text
        assert again.json()["already_revoked"] is True
        assert again.json()["revocation_reason"] == command["revocation_reason"]
        snapshot = client.get(f"/api/tasks/{task_id}")
        assert snapshot.status_code == 200
        assert len(snapshot.json()["business_effects"]["refunds"]) == 1
        assert len(snapshot.json()["business_effects"]["notifications"]) == 0
    store = UiReadStore(UI_DATABASE_URL)
    with connect(DATABASE_URL) as connection:
        from backend.audit.service import AuditService

        AuditService(DATABASE_URL).append_pending(max_events=10_000)
        states = connection.execute(
            "SELECT decision::text, state::text, count(*) FROM execution_records "
            "WHERE task_id = %s GROUP BY decision, state", (task_id,),
        ).fetchall()
        assert sorted(states) == [("ALLOW", "COMMITTED", 1), ("DENY", "DENIED", 3)]
        bound_denials = connection.execute(
            "SELECT initial_request_id, business_action_id FROM execution_records "
            "WHERE task_id = %s AND reason_code = %s", (task_id, verification["reason_code"]),
        ).fetchall()
        committed_action = connection.execute(
            "SELECT business_action_id FROM execution_records "
            "WHERE task_id = %s AND state = 'COMMITTED'", (task_id,),
        ).fetchone()[0]
        assert {row[0] for row in bound_denials} == original_requests
        assert all(row[1] == committed_action for row in bound_denials)
    task_snapshot = store.task_snapshot(task_id)
    revocations = [
        event for event in task_snapshot["audit_events"]
        if event["event_type"] == "CREDENTIAL_REVOKED"
    ]
    assert len(revocations) == 1
    assert revocations[0]["schema_version"] == "4.0"
    assert revocations[0]["evidence_binding_valid"] is True
    assert revocations[0]["credential_revocation_evidence"]["credential_id"] == credential_id
