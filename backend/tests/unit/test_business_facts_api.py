from __future__ import annotations

from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend.business_action.app import make_app
from backend.business_action.facts import evaluate_business_facts
from backend.business_action.service import BusinessActionRegistryService
from backend.common.internal_auth import CALLER_HEADER
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.tests.unit.test_business_facts import case_request
from backend.tests.unit.test_internal_auth import authenticator

KEYS = {
    "ui-api->business-action-registry": "91" * 32,
    "agent-refund->business-action-registry": "92" * 32,
    "agent-case->business-action-registry": "93" * 32,
}


def client(tmp_path):
    service = Mock(spec=BusinessActionRegistryService)
    request = case_request()
    facts = {
        "schema_version": "1.0", "order": {"order_id": "ORDER-facts", "amount_fen": 7000,
                                             "currency": "CNY"},
        "payments": request["payments"], "claim_text": request["claim_text"],
    }
    service.create_business_case.return_value = {
        "ticket_id": "T-facts", "tenant_id": "tenant-A", "customer_id": "C-facts",
        "title": "退款申请", "description": request["claim_text"], "status": "OPEN",
        "cloud_shareable": False, "business_facts": facts, "facts_hash": "a" * 64,
        "created_at": 1000,
    }
    service.evaluate_refund_facts.return_value = {
        **evaluate_business_facts(facts), "schema_version": "1.0", "task_id": "TASK-facts",
        "ticket_id": "T-facts", "facts_hash": "a" * 64, "evaluated_at": 1000,
    }
    receiver = authenticator(tmp_path, "business-action-registry", keys=KEYS)
    return TestClient(make_app(
        settings=Settings(internal_auth_required=True), service=service, internal_auth=receiver,
    )), service


def signed_post(tmp_path, browser, caller, path, document):
    raw = canonicalize(document)
    sender = authenticator(tmp_path, caller, keys=KEYS)
    headers = sender.request_headers(
        recipient="business-action-registry", method="POST", path=path, body=raw,
    )
    return browser.post(path, content=raw, headers=headers)


@pytest.mark.parametrize("path,document,operation", [
    ("/business-cases", case_request(), "create_business_case"),
    ("/business-actions/refund/evaluate", {"task_id": "TASK-facts"}, "evaluate_refund_facts"),
])
def test_new_business_endpoints_require_signed_internal_caller(tmp_path, path, document, operation):
    browser, service = client(tmp_path)
    response = browser.post(path, json=document, headers={CALLER_HEADER: "ui-api"})
    assert response.status_code == 403
    getattr(service, operation).assert_not_called()


def test_ui_internal_caller_can_create_only_raw_facts(tmp_path) -> None:
    browser, service = client(tmp_path)
    response = signed_post(tmp_path, browser, "ui-api", "/business-cases", case_request())
    assert response.status_code == 201
    assert "verification_status" not in response.json() and "status" not in (
        response.json()["business_facts"]
    )
    service.create_business_case.assert_called_once()
    malformed = {**case_request(), "verification_status": "VERIFIED"}
    assert signed_post(tmp_path, browser, "ui-api", "/business-cases", malformed).status_code == 400


@pytest.mark.parametrize("caller", ["agent-refund", "agent-case"])
def test_fact_evaluator_accepts_only_task_id_from_authorized_agents(tmp_path, caller) -> None:
    browser, service = client(tmp_path)
    path = "/business-actions/refund/evaluate"
    response = signed_post(tmp_path, browser, caller, path, {"task_id": "TASK-facts"})
    assert response.status_code == 200 and response.json()["refundable_amount_fen"] == 7000
    service.evaluate_refund_facts.assert_called_once()
    assert signed_post(tmp_path, browser, caller, path, {
        "task_id": "TASK-facts", "status": "VERIFIED", "refundable_amount_fen": 50000,
    }).status_code == 400


@pytest.mark.parametrize("caller,path,document", [
    ("ui-api", "/business-actions/refund/evaluate", {"task_id": "TASK-facts"}),
    ("agent-refund", "/business-cases", case_request()),
])
def test_valid_signature_for_wrong_business_role_is_rejected(tmp_path, caller, path, document):
    browser, service = client(tmp_path)
    assert signed_post(tmp_path, browser, caller, path, document).status_code == 403
    service.create_business_case.assert_not_called()
    service.evaluate_refund_facts.assert_not_called()
