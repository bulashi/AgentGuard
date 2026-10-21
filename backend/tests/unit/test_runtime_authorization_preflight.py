"""Real chain/signature, caller MAC and runtime checks over read-only synthetic DB rows."""

from __future__ import annotations

import json
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import backend.agent_runtime.service as runtime_module
import backend.gateway.app as gateway_app
import backend.gateway.runtime_authorization as preflight_module
from backend.agent_runtime.app import make_app as make_agent_app
from backend.agent_runtime.contracts import AgentContext, AgentRunRequest
from backend.agent_runtime.service import AgentRuntimeError, AgentRuntimeService
from backend.authorization.policy import build_root_capabilities
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.common.internal_auth import CALLER_HEADER, InternalAuthenticator
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL, DELEGATION_CREDENTIAL
from backend.crypto.sm import generate_keypair, sign_payload, signed_object_hash, sm3_hex
from backend.gateway.runtime_authorization import authorize_runtime
from backend.gateway.service import GatewayError, SecureGatewayService

NOW = 1000
TASK = "TASK-preflight"
TICKET = "TICKET-preflight"
CUSTOMER = "CUSTOMER-preflight"
AUTH_PATH = "/gateway/runtime/authorize"
MAC_KEYS = {f"agent-{role}->secure-gateway": "31" * 32 for role in (
    "coordinator", "knowledge", "case", "refund",
)} | {"ui-api->agent-refund": "32" * 32}


class MemoryNonces:
    def __init__(self):
        self.claimed = set()

    def claim(self, *, caller, recipient, nonce, expires_at, current_time):
        assert expires_at >= current_time
        identity = caller, recipient, nonce
        if identity in self.claimed:
            return False
        self.claimed.add(identity)
        return True


def internal_auth(service_id, *, required=True):
    return InternalAuthenticator(
        service_id=service_id, keys_json=json.dumps(MAC_KEYS), required=required,
        nonce_store=MemoryNonces(), clock=lambda: NOW,
    )


def credential_row(document):
    payload = document["payload"]
    return (
        payload["credential_id"], payload["credential_type"], payload["parent_credential_id"],
        payload["parent_credential_hash"], signed_object_hash(document), document,
        payload["issuer"]["subject_id"], payload["issuer"]["key_id"],
        payload["holder"]["agent_id"], payload["holder"]["key_id"],
        payload["tenant_id"], payload["task_id"], payload["verifier_audience"],
        payload["not_before"], payload["expires_at"], payload["delegation_depth"],
        payload["issued_at"], payload["issued_at"] + 1,
    )


class MemoryAuthority:
    def __init__(self, documents, keys):
        self.documents = documents
        self.keys = keys
        self.revoked = set()
        self.task = [TASK, "tenant-A", TICKET, CUSTOMER, 5000, "AUTHORIZED"]
        self.cloud_shareable = True
        self.sql = []

    def execute(self, statement, parameters=None):
        sql = " ".join(statement.split())
        self.sql.append(sql)
        assert sql.startswith("SELECT "), "preflight cannot write business or budget state"
        assert "FOR UPDATE" not in sql and "FOR SHARE" not in sql
        if "FROM credentials" in sql:
            document = next((item for item in self.documents
                             if item["payload"]["credential_id"] == parameters[0]), None)
            row = credential_row(document) if document else None
        elif "FROM credential_revocations" in sql:
            row = (1,) if parameters[0] in self.revoked else None
        elif "FROM key_registry" in sql:
            row = self.keys.get(parameters[0])
        elif "FROM tasks" in sql:
            row = self.task if self.task is not None and self.task[0] == parameters[0] else None
        elif "FROM tickets" in sql:
            assert parameters == (TICKET, "tenant-A", CUSTOMER)
            row = None if self.cloud_shareable is None else (self.cloud_shareable,)
        else:
            raise AssertionError(f"preflight accessed unexpected state: {sql}")
        return SimpleNamespace(fetchone=lambda: row)


def preflight_case(monkeypatch, *, role="refund"):
    subjects = ["authorization-authority", "agent-coordinator", "agent-case", "agent-refund"]
    pairs = {subject: generate_keypair() for subject in subjects}
    key_ids = {subject: ("auth-key-preflight" if index == 0 else f"{subject}-key-01")
               for index, subject in enumerate(subjects)}
    keys = {}
    for subject in subjects:
        purpose = (KeyPurpose.AUTHORIZATION_ROOT_SIGNING if subject == subjects[0]
                   else KeyPurpose.AGENT_HOLDER_SIGNING)
        keys[key_ids[subject]] = [
            key_ids[subject], subject, "AUTHORITY" if subject == subjects[0] else "AGENT",
            purpose.value, "SM2", pairs[subject].public_key_hex, "ACTIVE", "PRESENT", None,
            0, None, None, None, None, None, 0,
        ]
    documents = []
    capabilities = build_root_capabilities(
        ticket_id=TICKET, customer_id=CUSTOMER, refund_total_fen=30_000,
    )
    for index, agent_role in enumerate(("coordinator", "case", "refund")):
        allowed_tools = {
            "coordinator": {cap["tool"] for cap in capabilities},
            "case": {"ticket.read", "refund.create", "notification.send_template"},
            "refund": {"refund.create"},
        }[agent_role]
        granted = deepcopy([cap for cap in capabilities if cap["tool"] in allowed_tools])
        if index:
            next(cap for cap in granted if cap["tool"] == "refund.create")["constraints"][
                "single_max_fen"
            ] = 10_000
        issuer, holder = subjects[index:index + 2]
        payload = {
            "schema_version": "1.0", "credential_id": f"CRED-preflight-{index}",
            "credential_type": "ROOT" if index == 0 else "DELEGATION",
            "issuer": {"subject_id": issuer, "key_id": key_ids[issuer]},
            "holder": {"agent_id": holder, "key_id": key_ids[holder]},
            "tenant_id": "tenant-A", "task_id": TASK,
            "verifier_audience": "secure-tool-gateway", "capabilities": granted,
            "quotas": {"refund_total_fen": (30_000, 15_000, 10_000)[index],
                       "max_tool_calls": 10 - index * 3},
            "not_before": 100 + index * 10, "expires_at": 4000 - index * 100,
            "delegation_depth": 2 - index,
            "parent_credential_id": documents[-1]["payload"]["credential_id"] if index else None,
            "parent_credential_hash": signed_object_hash(documents[-1]) if index else None,
            "issued_at": 100 + index * 10,
        }
        signature = sign_payload(
            payload,
            domain_separator=CAPABILITY_CREDENTIAL if index == 0 else DELEGATION_CREDENTIAL,
            key_id=key_ids[issuer], key_purpose=(KeyPurpose.AUTHORIZATION_ROOT_SIGNING if index == 0
                                              else KeyPurpose.AGENT_HOLDER_SIGNING),
            private_key_hex=pairs[issuer].private_key_hex,
            public_key_hex=pairs[issuer].public_key_hex, signed_at=payload["issued_at"],
        )
        documents.append({"payload": payload, "signature": signature})
    authority = MemoryAuthority(documents, keys)

    @contextmanager
    def fake_connect(url):
        assert url == "unit-preflight-authority"
        yield authority

    monkeypatch.setattr(preflight_module, "connect", fake_connect)
    gateway = SecureGatewayService(database_url="unit-preflight-authority")
    length = {"coordinator": 1, "case": 2, "refund": 3}[role]
    request = AgentRunRequest(
        credential_chain=deepcopy(documents[:length]),
        context=AgentContext(ticket_id=TICKET, customer_id=CUSTOMER, refund_amount_fen=7000,
                             runtime_mode="deterministic"),
    )
    return SimpleNamespace(
        gateway=gateway, authority=authority, request=request, caller=f"agent-{role}",
    )


def authorize(case, **changes):
    return authorize_runtime(case.gateway, case.request, caller=changes.get("caller", case.caller),
                             current_time=changes.get("current_time", NOW))


def test_saved_signed_two_level_chain_returns_bound_ack_without_writes(monkeypatch):
    case = preflight_case(monkeypatch)
    assert authorize(case) == {
        "authorized": True, "task_id": TASK, "agent_id": "agent-refund",
        "credential_chain_hash": sm3_hex(canonicalize(case.request.credential_chain)),
    }
    assert case.authority.sql and all(sql.startswith("SELECT ") for sql in case.authority.sql)


@pytest.mark.parametrize("mutation,reason", [
    ("unknown_leaf", ReasonCode.INVALID_SIGNATURE),
    ("provided_chain_changed", ReasonCode.INVALID_SIGNATURE),
    ("stored_signature_invalid", ReasonCode.INVALID_SIGNATURE),
    ("wrong_caller", ReasonCode.WRONG_HOLDER),
    ("wrong_audience", ReasonCode.WRONG_AUDIENCE),
    ("task_missing", ReasonCode.CROSS_TASK),
    ("task_not_authorized", ReasonCode.CROSS_TASK),
    ("tenant_mismatch", ReasonCode.CROSS_TASK),
    ("wrong_ticket", ReasonCode.RESOURCE_NOT_ALLOWED),
    ("wrong_customer", ReasonCode.RESOURCE_NOT_ALLOWED),
    ("task_expired", ReasonCode.CREDENTIAL_EXPIRED),
    ("chain_expired", ReasonCode.CREDENTIAL_EXPIRED),
    ("root_revoked", ReasonCode.ANCESTOR_REVOKED),
    ("leaf_revoked", ReasonCode.KEY_REVOKED),
    ("leaf_key_revoked", ReasonCode.KEY_REVOKED),
    ("leaf_key_retired", ReasonCode.KEY_RETIRED_FOR_SIGNING),
    ("leaf_key_compromised", ReasonCode.KEY_COMPROMISED),
    ("amount_above_root", ReasonCode.BUDGET_EXCEEDED),
    ("amount_above_leaf", ReasonCode.BUDGET_EXCEEDED),
])
def test_preflight_rejects_invalid_authority_before_any_business_write(
    monkeypatch, mutation, reason,
):
    case = preflight_case(monkeypatch)
    changes = {}
    if mutation == "unknown_leaf":
        case.request.credential_chain[-1]["payload"]["credential_id"] = "CRED-not-registered"
    elif mutation == "provided_chain_changed":
        case.request.credential_chain[-1]["payload"]["quotas"]["refund_total_fen"] = 20_000
    elif mutation == "stored_signature_invalid":
        case.authority.documents[-1]["signature"]["value"] = "0" * 128
    elif mutation == "wrong_caller":
        changes["caller"] = "agent-case"
    elif mutation == "wrong_audience":
        case.gateway.audience = "another-gateway"
    elif mutation == "task_missing":
        case.authority.task = None
    elif mutation == "task_not_authorized":
        case.authority.task[5] = "PENDING_AUTHORIZATION"
    elif mutation == "tenant_mismatch":
        case.authority.task[1] = "tenant-B"
    elif mutation in {"wrong_ticket", "wrong_customer"}:
        field = "ticket_id" if mutation == "wrong_ticket" else "customer_id"
        case.request.context = case.request.context.model_copy(update={field: "outside-task"})
    elif mutation == "task_expired":
        case.authority.task[4] = NOW - 1
    elif mutation == "chain_expired":
        changes["current_time"] = 4001
    elif mutation in {"root_revoked", "leaf_revoked"}:
        index = 0 if mutation == "root_revoked" else -1
        case.authority.revoked.add(case.authority.documents[index]["payload"]["credential_id"])
    elif mutation in {"leaf_key_revoked", "leaf_key_retired", "leaf_key_compromised"}:
        key = case.authority.keys["agent-refund-key-01"]
        key[6], time_index = {
            "leaf_key_revoked": ("REVOKED", 11), "leaf_key_retired": ("RETIRED", 10),
            "leaf_key_compromised": ("COMPROMISED", 12),
        }[mutation]
        key[time_index] = 900
    elif mutation in {"amount_above_root", "amount_above_leaf"}:
        amount = 30_001 if mutation == "amount_above_root" else 10_001
        case.request.context = case.request.context.model_copy(update={"refund_amount_fen": amount})
    else:
        raise AssertionError(mutation)
    with pytest.raises(GatewayError) as failure:
        authorize(case, **changes)
    assert failure.value.reason_code is reason


@pytest.mark.parametrize("shareable,confirmed,allowed", [
    (True, True, True), (True, False, False), (False, True, False), (None, True, False),
])
def test_cloud_requires_independent_ticket_flag_and_explicit_confirmation(
    monkeypatch, shareable, confirmed, allowed,
):
    case = preflight_case(monkeypatch)
    case.authority.cloud_shareable = shareable
    case.request.context = case.request.context.model_copy(update={
        "runtime_mode": "cloud", "cloud_data_confirmed": confirmed,
        "ticket_context": {"cloud_shareable": True},
    })
    if allowed:
        assert authorize(case)["authorized"] is True
    else:
        with pytest.raises(GatewayError) as failure:
            authorize(case)
        assert failure.value.reason_code is ReasonCode.RESOURCE_NOT_ALLOWED


def gateway_client(monkeypatch, case, *, required=True):
    receiver = internal_auth("secure-gateway", required=required)

    def configured_receiver(_settings, *, service_id):
        assert service_id == "secure-gateway"
        return receiver

    monkeypatch.setattr(
        gateway_app.InternalAuthenticator, "from_settings",
        Mock(side_effect=configured_receiver),
    )
    monkeypatch.setattr(gateway_app, "now_unix", lambda: NOW)
    return TestClient(gateway_app.make_app(settings=Settings(), service=case.gateway))


@pytest.mark.parametrize("required,headers", [
    (True, {}), (True, {CALLER_HEADER: "agent-refund"}), (False, {}),
])
def test_gateway_missing_auth_does_not_enter_authority_route(monkeypatch, required, headers):
    case = preflight_case(monkeypatch)
    client = gateway_client(monkeypatch, case, required=required)
    response = client.post(AUTH_PATH, json=case.request.model_dump(mode="json"), headers=headers)
    assert response.status_code == 403
    assert case.authority.sql == []


def test_unsigned_test_stack_still_binds_explicit_caller_to_leaf(monkeypatch):
    case = preflight_case(monkeypatch)
    client = gateway_client(monkeypatch, case, required=False)
    response = client.post(
        AUTH_PATH, json=case.request.model_dump(mode="json"),
        headers={CALLER_HEADER: "agent-refund"},
    )
    assert response.status_code == 200
    assert response.json()["agent_id"] == "agent-refund"
    assert response.json()["credential_chain_hash"] == sm3_hex(
        canonicalize(case.request.credential_chain),
    )


@pytest.mark.parametrize("tamper", ["none", "body", "different_authenticated_agent"])
def test_gateway_mac_binding_and_authenticated_caller_match_leaf(monkeypatch, tamper):
    case = preflight_case(monkeypatch)
    client = gateway_client(monkeypatch, case)
    body = canonicalize(case.request.model_dump(mode="json"))
    sender = internal_auth("agent-case" if tamper == "different_authenticated_agent"
                           else "agent-refund")
    headers = sender.request_headers(recipient="secure-gateway", method="POST",
                                     path=AUTH_PATH, body=body)
    if tamper == "body":
        body += b" "
    response = client.post(AUTH_PATH, content=body, headers=headers)
    if tamper == "none":
        assert response.status_code == 200
        assert response.json()["credential_chain_hash"] == sm3_hex(
            canonicalize(case.request.credential_chain),
        )
    else:
        assert response.status_code == 403
        if tamper == "body":
            assert case.authority.sql == []
        else:
            assert response.json()["reason_code"] == "WRONG_HOLDER"


def runtime_subject(case):
    service = AgentRuntimeService.__new__(AgentRuntimeService)
    service.role = "refund"
    service.agent_id = "agent-refund"
    service.key_id = "agent-refund-key-01"
    service.settings = Settings()
    service.planner_name = "deterministic"
    service._plan = Mock(side_effect=AssertionError("denied preflight cannot consume planning"))
    return service


@pytest.mark.parametrize("field,value", [
    ("authorized", False), ("task_id", "TASK-another"), ("agent_id", "agent-case"),
    ("credential_chain_hash", "0" * 64),
])
def test_runtime_rejects_ack_that_does_not_bind_before_planning(monkeypatch, field, value):
    case = preflight_case(monkeypatch)
    service = runtime_subject(case)
    ack = authorize(case)
    ack[field] = value
    service._post_json = Mock(return_value=ack)
    with pytest.raises(AgentRuntimeError) as failure:
        service.run(case.request)
    assert failure.value.reason_code == "CONTROLLED_RESULT_INVALID"
    service._plan.assert_not_called()


def test_agent_route_rejects_missing_auth_before_run_or_workflow_creation(monkeypatch):
    case = preflight_case(monkeypatch)
    service = Mock(spec=AgentRuntimeService)
    client = TestClient(make_agent_app(
        settings=Settings(agent_role="refund", agent_id="agent-refund"), service=service,
        internal_auth=internal_auth("agent-refund"),
    ))
    for path in ("/agents/run", "/agents/workflows"):
        response = client.post(path, json=case.request.model_dump(mode="json"))
        assert response.status_code == 403
    service.run.assert_not_called()
    service.prepare_workflow.assert_not_called()


def test_authority_denial_stops_real_runtime_before_planning(monkeypatch):
    case = preflight_case(monkeypatch)
    case.authority.revoked.add(case.authority.documents[0]["payload"]["credential_id"])
    client = gateway_client(monkeypatch, case)
    service = runtime_subject(case)

    def preflight_post(_base, path, document):
        body = canonicalize(document)
        headers = internal_auth("agent-refund").request_headers(
            recipient="secure-gateway", method="POST", path=path, body=body,
        )
        response = client.post(path, content=body, headers=headers)
        if response.status_code != 200:
            raise AgentRuntimeError(response.json()["reason_code"], "preflight denied")
        return response.json()

    service._post_json = preflight_post
    with pytest.raises(AgentRuntimeError) as failure:
        service.run(case.request)
    assert failure.value.reason_code == "ANCESTOR_REVOKED"
    service._plan.assert_not_called()
    forbidden_store = Mock(side_effect=AssertionError("failed preflight cannot create workflow"))
    monkeypatch.setattr(runtime_module, "WorkflowStore", forbidden_store)
    coordinator = preflight_case(monkeypatch, role="coordinator")
    service.role, service.agent_id, service.key_id = (
        "coordinator", "agent-coordinator", "agent-coordinator-key-01",
    )
    service._post_json = Mock(side_effect=AgentRuntimeError("ANCESTOR_REVOKED", "denied"))
    with pytest.raises(AgentRuntimeError):
        service.prepare_workflow(coordinator.request)
    forbidden_store.assert_not_called()
