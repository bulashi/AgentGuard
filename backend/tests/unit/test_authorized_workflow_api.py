"""Source-only acceptance cases for starting an already authorized task.

Inputs are a stored ROOT, a UiReadStore projection, and isolated upstream stubs.
Acceptance requires a later authorized test run with its actual retained log;
writing or reading this module does not verify any of these cases.

The zero signature and projection signature.valid=True are UiReadStore isolation
stubs, NOT an SM2 validity proof. Computing a full signed-object hash only checks
binding. The nontransactional read preflight cannot replace Gateway admission,
signature/revocation checks, or the final authorization decision.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import Mock, call

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError
from referencing import Resource

import backend.ui_api.service as service_module
from backend.authorization.policy import build_root_capabilities
from backend.common.schema import SchemaStore
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash, sm3_hex
from backend.ui_api.app import make_app
from backend.ui_api.contracts import QueuedWorkflowResponse, StartWorkflowRequest
from backend.ui_api.service import UiApiError, UiService
from backend.ui_api.store import UiReadStore

PROJECT_ROOT = Path(__file__).resolve().parents[3]
NOW = 1_800_000_120
TASK_ID = "TASK-AUTHORIZED-WORKFLOW-01"
ROOT_ID = "ROOT-AUTHORIZED-WORKFLOW-01"
API_PATH = f"/api/tasks/{TASK_ID}/workflow"
API_TEMPLATE = "/api/tasks/{task_id}/workflow"
UPSTREAM_PATH = "/agents/workflows"
MODES = ("deterministic", "local", "cloud")
AVAILABLE_MODES = ("deterministic", "cloud")
REDACTION_MARKER = "FORBIDDEN_WORKFLOW_TEST_DATA"
RESPONSE_FIELDS = {"run_id", "task_id", "state", "runtime_mode"}
REQUEST_FIELDS = {"runtime_mode", "scenario", "cloud_data_confirmed", "custom_injection_text"}


class RecordingUi(UiService):
    """Replace the workflow transport explicitly; never invoke production _post."""

    def __init__(self, settings, store, queued):
        super().__init__(settings, store, protocol_root=PROJECT_ROOT / "protocol")
        self.upstream = Mock(return_value=queued)
        self.calls = []
        self.workflow_request_count = 0

    def _workflow_request(self, body):
        self.workflow_request_count += 1
        return self._post(
            self.settings.coordinator_agent_url,
            UPSTREAM_PATH,
            body,
            expected_status=202,
        )

    def _post(self, base_url, path, body, *, expected_status=200):
        self.calls.append((base_url, path, deepcopy(body), expected_status))
        assert base_url == self.settings.coordinator_agent_url
        assert path == UPSTREAM_PATH, "no task creation, authorization, or synchronous run"
        assert expected_status == 202
        return self.upstream(base_url, path, body, expected_status=expected_status)


@pytest.fixture
def case() -> dict[str, Any]:
    payload = {
        "schema_version": "1.0",
        "credential_id": ROOT_ID,
        "credential_type": "ROOT",
        "issuer": {"subject_id": "authority", "key_id": "authority-key-01"},
        "holder": {
            "agent_id": "agent-coordinator",
            "key_id": "agent-coordinator-key-01",
        },
        "tenant_id": "tenant-A",
        "task_id": TASK_ID,
        "verifier_audience": "secure-tool-gateway",
        "capabilities": build_root_capabilities(
            ticket_id="T10086",
            customer_id="C9527",
            refund_total_fen=7_000,
        ),
        "quotas": {"refund_total_fen": 7_000, "max_tool_calls": 4},
        "not_before": NOW - 60,
        "expires_at": NOW + 600,
        "delegation_depth": 2,
        "parent_credential_id": None,
        "parent_credential_hash": None,
        "issued_at": NOW - 30,
    }
    root = {
        "payload": payload,
        "signature": {
            "algorithm": "SM2",
            "key_id": "authority-key-01",
            "key_purpose": "AUTHORIZATION_ROOT_SIGNING",
            "encoding": "SM2_RS_HEX_128_LOWERCASE",
            "value": "0" * 128,
            "signed_at": payload["issued_at"],
        },
    }
    projection = {
        "credential_id": ROOT_ID,
        "credential_type": "ROOT",
        "parent_credential_id": None,
        "parent_credential_hash": None,
        "signed_object_hash": signed_object_hash(root),
        "stored_hash_valid": True,
        "issuer_subject_id": "authority",
        "issuer_key_id": "authority-key-01",
        "holder_agent_id": "agent-coordinator",
        "holder_key_id": "agent-coordinator-key-01",
        "not_before": payload["not_before"],
        "expires_at": payload["expires_at"],
        "delegation_depth": payload["delegation_depth"],
        "issued_at": payload["issued_at"],
        "revoked_at": None,
        "revocation_reason": None,
        "capabilities": deepcopy(payload["capabilities"]),
        # This is the mocked read projection's assertion, never cryptographic proof.
        "signature": {
            "algorithm": "SM2",
            "key_id": "authority-key-01",
            "valid": True,
        },
    }
    return {
        "root": root,
        "snapshot": {
            "task": {
                "task_id": TASK_ID,
                "tenant_id": "tenant-A",
                "ticket_id": "T10086",
                "customer_id": "C9527",
                "refund_total_fen": 7_000,
                "max_tool_calls": 4,
                "expires_at": payload["expires_at"],
                "status": "AUTHORIZED",
                "created_at": NOW - 60,
                "updated_at": NOW - 30,
            },
            "credentials": [projection],
            "budgets": [],
            "executions": [],
            "receipts": [],
            "business_effects": {"refunds": [], "notifications": []},
            "workflow_runs": [],
            "audit_events": [],
        },
        "profiles": {
            "workflow_enabled": True,
            "items": [
                {"mode": mode, "available": True, "message": "isolated profile"}
                for mode in AVAILABLE_MODES
            ],
        },
        "queued": {
            "run_id": "RUN-AUTHORIZED-01",
            "task_id": TASK_ID,
            "state": "QUEUED",
            "runtime_mode": "deterministic",
        },
    }


@pytest.fixture
def subject(case, monkeypatch):
    store = Mock(spec=UiReadStore)
    store.task_snapshot.return_value = case["snapshot"]
    store.root_credential.return_value = case["root"]
    store.business_ticket.return_value = {
        "tenant_id": "tenant-A",
        "ticket_id": "T10086",
        "customer_id": "C9527",
        "cloud_shareable": True,
    }
    settings = Settings(
        authority_url="https://authority.invalid",
        coordinator_agent_url="https://coordinator.invalid",
        ui_request_timeout_seconds=3.25,
        coauthorization_required=True,
    )
    service = RecordingUi(settings, store, case["queued"])
    monkeypatch.setattr(service_module, "now_unix", lambda: NOW)
    monkeypatch.setattr(service, "runtime_profiles", Mock(return_value=case["profiles"]))
    monkeypatch.setattr(
        service_module.httpx,
        "Client",
        Mock(side_effect=AssertionError("RecordingUi must not access the network")),
    )
    guards = []
    for name in (
        "create_task",
        "authorize_task",
        "start_workflow",
        "run_task",
        "coauthorization_status",
    ):
        guard = Mock(side_effect=AssertionError(f"authorized start must not call {name}"))
        monkeypatch.setattr(service, name, guard)
        guards.append(guard)
    yield service
    for guard in guards:
        guard.assert_not_called()
    assert {entry[0] for entry in store.mock_calls} <= {
        "task_snapshot",
        "root_credential",
        "business_ticket",
    }


@pytest.fixture
def posted(subject):
    return subject.upstream


@pytest.fixture
def extension_schemas():
    extension = PROJECT_ROOT / "protocol" / "extensions" / "authorized-workflow-v1"
    schemas = SchemaStore(extension)
    schemas.registry = schemas.registry.with_resources(
        (document["$id"], Resource.from_contents(document))
        for document in SchemaStore(PROJECT_ROOT / "protocol" / "schemas").documents.values()
    )
    return schemas


def _request(mode="deterministic", *, scenario="normal", confirmed=None):
    return StartWorkflowRequest(
        runtime_mode=mode,
        scenario=scenario,
        cloud_data_confirmed=(mode == "cloud") if confirmed is None else confirmed,
    )


def _set_path(document, path, value):
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def _refresh_hash(case):
    case["snapshot"]["credentials"][0]["signed_object_hash"] = signed_object_hash(case["root"])


def _refresh_projection(case):
    payload = case["root"]["payload"]
    projection = case["snapshot"]["credentials"][0]
    for name in ("credential_id", "not_before", "expires_at", "delegation_depth", "issued_at"):
        projection[name] = payload[name]
    projection.update(
        issuer_subject_id=payload["issuer"]["subject_id"],
        issuer_key_id=payload["issuer"]["key_id"],
        holder_agent_id=payload["holder"]["agent_id"],
        holder_key_id=payload["holder"]["key_id"],
        capabilities=deepcopy(payload["capabilities"]),
    )
    _refresh_hash(case)


def _preflight_error(subject, posted, reason, *, status=409, request=None):
    with pytest.raises(UiApiError) as caught:
        subject.start_authorized_workflow(TASK_ID, request or _request())
    assert caught.value.reason_code == reason
    assert caught.value.status_code == status
    posted.assert_not_called()
    assert subject.workflow_request_count == 0
    assert subject.calls == []
    subject.runtime_profiles.assert_not_called()
    return caught.value


def _assert_posted(subject, case, posted, request):
    task = case["snapshot"]["task"]
    posted.assert_called_once_with(
        subject.settings.coordinator_agent_url,
        UPSTREAM_PATH,
        {
            "credential_chain": [case["root"]],
            "context": {
                "ticket_id": task["ticket_id"],
                "customer_id": task["customer_id"],
                "refund_amount_fen": task["refund_total_fen"],
                "runtime_mode": request.runtime_mode,
                "scenario": request.scenario,
                "cloud_data_confirmed": request.cloud_data_confirmed,
            },
        },
        expected_status=202,
    )
    assert subject.workflow_request_count == 1
    assert len(subject.calls) == 1
    expected_reads = [
        call.task_snapshot(TASK_ID),
        call.root_credential(TASK_ID),
    ]
    if request.runtime_mode == "cloud":
        expected_reads.append(call.business_ticket(task["ticket_id"]))
    assert subject.store.mock_calls == expected_reads


def test_root_fixture_satisfies_frozen_structure_without_claiming_signature_validity(case):
    SchemaStore(PROJECT_ROOT / "protocol" / "schemas").validate(
        "capability-credential.schema.json",
        case["root"],
    )
    assert case["root"]["signature"]["value"] == "0" * 128
    assert "value" not in case["snapshot"]["credentials"][0]["signature"]


@pytest.mark.parametrize("mode", AVAILABLE_MODES)
@pytest.mark.parametrize("coauthorization_required", [False, True])
def test_start_reuses_exact_stored_root_without_creation_or_reauthorization(
    case,
    subject,
    posted,
    mode,
    coauthorization_required,
):
    subject.settings.coauthorization_required = coauthorization_required
    case["queued"]["runtime_mode"] = mode
    before = deepcopy(case)
    request = _request(mode, scenario="policy_injection")

    result = subject.start_authorized_workflow(TASK_ID, request)

    assert result == case["queued"]
    assert set(result) == RESPONSE_FIELDS
    _assert_posted(subject, case, posted, request)
    subject.runtime_profiles.assert_called_once_with()
    assert case == before


@pytest.mark.parametrize("mode", ["deterministic"])
def test_context_uses_saved_business_task_instead_of_demo_defaults(case, subject, posted, mode):
    task = case["snapshot"]["task"]
    task.update(
        tenant_id="tenant-B",
        ticket_id="T-SAVED-73",
        customer_id="C-SAVED-91",
        refund_total_fen=7_300,
    )
    payload = case["root"]["payload"]
    payload["tenant_id"] = task["tenant_id"]
    payload["quotas"]["refund_total_fen"] = task["refund_total_fen"]
    payload["capabilities"] = build_root_capabilities(
        ticket_id=task["ticket_id"],
        customer_id=task["customer_id"],
        refund_total_fen=task["refund_total_fen"],
    )
    _refresh_projection(case)
    case["queued"]["runtime_mode"] = mode
    request = _request(mode)

    assert subject.start_authorized_workflow(TASK_ID, request) == case["queued"]
    _assert_posted(subject, case, posted, request)


def test_missing_task_is_cross_task_404_before_root_or_model_read(subject, posted):
    subject.store.task_snapshot.return_value = None
    _preflight_error(subject, posted, "CROSS_TASK", status=404)
    subject.store.root_credential.assert_not_called()


@pytest.mark.parametrize("task", [None, {}, {"task_id": "TASK-other", "status": "AUTHORIZED"}])
def test_snapshot_task_must_match_path(case, subject, posted, task):
    case["snapshot"]["task"] = task
    _preflight_error(subject, posted, "CROSS_TASK")
    subject.store.root_credential.assert_not_called()


@pytest.mark.parametrize("status", ["PENDING_AUTHORIZATION", "CLOSED", "REVOKED", "UNKNOWN", None])
def test_non_authorized_task_is_not_executable_before_model_or_root_lookup(
    case,
    subject,
    posted,
    status,
):
    case["snapshot"]["task"]["status"] = status
    case["profiles"]["workflow_enabled"] = False
    _preflight_error(subject, posted, "TASK_NOT_EXECUTABLE")
    subject.store.root_credential.assert_not_called()


@pytest.mark.parametrize(
    "kind",
    [
        "missing-stored-root",
        "no-projected-root",
        "duplicate-projected-root",
        "delegation-only",
    ],
)
def test_task_requires_one_projected_and_one_stored_root(case, subject, posted, kind):
    credentials = case["snapshot"]["credentials"]
    if kind == "missing-stored-root":
        subject.store.root_credential.return_value = None
    elif kind == "no-projected-root":
        credentials.clear()
    elif kind == "duplicate-projected-root":
        credentials.append(deepcopy(credentials[0]))
    else:
        credentials[0]["credential_type"] = "DELEGATION"
    _preflight_error(subject, posted, "TASK_NOT_EXECUTABLE")


@pytest.mark.parametrize("field,value", [("task_id", "TASK-other"), ("tenant_id", "tenant-other")])
def test_stored_root_cannot_cross_task_or_tenant(case, subject, posted, field, value):
    case["root"]["payload"][field] = value
    _refresh_hash(case)
    _preflight_error(subject, posted, "CROSS_TASK")


@pytest.mark.parametrize(
    "path,value",
    [
        (("root", "payload", "quotas", "refund_total_fen"), 6_999),
        (("root", "payload", "quotas", "refund_total_fen"), 7_001),
        (("root", "payload", "quotas", "max_tool_calls"), 3),
        (("root", "payload", "quotas", "max_tool_calls"), 5),
        (("snapshot", "task", "refund_total_fen"), 7_001),
        (("snapshot", "task", "max_tool_calls"), 5),
        (("root", "payload", "expires_at"), NOW + 599),
        (("root", "payload", "expires_at"), NOW + 601),
        (("snapshot", "task", "expires_at"), NOW + 599),
        (("snapshot", "task", "expires_at"), NOW + 601),
    ],
)
def test_root_quotas_and_expiry_bind_exactly_to_saved_task(case, subject, posted, path, value):
    _set_path(case, path, value)
    _refresh_projection(case)
    _preflight_error(subject, posted, "TASK_NOT_EXECUTABLE")


@pytest.mark.parametrize(
    "field,value",
    [
        ("credential_id", "ROOT-other"),
        ("signed_object_hash", "f" * 64),
        ("not_before", NOW - 61),
        ("expires_at", NOW + 601),
        ("delegation_depth", 3),
        ("issued_at", NOW - 31),
        ("holder_agent_id", "agent-refund"),
        ("holder_key_id", "agent-coordinator-key-02"),
        ("issuer_subject_id", "another-authority"),
        ("issuer_key_id", "authority-key-02"),
    ],
)
def test_root_identity_and_metadata_must_match_read_projection(case, subject, posted, field, value):
    case["snapshot"]["credentials"][0][field] = value
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize("kind", ["payload-tamper", "signature-tamper", "payload-only-digest"])
def test_projection_hash_binds_full_signed_root_not_only_payload(case, subject, posted, kind):
    if kind == "payload-tamper":
        case["root"]["payload"]["capabilities"][2]["constraints"]["single_max_fen"] = 6_999
    elif kind == "signature-tamper":
        case["root"]["signature"]["value"] = "1" * 128
    else:
        case["snapshot"]["credentials"][0]["signed_object_hash"] = sm3_hex(
            canonicalize(case["root"]["payload"]),
        )
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize(
    "field,value",
    [
        ("key_id", "authority-key-02"),
        ("key_purpose", "AGENT_HOLDER_SIGNING"),
        ("signed_at", NOW - 31),
    ],
)
def test_signature_metadata_remains_bound_even_with_a_validity_projection_stub(
    case, subject, posted, field, value
):
    case["root"]["signature"][field] = value
    _refresh_hash(case)
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize("field", ["stored_hash_valid", "signature.valid"])
@pytest.mark.parametrize("value", [False, None, "true", 1, {}])
def test_projection_validity_requires_literal_true(case, subject, posted, field, value):
    projection = case["snapshot"]["credentials"][0]
    _set_path(projection, tuple(field.split(".")), value)
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize(
    "kind",
    [
        "missing-hash-valid",
        "missing-signature-valid",
        "missing-signature",
        "nonobject-signature",
    ],
)
def test_incomplete_validity_projection_is_rejected(case, subject, posted, kind):
    projection = case["snapshot"]["credentials"][0]
    if kind == "missing-hash-valid":
        projection.pop("stored_hash_valid")
    elif kind == "missing-signature-valid":
        projection["signature"].pop("valid")
    elif kind == "missing-signature":
        projection.pop("signature")
    else:
        projection["signature"] = "true"
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize(
    "path,value",
    [
        (("root", "extra"), REDACTION_MARKER),
        (("root", "payload", "schema_version"), "2.0"),
        (("root", "payload", "credential_type"), "DELEGATION"),
        (("root", "payload", "verifier_audience"), "other-gateway"),
        (("root", "payload", "parent_credential_id"), "ROOT-parent"),
        (("root", "payload", "capabilities"), []),
        (("root", "payload", "quotas", "max_tool_calls"), "4"),
        (("root", "payload", "not_before"), "1800000060"),
        (("root", "payload", "delegation_depth"), 17),
        (("root", "signature", "value"), "not-an-sm2-encoding"),
        (("root", "signature", "private_key"), REDACTION_MARKER),
    ],
)
def test_frozen_root_schema_is_checked_despite_valid_projection_stubs(
    case,
    subject,
    posted,
    path,
    value,
):
    _set_path(case, path, value)
    _refresh_hash(case)
    error = _preflight_error(subject, posted, "INVALID_SIGNATURE")
    assert REDACTION_MARKER not in str(error)


@pytest.mark.parametrize("root", [[], {}, {"payload": {}}, {"payload": None, "signature": {}}])
def test_malformed_stored_root_is_a_controlled_rejection(subject, posted, root):
    subject.store.root_credential.return_value = root
    _preflight_error(subject, posted, "INVALID_SIGNATURE")


@pytest.mark.parametrize("revoked_at", [0, NOW - 1, NOW])
def test_any_recorded_root_revocation_prevents_start(case, subject, posted, revoked_at):
    case["snapshot"]["credentials"][0].update(
        revoked_at=revoked_at,
        revocation_reason="ROOT_REVOKED",
    )
    _preflight_error(subject, posted, "ANCESTOR_REVOKED")


@pytest.mark.parametrize(
    "not_before,expires_at,allowed",
    [
        (NOW - 1, NOW + 600, True),
        (NOW, NOW + 600, True),
        (NOW + 1, NOW + 600, False),
        (NOW - 60, NOW + 1, True),
        (NOW - 60, NOW, False),
        (NOW - 60, NOW - 1, False),
    ],
)
def test_root_time_interval_is_inclusive_lower_and_exclusive_upper(
    case,
    subject,
    posted,
    not_before,
    expires_at,
    allowed,
):
    case["root"]["payload"].update(not_before=not_before, expires_at=expires_at)
    case["snapshot"]["task"]["expires_at"] = expires_at
    _refresh_projection(case)
    if allowed:
        request = _request()
        assert subject.start_authorized_workflow(TASK_ID, request) == case["queued"]
        _assert_posted(subject, case, posted, request)
    else:
        _preflight_error(subject, posted, "CREDENTIAL_EXPIRED")


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "agent-refund"),
        ("key_id", "agent-coordinator-key-02"),
    ],
)
def test_coordinator_agent_and_exact_key_are_required(case, subject, posted, field, value):
    case["root"]["payload"]["holder"][field] = value
    _refresh_projection(case)
    _preflight_error(subject, posted, "WRONG_HOLDER")


@pytest.mark.parametrize("depth", [0, 1, 2, 16])
def test_root_requires_at_least_two_delegation_levels(case, subject, posted, depth):
    case["root"]["payload"]["delegation_depth"] = depth
    _refresh_projection(case)
    if depth < 2:
        _preflight_error(subject, posted, "DELEGATION_ESCALATION")
    else:
        request = _request()
        assert subject.start_authorized_workflow(TASK_ID, request) == case["queued"]
        _assert_posted(subject, case, posted, request)


def test_expiry_is_reported_before_wrong_holder_or_insufficient_depth(case, subject, posted):
    payload = case["root"]["payload"]
    payload.update(expires_at=NOW, delegation_depth=1)
    payload["holder"]["agent_id"] = "agent-refund"
    case["snapshot"]["task"]["expires_at"] = NOW
    _refresh_projection(case)
    _preflight_error(subject, posted, "CREDENTIAL_EXPIRED")


@pytest.mark.parametrize(
    "state",
    [
        "QUEUED",
        "RUNNING",
        "COMPLETED",
        "DENIED",
        "FAILED",
        "INTERRUPTED",
    ],
)
def test_existing_workflow_in_any_state_prevents_another_start(case, subject, posted, state):
    case["snapshot"]["workflow_runs"] = [{"run_id": "RUN-existing", "state": state}]
    _preflight_error(subject, posted, "WORKFLOW_ALREADY_EXISTS")
    subject.store.root_credential.assert_not_called()


@pytest.mark.parametrize("kind", ["execution", "refund", "notification"])
def test_existing_execution_or_business_effect_prevents_start(case, subject, posted, kind):
    snapshot = case["snapshot"]
    if kind == "execution":
        snapshot["executions"] = [{"execution_id": "EXEC-existing", "decision": "DENY"}]
    elif kind == "refund":
        snapshot["business_effects"]["refunds"] = [{"refund_id": "REFUND-existing"}]
    else:
        snapshot["business_effects"]["notifications"] = [{"notification_id": "NOTICE-existing"}]
    _preflight_error(subject, posted, "TASK_ALREADY_STARTED")
    subject.store.root_credential.assert_not_called()


def test_seed_cloud_task_still_requires_explicit_synthetic_data_confirmation(subject, posted):
    with pytest.raises(UiApiError) as caught:
        subject.start_authorized_workflow(TASK_ID, _request("cloud", confirmed=False))
    assert caught.value.reason_code == "CLOUD_CONFIRMATION_REQUIRED"
    assert caught.value.status_code == 400
    posted.assert_not_called()
    subject.runtime_profiles.assert_called_once_with()


def test_existing_delegation_is_not_a_second_root_or_a_business_execution(case, subject, posted):
    delegation = deepcopy(case["snapshot"]["credentials"][0])
    delegation.update(
        credential_type="DELEGATION",
        credential_id="CHILD-existing",
        parent_credential_id=ROOT_ID,
    )
    case["snapshot"]["credentials"].append(delegation)
    request = _request()
    assert subject.start_authorized_workflow(TASK_ID, request) == case["queued"]
    _assert_posted(subject, case, posted, request)
    assert posted.call_args.args[2]["credential_chain"] == [case["root"]]


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "tenant-B"),
        ("ticket_id", "T-other"),
        ("customer_id", "C-other"),
    ],
)
def test_cloud_refuses_business_scope_outside_server_seed_even_when_confirmed(
    case,
    subject,
    posted,
    field,
    value,
):
    task = case["snapshot"]["task"]
    task[field] = value
    payload = case["root"]["payload"]
    payload["tenant_id"] = task["tenant_id"]
    payload["capabilities"] = build_root_capabilities(
        ticket_id=task["ticket_id"],
        customer_id=task["customer_id"],
        refund_total_fen=task["refund_total_fen"],
    )
    _refresh_projection(case)
    _preflight_error(
        subject,
        posted,
        "CLOUD_TASK_SCOPE_DENIED",
        status=403,
        request=_request("cloud", confirmed=True),
    )


@pytest.mark.parametrize("mode", AVAILABLE_MODES)
@pytest.mark.parametrize("kind", ["disabled", "missing-profile", "unavailable", "truthy-not-bool"])
def test_runtime_profile_must_be_explicitly_available_before_post(
    case,
    subject,
    posted,
    mode,
    kind,
):
    profiles = case["profiles"]
    if kind == "disabled":
        profiles["workflow_enabled"] = False
    elif kind == "missing-profile":
        profiles["items"] = [item for item in profiles["items"] if item["mode"] != mode]
    else:
        profile = next(item for item in profiles["items"] if item["mode"] == mode)
        profile["available"] = False if kind == "unavailable" else "true"
    with pytest.raises(UiApiError) as caught:
        subject.start_authorized_workflow(TASK_ID, _request(mode))
    assert caught.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    assert caught.value.status_code == 503
    posted.assert_not_called()
    subject.runtime_profiles.assert_called_once_with()


@pytest.mark.parametrize("coauthorization_required", [False, True])
def test_retired_local_authorized_start_does_not_queue_or_reauthorize(
    case,
    subject,
    posted,
    coauthorization_required,
):
    subject.settings.coauthorization_required = coauthorization_required
    before = deepcopy(case)
    with pytest.raises(UiApiError) as caught:
        subject.start_authorized_workflow(TASK_ID, _request("local"))
    assert caught.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    assert caught.value.status_code == 503
    posted.assert_not_called()
    assert subject.workflow_request_count == 0
    assert case == before
    subject.runtime_profiles.assert_not_called()


def test_missing_coordinator_url_cannot_queue_even_with_stubbed_available_profile(subject, posted):
    subject.settings.coordinator_agent_url = ""
    with pytest.raises(UiApiError) as caught:
        subject.start_authorized_workflow(TASK_ID, _request())
    assert caught.value.reason_code == "MODEL_MODE_UNAVAILABLE"
    assert caught.value.status_code == 503
    assert subject.workflow_request_count == 0
    posted.assert_not_called()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("scenario", ["normal", "policy_injection"])
def test_start_request_has_only_four_public_fields(extension_schemas, mode, scenario):
    request = _request(mode, scenario=scenario)
    assert set(request.model_dump(mode="json")) == REQUEST_FIELDS
    assert type(request.cloud_data_confirmed) is bool
    schema = StartWorkflowRequest.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == REQUEST_FIELDS
    extension_schemas.validate("start-request.schema.json", request.model_dump(mode="json"))


@pytest.mark.parametrize("mode", MODES)
def test_queued_response_has_exact_required_public_shape(case, extension_schemas, mode):
    document = dict(case["queued"], runtime_mode=mode)
    assert QueuedWorkflowResponse.model_validate(document).model_dump(mode="json") == document
    schema = QueuedWorkflowResponse.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == RESPONSE_FIELDS
    assert set(schema["required"]) == RESPONSE_FIELDS
    extension_schemas.validate("queued-response.schema.json", document)


def _client(subject):
    return TestClient(make_app(settings=subject.settings, service=subject))


@pytest.mark.parametrize("mode", AVAILABLE_MODES)
@pytest.mark.parametrize("scenario", ["normal", "policy_injection"])
def test_http_route_returns_202_for_the_same_task_and_mode(case, subject, posted, mode, scenario):
    case["queued"]["runtime_mode"] = mode
    request = _request(mode, scenario=scenario)
    response = _client(subject).post(API_PATH, json=request.model_dump(mode="json"))
    assert response.status_code == 202
    assert response.json() == case["queued"]
    assert set(response.json()) == RESPONSE_FIELDS
    _assert_posted(subject, case, posted, request)


def test_http_empty_object_uses_explicit_public_defaults(case, subject, posted):
    response = _client(subject).post(API_PATH, json={})
    assert response.status_code == 202
    assert response.json() == case["queued"]
    request = StartWorkflowRequest()
    assert request.model_dump(mode="json") == {
        "runtime_mode": "deterministic",
        "scenario": "normal",
        "cloud_data_confirmed": False,
        "custom_injection_text": None,
    }
    _assert_posted(subject, case, posted, request)


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_mode", "other"),
        ("runtime_mode", None),
        ("runtime_mode", 1),
        ("scenario", "unknown"),
        ("scenario", None),
        ("cloud_data_confirmed", "true"),
        ("cloud_data_confirmed", "false"),
        ("cloud_data_confirmed", 1),
        ("cloud_data_confirmed", 0),
        ("cloud_data_confirmed", None),
        ("cloud_data_confirmed", []),
        ("credential", REDACTION_MARKER),
        ("root_credential", REDACTION_MARKER),
        ("credential_chain", [{"signature": REDACTION_MARKER}]),
        ("budget", REDACTION_MARKER),
        ("budgets", []),
        ("quotas", {"max_tool_calls": 99}),
        ("amount", 999_999),
        ("amount_fen", 999_999),
        ("refund_amount_fen", 999_999),
        ("token", REDACTION_MARKER),
        ("workflow_token", REDACTION_MARKER),
        ("api_key", REDACTION_MARKER),
        ("model_url", "https://attacker.invalid"),
        ("task_id", "TASK-other"),
        ("tenant_id", "tenant-other"),
        ("ticket_id", "T-other"),
        ("customer_id", "C-other"),
        ("context", {"refund_amount_fen": 999_999}),
    ],
)
def test_http_and_request_contract_reject_nonpublic_fields_or_coercion(
    subject,
    posted,
    extension_schemas,
    monkeypatch,
    field,
    value,
):
    document = _request().model_dump(mode="json")
    document[field] = value
    with pytest.raises(ValidationError):
        StartWorkflowRequest.model_validate(document)
    assert not extension_schemas.validator("start-request.schema.json").is_valid(document)
    dispatch = Mock(wraps=subject.start_authorized_workflow)
    monkeypatch.setattr(subject, "start_authorized_workflow", dispatch)

    response = _client(subject).post(API_PATH, json=document)

    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    assert set(response.json()) == {"reason_code", "message"}
    assert REDACTION_MARKER not in response.text
    dispatch.assert_not_called()
    posted.assert_not_called()
    assert subject.store.mock_calls == []


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            b'{"runtime_mode":"deterministic","runtime_mode":"local"}',
            id="duplicate-mode",
        ),
        pytest.param(
            b'{"scenario":"normal","scenario":"policy_injection"}',
            id="duplicate-scenario",
        ),
        pytest.param(
            b'{"cloud_data_confirmed":false,"cloud_data_confirmed":true}',
            id="duplicate-confirmation",
        ),
        pytest.param(
            b'{"runtime_mode":"deterministic","\\u0072untime_mode":"local"}',
            id="escaped-duplicate-mode",
        ),
        pytest.param(b'{"cloud_data_confirmed":NaN}', id="nan"),
        pytest.param(b'{"cloud_data_confirmed":Infinity}', id="infinity"),
        pytest.param(b'{"runtime_mode":"deterministic",}', id="malformed"),
        pytest.param(b"[]", id="array"),
        pytest.param(b"null", id="null"),
        pytest.param(b'"deterministic"', id="string"),
        pytest.param(b"1", id="number"),
        pytest.param(b"", id="missing-body"),
    ],
)
def test_http_strict_json_refuses_ambiguous_or_nonobject_body(subject, posted, monkeypatch, raw):
    dispatch = Mock(wraps=subject.start_authorized_workflow)
    monkeypatch.setattr(subject, "start_authorized_workflow", dispatch)
    response = _client(subject).post(
        API_PATH,
        content=raw,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    dispatch.assert_not_called()
    posted.assert_not_called()
    assert subject.store.mock_calls == []


@pytest.mark.parametrize(
    "task_id",
    [
        "invalid!id",
        "_invalid-leading",
        "has%20space",
        "TASK%00bad",
        "x" * 129,
        "%E4%BB%BB%E5%8A%A1",
    ],
)
def test_http_invalid_path_identifier_is_400_before_service(subject, posted, monkeypatch, task_id):
    dispatch = Mock(wraps=subject.start_authorized_workflow)
    monkeypatch.setattr(subject, "start_authorized_workflow", dispatch)
    response = _client(subject).post(
        f"/api/tasks/{task_id}/workflow",
        json=_request().model_dump(mode="json"),
    )
    assert response.status_code == 400
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    dispatch.assert_not_called()
    posted.assert_not_called()
    assert subject.store.mock_calls == []


def _assert_unconfirmed_response(case, subject, posted, *, status=502):
    request = _request()
    response = _client(subject).post(API_PATH, json=request.model_dump(mode="json"))
    assert response.status_code == status
    assert response.json()["reason_code"] == "WORKFLOW_RESULT_UNCONFIRMED"
    assert set(response.json()) == {"reason_code", "message"}
    assert REDACTION_MARKER not in response.text
    assert "state" not in response.json(), "an unknown queue result is not execution FAILED"
    _assert_posted(subject, case, posted, request)
    return response


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", ""),
        ("run_id", None),
        ("run_id", 1),
        ("run_id", "RUN invalid"),
        ("run_id", "r" * 129),
        ("task_id", ""),
        ("task_id", None),
        ("task_id", 1),
        ("task_id", "TASK!invalid"),
        ("state", "RUNNING"),
        ("state", "COMPLETED"),
        ("state", "FAILED"),
        ("state", None),
        ("state", True),
        ("runtime_mode", "other"),
        ("runtime_mode", None),
        ("runtime_mode", True),
        ("extra", REDACTION_MARKER),
        ("token", REDACTION_MARKER),
        ("workflow_token", REDACTION_MARKER),
        ("credential_chain", [{"signature": REDACTION_MARKER}]),
    ],
)
def test_invalid_or_extended_queue_ack_is_unconfirmed_without_retry(
    case,
    subject,
    posted,
    extension_schemas,
    field,
    value,
):
    document = dict(case["queued"])
    document[field] = value
    with pytest.raises(ValidationError):
        QueuedWorkflowResponse.model_validate(document)
    assert not extension_schemas.validator("queued-response.schema.json").is_valid(document)
    posted.return_value = document
    _assert_unconfirmed_response(case, subject, posted)


@pytest.mark.parametrize("field", sorted(RESPONSE_FIELDS))
def test_queue_ack_cannot_omit_any_public_field(case, subject, posted, extension_schemas, field):
    document = dict(case["queued"])
    document.pop(field)
    with pytest.raises(ValidationError):
        QueuedWorkflowResponse.model_validate(document)
    assert not extension_schemas.validator("queued-response.schema.json").is_valid(document)
    posted.return_value = document
    _assert_unconfirmed_response(case, subject, posted)


@pytest.mark.parametrize("document", [None, [], "queued", 1])
def test_nonobject_queue_ack_is_unconfirmed_without_retry(case, subject, posted, document):
    posted.return_value = document
    _assert_unconfirmed_response(case, subject, posted)


@pytest.mark.parametrize("field,value", [("task_id", "TASK-other"), ("runtime_mode", "local")])
def test_structurally_valid_ack_must_bind_to_requested_task_and_mode(
    case,
    subject,
    posted,
    field,
    value,
):
    document = dict(case["queued"])
    document[field] = value
    QueuedWorkflowResponse.model_validate(document)
    posted.return_value = document
    _assert_unconfirmed_response(case, subject, posted)


def test_definite_upstream_409_is_preserved_after_read_preflight(case, subject, posted):
    # The coordinator may observe a concurrent run after the read-side preflight.
    posted.side_effect = UiApiError(
        "WORKFLOW_ALREADY_EXISTS",
        "coordinator rejected this start",
        status_code=409,
    )
    request = _request()
    response = _client(subject).post(API_PATH, json=request.model_dump(mode="json"))
    assert response.status_code == 409
    assert response.json()["reason_code"] == "WORKFLOW_ALREADY_EXISTS"
    assert set(response.json()) == {"reason_code", "message"}
    _assert_posted(subject, case, posted, request)


@pytest.mark.parametrize(
    "reason,status,expected_status",
    [
        ("WORKFLOW_RESULT_UNCONFIRMED", 502, 502),
        ("WORKFLOW_RESULT_UNCONFIRMED", 503, 503),
        ("INVALID_SIGNATURE", 500, 502),
        ("INVALID_SIGNATURE", 503, 503),
        ("CONTROLLED_RESULT_INVALID", 502, 502),
    ],
)
def test_nondeterministic_upstream_error_never_becomes_failed_execution_or_retry(
    case,
    subject,
    posted,
    reason,
    status,
    expected_status,
):
    posted.side_effect = UiApiError(reason, REDACTION_MARKER, status_code=status)
    _assert_unconfirmed_response(case, subject, posted, status=expected_status)


def test_generated_openapi_matches_public_request_response_and_path_constraints(subject):
    document = make_app(settings=subject.settings, service=subject).openapi()
    operation = document["paths"][API_TEMPLATE]["post"]
    assert operation["requestBody"]["required"] is True
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/StartWorkflowRequest",
    }
    assert operation["responses"]["202"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/QueuedWorkflowResponse",
    }
    assert {"400", "403", "404", "409", "502", "503"} <= set(operation["responses"])
    assert "422" not in operation["responses"]
    assert operation["responses"]["400"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/WorkflowErrorResponse",
    }
    schemas = document["components"]["schemas"]
    assert schemas["StartWorkflowRequest"]["additionalProperties"] is False
    assert set(schemas["StartWorkflowRequest"]["properties"]) == REQUEST_FIELDS
    assert schemas["QueuedWorkflowResponse"]["additionalProperties"] is False
    assert set(schemas["QueuedWorkflowResponse"]["properties"]) == RESPONSE_FIELDS
    assert set(schemas["QueuedWorkflowResponse"]["required"]) == RESPONSE_FIELDS
    parameter = next(item for item in operation["parameters"] if item["name"] == "task_id")
    assert parameter["in"] == "path" and parameter["required"] is True
    assert parameter["schema"]["minLength"] == 1
    assert parameter["schema"]["maxLength"] == 128
    assert parameter["schema"]["pattern"] == r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"


def test_extension_openapi_documents_existing_task_route_and_strict_queue_boundary():
    extension = PROJECT_ROOT / "protocol" / "extensions" / "authorized-workflow-v1"
    document = yaml.safe_load((extension / "openapi.yaml").read_text(encoding="utf-8"))
    operation = document["paths"][API_TEMPLATE]["post"]
    assert operation["requestBody"]["required"] is True
    assert operation["requestBody"]["x-agentguard-strict-json"] is True
    assert operation["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "./start-request.schema.json",
    }
    assert operation["responses"]["202"]["content"]["application/json"]["schema"] == {
        "$ref": "./queued-response.schema.json",
    }
    assert {"400", "403", "404", "409", "502", "503"} <= set(operation["responses"])
    request_schema = json.loads(
        (extension / "start-request.schema.json").read_text(encoding="utf-8"),
    )
    assert request_schema["$ref"] == "https://agentguard.local/schemas/workflow-start.schema.json"
    response_schema = json.loads(
        (extension / "queued-response.schema.json").read_text(encoding="utf-8"),
    )
    assert response_schema["additionalProperties"] is False
    assert set(response_schema["required"]) == RESPONSE_FIELDS
    assert set(response_schema["properties"]) == RESPONSE_FIELDS
    queue = document["x-agentguard-queue-response"]
    assert queue["maximum-bytes"] == 65_536
    assert queue["strict-json"] is True
    assert set(queue["required-binding"]) == {"task_id", "runtime_mode"}
    assert queue["accepted-state"] == "QUEUED"
    assert queue["extra-fields"] == "forbidden"
