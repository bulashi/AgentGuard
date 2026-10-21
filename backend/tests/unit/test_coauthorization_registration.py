from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError

from backend.coauthorization.contracts import PublicApprovalSetup, RegisteredApprovalKey, TrustedApprovalPolicy
from backend.coauthorization.service import _valid_public_point
from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT
from backend.common.schema import SchemaStore
from backend.crypto.sm import generate_keypair


@pytest.fixture
def registration() -> dict:
    now = 1_800_000_000
    keys = []
    for role, name in (("ENTERPRISE_APPROVER", "enterprise"), ("FINANCE_APPROVER", "finance")):
        pair = generate_keypair()
        keys.append({
            "tenant_id": "tenant-registration-test", "subject_id": name + "-subject",
            "principal_id": name + "-principal", "key_id": name + "-key", "role": role,
            "approval_purpose": "TASK_COAUTHORIZATION_APPROVAL_V1",
            "signing_purpose": "AUTHORIZATION_ROOT_SIGNING", "algorithm": "SM2",
            "public_key_hex": pair.public_key_hex, "status": "ACTIVE",
            "activated_at": now - 100, "expires_at": now + 1000,
            "retired_at": None, "revoked_at": None, "compromised_at": None,
        })
    return {"keys": keys, "policy": {
        "tenant_id": "tenant-registration-test", "revision": "test-v1",
        "required_signers": {
            "enterprise_approver": {"subject_id": keys[0]["subject_id"], "key_id": keys[0]["key_id"]},
            "finance_approver": {"subject_id": keys[1]["subject_id"], "key_id": keys[1]["key_id"]},
        },
        "not_before": now, "expires_at": now + 900,
    }}


def test_public_registration_contains_only_two_governed_public_keys(registration: dict) -> None:
    setup = PublicApprovalSetup.model_validate(registration)
    assert len(setup.keys) == 2
    assert all(_valid_public_point(key.public_key_hex) for key in setup.keys)
    assert len({key.principal_id for key in setup.keys}) == 2


def test_public_setup_schema_matches_contract_fields(registration: dict) -> None:
    store = SchemaStore(EXTENSION_SCHEMA_ROOT)
    document = store.documents["public-approval-setup.schema.json"]
    store.validate("public-approval-setup.schema.json", registration)
    for model, schema in (
        (PublicApprovalSetup, document),
        (TrustedApprovalPolicy, document["$defs"]["policy"]),
        (RegisteredApprovalKey, document["$defs"]["publicKey"]),
    ):
        assert set(model.model_fields) == set(schema["properties"]) == set(schema["required"])


@pytest.mark.parametrize("target", ["root", "policy", "key"])
def test_public_setup_schema_rejects_private_material(registration: dict, target: str) -> None:
    selected = {"root": registration, "policy": registration["policy"], "key": registration["keys"][0]}[target]
    selected["private_key_hex"] = "forbidden"
    with pytest.raises(SchemaValidationError):
        SchemaStore(EXTENSION_SCHEMA_ROOT).validate("public-approval-setup.schema.json", registration)


@pytest.mark.parametrize("field", ["principal_id", "subject_id", "key_id", "public_key_hex"])
def test_public_registration_rejects_two_aliases_for_one_principal_or_key(registration: dict, field: str) -> None:
    registration["keys"][1][field] = registration["keys"][0][field]
    with pytest.raises(ValidationError):
        PublicApprovalSetup.model_validate(registration)


@pytest.mark.parametrize("updates", [
    {"tenant_id": "other-tenant"}, {"role": "ENTERPRISE_APPROVER"},
    {"status": "REVOKED", "revoked_at": 1_800_000_000},
    {"retired_at": 1_800_000_000}, {"compromised_at": 1_800_000_000},
    {"activated_at": 1_800_000_001}, {"expires_at": 1_800_000_899},
    {"signing_purpose": "AGENT_HOLDER_SIGNING"},
    {"private_key_hex": "not-accepted-or-used"},
])
def test_public_registration_rejects_unsafe_metadata(registration: dict, updates: dict) -> None:
    registration["keys"][1].update(deepcopy(updates))
    with pytest.raises(ValidationError):
        PublicApprovalSetup.model_validate(registration)


@pytest.mark.parametrize("public_key", ["0" * 128, "f" * 128, "0" * 127 + "1"])
def test_invalid_sm2_points_cannot_be_registered(public_key: str) -> None:
    assert not _valid_public_point(public_key)
