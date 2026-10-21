from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import ValidationError

from backend.common.schema import SchemaStore
from backend.tests.fixtures import valid_schema_instances


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore()


def test_all_thirteen_protocol_objects_have_positive_cases(store: SchemaStore) -> None:
    instances = valid_schema_instances()
    assert len(instances) == 13
    for schema_name, instance in instances.items():
        store.validate(schema_name, instance)


@pytest.mark.parametrize(
    ("schema_name", "mutator"),
    [
        ("request-envelope.schema.json", lambda value: value.update({"unknown": True})),
        (
            "request-envelope.schema.json",
            lambda value: value["canonical_parameters"].update({"amount_fen": "10000"}),
        ),
        (
            "request-envelope.schema.json",
            lambda value: value["canonical_parameters"].update({"amount_fen": -1}),
        ),
        (
            "request-envelope.schema.json",
            lambda value: value["canonical_parameters"].update(
                {"amount_fen": 9_007_199_254_740_992}
            ),
        ),
        (
            "capability-credential.schema.json",
            lambda value: value["payload"].pop("parent_credential_id"),
        ),
    ],
)
def test_negative_schema_cases_are_rejected(
    store: SchemaStore,
    schema_name: str,
    mutator,
) -> None:
    value = deepcopy(valid_schema_instances()[schema_name])
    mutator(value)
    with pytest.raises(ValidationError):
        store.validate(schema_name, value)


def test_deny_receipt_cannot_claim_effect_or_committed_budget(store: SchemaStore) -> None:
    receipt = deepcopy(valid_schema_instances()["execution-receipt.schema.json"])
    receipt["payload"].update(
        {
            "receipt_type": "AUTHORIZATION_DENIAL",
            "decision": "DENY",
            "reason_code": "BUDGET_EXCEEDED",
            "business_effect_id": "forbidden-effect",
            "business_result_hash": "0" * 64,
            "budget_reserved": 1,
            "budget_committed": 1,
            "business_effect_finalized_at": None,
        }
    )
    with pytest.raises(ValidationError):
        store.validate("execution-receipt.schema.json", receipt)
