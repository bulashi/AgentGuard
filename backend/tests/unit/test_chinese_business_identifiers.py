from __future__ import annotations

from copy import deepcopy
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError

from backend.authorization.contracts import AuthorizeTaskRequest, CreateTaskRequest
from backend.common.enums import KeyPurpose
from backend.common.schema import SchemaStore
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import CAPABILITY_CREDENTIAL
from backend.crypto.sm import generate_keypair, sign_payload, verify_payload
from backend.tests.fixtures import valid_schema_instances
from backend.ui_api.app import make_app


def task_body(**changes) -> dict:
    return {
        "tenant_id": "演示企业（华东）", "ticket_id": "T10088", "customer_id": "张三",
        "refund_total_fen": 7000, "max_tool_calls": 4, "expires_in_seconds": 1800, **changes,
    }


@pytest.mark.parametrize("value", ["演示企业", "张三", "客户-C9527", "公司（华东）", "公司(华东)", "张三·测试", "tenant-A"])
@pytest.mark.parametrize("field", ["tenant_id", "customer_id"])
def test_chinese_business_input_keeps_exact_text(field: str, value: str) -> None:
    assert CreateTaskRequest.model_validate(task_body(**{field: value})).model_dump()[field] == value


@pytest.mark.parametrize("value", ["", " 张三", "张三 ", "张 三", "张三\n", "张三\r", "张三\x00", "张\u200b三", "张\u202e三", "张三/四", "<script>", "张" * 129])
@pytest.mark.parametrize("field", ["tenant_id", "customer_id"])
def test_invalid_business_input_is_rejected_by_python_and_schema(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(task_body(**{field: value}))
    store = SchemaStore()
    credential = deepcopy(valid_schema_instances()["capability-credential.schema.json"])
    if field == "tenant_id":
        credential["payload"]["tenant_id"] = value
    else:
        credential["payload"]["capabilities"][0]["resources"] = {"customer_ids": [value]}
    with pytest.raises(SchemaValidationError):
        store.validate("capability-credential.schema.json", credential)


def test_crypto_binds_exact_chinese_business_identity() -> None:
    pair = generate_keypair()
    payload = {"tenant_id": "演示企业", "customer_id": "张三"}
    assert "张三".encode("utf-8") in canonicalize(payload)
    signature = sign_payload(
        payload, domain_separator=CAPABILITY_CREDENTIAL, key_id="key-test",
        key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING, private_key_hex=pair.private_key_hex,
        public_key_hex=pair.public_key_hex, signed_at=1,
    )
    args = {"domain_separator": CAPABILITY_CREDENTIAL, "expected_key_id": "key-test",
            "expected_key_purpose": KeyPurpose.AUTHORIZATION_ROOT_SIGNING, "public_key_hex": pair.public_key_hex}
    assert verify_payload(payload, signature, **args)
    assert not verify_payload({**payload, "customer_id": "李四"}, signature, **args)


def test_chinese_never_relaxes_holder_or_ticket_identifiers() -> None:
    with pytest.raises(ValidationError):
        CreateTaskRequest.model_validate(task_body(ticket_id="中文工单"))
    with pytest.raises(ValidationError):
        AuthorizeTaskRequest.model_validate({
            "confirmed": True, "confirmer_id": "policy-refund-v1", "holder_agent_id": "中文密钥主体",
            "holder_key_id": "holder-key", "delegation_depth": 2,
        })


def test_ui_returns_chinese_field_errors_without_echoing_inputs() -> None:
    service = Mock()
    client = TestClient(make_app(settings=Settings(), service=service))
    response = client.post("/api/tasks", json=task_body(customer_id="张三\n"))
    assert response.status_code == 422
    assert response.json()["reason_code"] == "REQUEST_SCHEMA_INVALID"
    assert "客户" in response.json()["field_errors"]["customer_id"]
    assert "张三" not in response.text
    service.create_task.assert_not_called()


def test_ui_accepts_chinese_and_lists_existing_business_records() -> None:
    service = Mock()
    service.create_task.return_value = {"task_id": "TASK-chinese", "status": "PENDING_AUTHORIZATION"}
    service.store.list_business_tickets.return_value = [{
        "ticket_id": "T10088", "tenant_id": "演示企业", "customer_id": "张三", "title": "演示工单",
    }]
    client = TestClient(make_app(settings=Settings(), service=service))
    assert client.post("/api/tasks", json=task_body()).status_code == 201
    assert service.create_task.call_args.args[0].customer_id == "张三"
    response = client.get("/api/business/tickets")
    assert response.status_code == 200
    assert response.json()["items"][0]["customer_id"] == "张三"
