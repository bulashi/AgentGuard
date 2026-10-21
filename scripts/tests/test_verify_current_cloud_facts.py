"""Offline tests of evidence guards; these fixtures are not real cloud-call evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from scripts import verify_current_cloud as cloud


def business_and_snapshot() -> tuple[dict, dict]:
    facts = {
        "schema_version": "1.0",
        "order": {"order_id": "ORDER-FACT", "amount_fen": 7000, "currency": "CNY"},
        "payments": [
            {
                "transaction_id": f"PAY-{index}",
                "amount_fen": 7000,
                "status": "SUCCESS",
                "refunded_amount_fen": 0,
            }
            for index in (1, 2)
        ],
        "claim_text": "客户反映可能重复扣款, 请核对支付。",
    }
    business = {
        "ticket_id": "T-FACT",
        "tenant_id": "tenant-A",
        "customer_id": "C-FACT",
        "business_facts": facts,
        "facts_hash": sm3_hex(canonicalize(facts)),
    }
    ticket = {"status": "OPEN", **business}
    inputs = {
        "ticket": ticket,
        "authorized_task": {
            "ticket_id": "T-FACT",
            "customer_id": "C-FACT",
            "refund_limit_fen": 7000,
        },
    }
    events = [
        {
            "action": "call_tool",
            "sequence": 3,
            "details": {"tool": "ticket.read", "output": deepcopy(ticket)},
        },
        {
            "action": "plan",
            "sequence": 4,
            "details": {
                "stage": "refund",
                "input": inputs,
                "user_prompt": json.dumps({"input": inputs}),
                "prompt_messages_sm3": "a" * 64,
            },
        },
        {"action": "business_verification", "sequence": 5, "details": {}},
    ]
    return business, {"workflow_runs": [{"events": events}]}


def test_fact_model_input_guard_accepts_actual_prompt_shape_with_raw_facts():
    business, value = business_and_snapshot()
    verified = cloud.verify_fact_model_input(value, business)
    assert verified["original_facts_in_actual_refund_prompt"] is True
    assert verified["no_precomputed_verdict_in_refund_prompt"] is True
    assert verified["cloud_proposal_before_independent_verdict"] is True


@pytest.mark.parametrize("location", ["tool", "prompt"])
def test_fact_model_input_guard_rejects_a_precomputed_verdict(location):
    business, value = business_and_snapshot()
    if location == "tool":
        value["workflow_runs"][0]["events"][0]["details"]["output"]["business_verification"] = {
            "status": "VERIFIED"
        }
    else:
        details = value["workflow_runs"][0]["events"][1]["details"]
        details["input"]["ticket"]["business_verification"] = {"status": "VERIFIED"}
        details["user_prompt"] = json.dumps({"input": details["input"]})
    with pytest.raises(RuntimeError, match="precomputed verdict"):
        cloud.verify_fact_model_input(value, business)


def test_fact_model_input_guard_rejects_changed_actual_model_prompt():
    business, value = business_and_snapshot()
    details = value["workflow_runs"][0]["events"][1]["details"]
    changed = deepcopy(details["input"])
    changed["ticket"]["business_facts"]["payments"][1]["status"] = "FAILED"
    details["user_prompt"] = json.dumps({"input": changed})
    with pytest.raises(RuntimeError, match="actual cloud prompt differs"):
        cloud.verify_fact_model_input(value, business)


def test_fact_model_input_guard_rejects_independent_verdict_before_cloud_proposal():
    business, value = business_and_snapshot()
    value["workflow_runs"][0]["events"][2]["sequence"] = 2
    with pytest.raises(RuntimeError, match="before the actual cloud"):
        cloud.verify_fact_model_input(value, business)


def test_fact_case_failure_retains_raw_request_and_stops_before_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def create_business(path, *, json):
        assert path == "/api/business/cases"
        assert "verification_status" not in json and "business_verification" not in json
        assert json["cloud_shareable"] is True
        assert [payment["status"] for payment in json["payments"]] == ["SUCCESS", "SUCCESS"]
        facts = {
            "schema_version": "1.0",
            "order": {"order_id": json["order_id"], "amount_fen": 7000, "currency": "CNY"},
            "payments": json["payments"],
            "claim_text": json["claim_text"],
        }
        body = {**json, "business_facts": facts, "facts_hash": sm3_hex(canonicalize(facts))}
        return SimpleNamespace(status_code=201, json=lambda: body)

    def forbidden(*_args, **_kwargs):
        pytest.fail("a precomputed verdict must stop the facts test before authorization/cloud")

    monkeypatch.setattr(cloud, "authorize_case", forbidden)
    monkeypatch.setattr(cloud, "run_case", forbidden)
    monkeypatch.setattr(
        cloud,
        "fact_verdict_counts",
        lambda *_args: {
            "refund_eligibility": 1,
            "business_payment_verifications": 0,
            "business_fact_evaluations": 0,
        },
    )
    directory = tmp_path / "facts-normal"
    result = cloud.run_fact_driven_case(
        SimpleNamespace(post=create_business), {"main": "offline-unit-target"}, directory
    )

    assert result["status"] == "FAIL"
    assert "precomputed a verdict" in result["failure"]["message"]
    assert (directory / "business-case-request.json").is_file()
    assert (directory / "verdict-counts-after-creation.json").is_file()
    assert json.loads((directory / "facts-normal-result.json").read_text())["status"] == "FAIL"
    assert not (directory / "cloudreport.json").exists()
