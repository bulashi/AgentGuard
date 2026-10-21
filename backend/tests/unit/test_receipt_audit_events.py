from __future__ import annotations

from typing import Any

import pytest

from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.receipt.service import ReceiptService


class RecordingConnection:
    def __init__(self) -> None:
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, query: str, parameters: tuple[Any, ...]) -> None:
        assert "INSERT INTO audit_outbox" in query
        self.rows.append(parameters)


@pytest.mark.parametrize(
    ("state", "decision", "effect_id", "outcome"),
    [
        ("DENIED", "DENY", None, "AUTHORIZATION_DENIED"),
        ("COMMITTED", "ALLOW", None, "EXECUTION_COMMITTED"),
        ("COMMITTED", "ALLOW", "REFUND-TEST", "EXECUTION_COMMITTED"),
        ("RELEASED", "ALLOW", None, "EXECUTION_RELEASED"),
    ],
)
def test_outbox_outcome_uses_execution_state(
    state: str, decision: str, effect_id: str | None, outcome: str
) -> None:
    connection = RecordingConnection()
    ReceiptService._enqueue_audit_events(
        connection,
        execution_id="EXEC-TEST",
        receipt_id="RECEIPT-TEST",
        receipt_hash="1" * 64,
        payload={"decision": decision, "business_effect_id": effect_id},
        execution_state=state,
        timestamp=100,
    )
    assert [row[2] for row in connection.rows] == ["RECEIPT_SIGNED", outcome]
    for row in connection.rows:
        event = row[5].obj
        assert event["event_type"] == row[2]
        assert event["execution_id"] == "EXEC-TEST"
        assert row[4] == sm3_hex(canonicalize(event))
