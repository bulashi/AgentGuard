from __future__ import annotations

import hmac
import json
import secrets
import time
from typing import Any

from psycopg.types.json import Jsonb

from backend.agent_runtime.contracts import AgentStep, RuntimeMode, WorkflowScenario
from backend.common.ids import new_id
from backend.crypto.sm import sm3_hex
from backend.state.database import connect


def safe_observation(value: Any) -> Any:
    blocked = {
        "workflow_token",
        "observation_token_hash",
        "private_key",
        "api_key",
        "credential_chain",
        "holder_proof",
        "signature",
        "response_content",
        "reasoning_content",
        "authorization",
        "access_token",
    }
    if isinstance(value, dict):
        return {
            key: safe_observation(item) for key, item in value.items() if key.lower() not in blocked
        }
    if isinstance(value, (list, tuple)):
        return [safe_observation(item) for item in value]
    return value


class WorkflowStoreError(RuntimeError):
    pass


WORKFLOW_TRANSITIONS = {
    "QUEUED": {"RUNNING", "FAILED"},
    "RUNNING": {"COMPLETED", "DENIED", "FAILED"},
    "COMPLETED": set(),
    "DENIED": set(),
    "FAILED": set(),
}


class WorkflowStore:
    """Operational-only persistence. It cannot authorize or execute tools."""

    def __init__(self, database_url: str) -> None:
        if not database_url:
            raise WorkflowStoreError("workflow observation store is not configured")
        self.database_url = database_url

    def create(
        self,
        *,
        task_id: str,
        mode: RuntimeMode,
        scenario: WorkflowScenario,
        model: str | None,
        timeout_seconds: int,
    ) -> tuple[str, str]:
        run_id, token = new_id("RUN"), secrets.token_urlsafe(32)
        current = int(time.time() * 1000)
        with connect(self.database_url) as connection:
            connection.execute(
                """
                INSERT INTO agent_workflow_runs (
                    run_id, task_id, runtime_mode, scenario, model, state,
                    observation_token_hash, created_at_ms, updated_at_ms, deadline_at_ms
                ) VALUES (%s, %s, %s, %s, %s, 'QUEUED', %s, %s, %s, %s)
                """,
                (
                    run_id,
                    task_id,
                    mode,
                    scenario,
                    model,
                    sm3_hex(token.encode("ascii")),
                    current,
                    current,
                    current + timeout_seconds * 1000,
                ),
            )
        return run_id, token

    def state(self, run_id: str, state: str, reason_code: str | None = None) -> None:
        current = int(time.time() * 1000)
        terminal = state in {"COMPLETED", "DENIED", "FAILED"}
        with connect(self.database_url) as connection, connection.transaction():
            previous = connection.execute(
                "SELECT state FROM agent_workflow_runs WHERE run_id = %s FOR UPDATE", (run_id,)
            ).fetchone()
            if previous is None or state not in WORKFLOW_TRANSITIONS.get(previous[0], set()):
                raise WorkflowStoreError("invalid operational workflow state transition")
            connection.execute(
                """
                UPDATE agent_workflow_runs
                SET state = %s, reason_code = %s, updated_at_ms = %s, finished_at_ms = %s
                WHERE run_id = %s
                """,
                (state, reason_code, current, current if terminal else None, run_id),
            )

    def append(self, run_id: str, token: str, event: AgentStep) -> None:
        details = safe_observation(event.details)
        if len(json.dumps(details, ensure_ascii=False).encode("utf-8")) > 131_072:
            raise WorkflowStoreError("operational event is too large")
        current = int(time.time() * 1000)
        with connect(self.database_url) as connection, connection.transaction():
            row = connection.execute(
                """SELECT observation_token_hash, state, deadline_at_ms
                   FROM agent_workflow_runs WHERE run_id = %s FOR UPDATE""",
                (run_id,),
            ).fetchone()
            valid = row is not None and hmac.compare_digest(
                str(row[0]), sm3_hex(token.encode("utf-8"))
            )
            if not valid or row[1] not in {"QUEUED", "RUNNING"} or current > int(row[2]):
                raise WorkflowStoreError("observation token or active run is invalid")
            sequence = connection.execute(
                """UPDATE agent_workflow_runs
                   SET next_sequence = next_sequence + 1, updated_at_ms = %s
                   WHERE run_id = %s AND next_sequence < 128 RETURNING next_sequence""",
                (current, run_id),
            ).fetchone()
            if sequence is None:
                raise WorkflowStoreError("operational event limit reached")
            connection.execute(
                """INSERT INTO agent_workflow_events (
                    run_id, sequence, agent_id, action, status,
                    timestamp_ms, recorded_at_ms, details
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    run_id,
                    sequence[0],
                    event.agent_id,
                    event.action,
                    event.status,
                    event.timestamp_ms,
                    current,
                    Jsonb(details),
                ),
            )
