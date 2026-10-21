from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import psycopg
from jsonschema import ValidationError
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import sm3_hex, verify_payload
from backend.delegation.verifier import ChainVerificationError
from backend.gateway.contracts import ResultRetrievalRequestModel
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect

RETRIEVAL_TOOL_SERVICE = "secure-tool-gateway"
RETRIEVAL_TOOL_NAME = "gateway.result_retrieve"
RETRIEVAL_TOOL_VERSION = "v1"
FINAL_RESULT_STATES = frozenset({"COMMITTED", "RELEASED"})
FINAL_RECEIPT_STATES = frozenset({"DENIED", "COMMITTED", "RELEASED"})


@dataclass(frozen=True)
class _RetrievalTarget:
    execution_id: str
    task_id: str
    tenant_id: str
    credential_chain_hash: str
    state: str
    result: Any
    receipt_id: str | None
    signed_receipt: dict[str, Any] | None
    target_type: Literal["EXECUTION", "RECEIPT"]
    target_id: str


class ResultRetrievalService:
    """Reauthorize and return an existing result or receipt without executing anything."""

    def __init__(
        self,
        *,
        database_url: str,
        gateway: SecureGatewayService,
        schema_store: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.gateway = gateway
        self.schemas = schema_store or SchemaStore()

    def retrieve(
        self,
        request: ResultRetrievalRequestModel,
        *,
        operation: Literal["result", "receipt"],
        current_time: int,
    ) -> dict[str, Any]:
        raw_request = request.model_dump(mode="json")
        request_hash = sm3_hex(canonicalize(raw_request))
        target_type = "EXECUTION" if request.execution_id is not None else "RECEIPT"
        target_id = request.execution_id or request.receipt_id
        assert target_id is not None

        try:
            with connect(self.database_url) as connection, connection.transaction():
                existing = connection.execute(
                    """
                    SELECT request_hash
                    FROM result_retrieval_requests
                    WHERE request_id = %s
                    FOR UPDATE
                    """,
                    (request.request_id,),
                ).fetchone()
                if existing is not None:
                    raise GatewayError(
                        ReasonCode.REPLAY_DETECTED,
                        "result retrieval request_id has already been observed",
                    )

                target: _RetrievalTarget | None = None
                denied_error: GatewayError | None = None
                try:
                    self._validate_schema(request, raw_request)
                    self._validate_freshness(request, current_time)
                    target = self._load_target(
                        connection,
                        target_type=target_type,
                        target_id=target_id,
                    )
                    chain = self._verify_chain_and_binding(
                        connection,
                        request,
                        target=target,
                        current_time=current_time,
                    )
                    self._verify_holder_proof(
                        connection,
                        request,
                        chain=chain,
                        current_time=current_time,
                    )
                    self._validate_operation(target, operation)
                except GatewayError as exc:
                    self._record_request(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        target_type=target_type,
                        target_id=target_id,
                        target=target,
                        outcome="DENIED",
                        reason_code=exc.reason_code.value,
                        current_time=current_time,
                    )
                    self._enqueue_audit(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        target_type=target_type,
                        target_id=target_id,
                        execution_id=None if target is None else target.execution_id,
                        outcome="DENIED",
                        reason_code=exc.reason_code.value,
                        current_time=current_time,
                    )
                    denied_error = exc
                if denied_error is None:
                    self._record_request(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        target_type=target_type,
                        target_id=target_id,
                        target=target,
                        outcome="ALLOWED",
                        reason_code=ReasonCode.ALLOWED.value,
                        current_time=current_time,
                    )
                    assert target is not None
                    self._enqueue_audit(
                        connection,
                        request=request,
                        request_hash=request_hash,
                        target_type=target_type,
                        target_id=target_id,
                        execution_id=target.execution_id,
                        outcome="ALLOWED",
                        reason_code=ReasonCode.ALLOWED.value,
                        current_time=current_time,
                    )
                    if operation == "receipt":
                        assert target.signed_receipt is not None
                        result: dict[str, Any] = dict(target.signed_receipt)
                    else:
                        result = {
                            "execution_id": target.execution_id,
                            "state": target.state,
                            "result": target.result,
                        }
                else:
                    result = {}
            if denied_error is not None:
                raise denied_error
            return result
        except GatewayError as exc:
            if exc.reason_code is ReasonCode.REPLAY_DETECTED:
                self._record_replay_denial(
                    request, request_hash=request_hash, target_type=target_type,
                    target_id=target_id, current_time=current_time,
                )
            raise
        except UniqueViolation as exc:
            self._record_replay_denial(
                request, request_hash=request_hash, target_type=target_type,
                target_id=target_id, current_time=current_time,
            )
            raise GatewayError(
                ReasonCode.REPLAY_DETECTED,
                "result retrieval request_id was concurrently observed",
            ) from exc

    def _record_replay_denial(
        self,
        request: ResultRetrievalRequestModel,
        *,
        request_hash: str,
        target_type: str,
        target_id: str,
        current_time: int,
    ) -> None:
        # Preserve the original read record; append this rejected attempt after rollback.
        with connect(self.database_url) as connection, connection.transaction():
            self._enqueue_audit(
                connection, request=request, request_hash=request_hash,
                target_type=target_type, target_id=target_id, execution_id=None,
                outcome="DENIED", reason_code=ReasonCode.REPLAY_DETECTED.value,
                current_time=current_time,
            )

    def _validate_schema(
        self,
        request: ResultRetrievalRequestModel,
        raw_request: dict[str, Any],
    ) -> None:
        try:
            self.schemas.validate("result-retrieval-request.schema.json", raw_request)
        except ValidationError as exc:
            raise GatewayError(
                ReasonCode.REQUEST_SCHEMA_INVALID,
                "result retrieval request violates the frozen schema",
                status_code=400,
            ) from exc

    def _validate_freshness(
        self, request: ResultRetrievalRequestModel, current_time: int
    ) -> None:
        if not (
            current_time - self.gateway.freshness_window_seconds
            <= request.issued_at
            <= current_time + self.gateway.allowed_clock_skew_seconds
        ):
            raise GatewayError(
                ReasonCode.REQUEST_STALE,
                "result retrieval issued_at is outside the trusted gateway freshness window",
            )

    @staticmethod
    def _load_target(
        connection: psycopg.Connection,
        *,
        target_type: str,
        target_id: str,
    ) -> _RetrievalTarget:
        if target_type == "EXECUTION":
            row = connection.execute(
                """
                SELECT e.execution_id, e.task_id, e.tenant_id,
                       e.credential_chain_hash, e.state, e.result,
                       r.receipt_id, r.signed_receipt, r.receipt_status
                FROM execution_records e
                LEFT JOIN execution_receipts r ON r.execution_id = e.execution_id
                WHERE e.execution_id = %s
                """,
                (target_id,),
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT e.execution_id, e.task_id, e.tenant_id,
                       e.credential_chain_hash, e.state, e.result,
                       r.receipt_id, r.signed_receipt, r.receipt_status
                FROM execution_receipts r
                JOIN execution_records e ON e.execution_id = r.execution_id
                WHERE r.receipt_id = %s
                """,
                (target_id,),
            ).fetchone()
        if row is None:
            raise GatewayError(
                ReasonCode.RESULT_ACCESS_DENIED,
                "retrieval target does not exist",
            )
        signed_receipt = (
            dict(row[7])
            if row[7] is not None and str(row[8]) == "SIGNED"
            else None
        )
        return _RetrievalTarget(
            execution_id=str(row[0]),
            task_id=str(row[1]),
            tenant_id=str(row[2]),
            credential_chain_hash=str(row[3]),
            state=str(row[4]),
            result=row[5],
            receipt_id=None if row[6] is None else str(row[6]),
            signed_receipt=signed_receipt,
            target_type=target_type,  # type: ignore[arg-type]
            target_id=target_id,
        )

    def _verify_chain_and_binding(
        self,
        connection: psycopg.Connection,
        request: ResultRetrievalRequestModel,
        *,
        target: _RetrievalTarget,
        current_time: int,
    ) -> list[dict[str, Any]]:
        try:
            leaf_payload = request.credential_chain[-1]["payload"]
            leaf_credential_id = str(leaf_payload["credential_id"])
            chain = self.gateway.chain_verifier.verify_chain_with_connection(
                connection,
                leaf_credential_id,
                current_time=current_time,
                lock=False,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayError(
                ReasonCode.REQUEST_SCHEMA_INVALID,
                "result retrieval credential chain is malformed",
                status_code=400,
            ) from exc
        except (ChainVerificationError, KeyRegistryError) as exc:
            reason = getattr(exc, "reason_code", ReasonCode.INVALID_SIGNATURE)
            if not isinstance(reason, ReasonCode):
                reason = ReasonCode.INVALID_SIGNATURE
            raise GatewayError(reason, "credential chain verification failed") from exc

        if canonicalize(chain) != canonicalize(request.credential_chain):
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "submitted credential chain differs from trusted persisted chain",
            )
        if any(item["payload"]["verifier_audience"] != self.gateway.audience for item in chain):
            raise GatewayError(
                ReasonCode.WRONG_AUDIENCE,
                "credential audience is not the Secure Gateway",
            )

        leaf_payload = chain[-1]["payload"]
        task = self.gateway._load_task(connection, request.task_id, current_time)
        if leaf_payload["task_id"] != request.task_id:
            raise GatewayError(ReasonCode.CROSS_TASK, "retrieval task does not match credential")
        if leaf_payload["tenant_id"] != task.tenant_id:
            raise GatewayError(
                ReasonCode.CROSS_TENANT,
                "credential tenant does not match task",
            )
        if target.task_id != task.task_id:
            raise GatewayError(ReasonCode.CROSS_TASK, "retrieval target belongs to another task")
        if target.tenant_id != task.tenant_id:
            raise GatewayError(
                ReasonCode.CROSS_TENANT,
                "retrieval target belongs to another tenant",
            )
        if target.credential_chain_hash != self.gateway._credential_chain_hash(chain):
            raise GatewayError(
                ReasonCode.RESULT_ACCESS_DENIED,
                "retrieval target is not bound to the current credential chain",
            )
        return chain

    def _verify_holder_proof(
        self,
        connection: psycopg.Connection,
        request: ResultRetrievalRequestModel,
        *,
        chain: list[dict[str, Any]],
        current_time: int,
    ) -> None:
        proof = request.holder_proof
        proof_payload = proof.get("payload")
        signature = proof.get("signature")
        if not isinstance(proof_payload, dict) or not isinstance(signature, dict):
            raise GatewayError(ReasonCode.REQUEST_SCHEMA_INVALID, "malformed Holder Proof")
        target_binding = {
            "execution_id": request.execution_id,
            "receipt_id": request.receipt_id,
        }
        expected = {
            "schema_version": "1.0",
            "credential_chain_hash": self.gateway._credential_chain_hash(chain),
            "task_id": request.task_id,
            "tool_service": RETRIEVAL_TOOL_SERVICE,
            "tool_name": RETRIEVAL_TOOL_NAME,
            "tool_version": RETRIEVAL_TOOL_VERSION,
            "canonical_parameter_hash": sm3_hex(canonicalize(target_binding)),
            "request_id": request.request_id,
            "issued_at": request.issued_at,
            "business_action_id": None,
        }
        if proof_payload != expected:
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "Holder Proof does not bind the complete retrieval context",
            )
        leaf_holder = chain[-1]["payload"]["holder"]
        if signature.get("key_id") != leaf_holder["key_id"]:
            raise GatewayError(
                ReasonCode.WRONG_HOLDER,
                "Holder Proof key is not the leaf holder key",
            )
        if signature.get("signed_at") != request.issued_at:
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "Holder Proof signed_at must equal issued_at",
            )
        try:
            holder_key = PostgresKeyRegistry.get_with_connection(
                connection, str(leaf_holder["key_id"]), lock=False
            )
        except KeyRegistryError as exc:
            raise GatewayError(exc.reason_code, str(exc)) from exc
        if holder_key.subject_id != leaf_holder["agent_id"]:
            raise GatewayError(ReasonCode.WRONG_HOLDER, "Holder Proof signer subject mismatch")
        if (
            holder_key.subject_type != "AGENT"
            or holder_key.purpose is not KeyPurpose.AGENT_HOLDER_SIGNING
        ):
            raise GatewayError(ReasonCode.WRONG_HOLDER, "Holder Proof signer purpose mismatch")
        key_state_reason = {
            KeyState.RETIRED: ReasonCode.KEY_RETIRED_FOR_SIGNING,
            KeyState.REVOKED: ReasonCode.KEY_REVOKED,
            KeyState.COMPROMISED: ReasonCode.KEY_COMPROMISED,
        }.get(holder_key.status)
        if key_state_reason is not None:
            raise GatewayError(key_state_reason, "Holder Proof signer key is not active")
        if holder_key.material_state is not KeyMaterialState.PRESENT:
            raise GatewayError(
                ReasonCode.UNKNOWN_KEY,
                "Holder Proof signer private material is unavailable",
            )
        try:
            valid = verify_payload(
                proof_payload,
                signature,
                domain_separator=HOLDER_PROOF,
                expected_key_id=holder_key.key_id,
                expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
                public_key_hex=holder_key.public_key_hex,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GatewayError(ReasonCode.INVALID_SIGNATURE, "Holder Proof is malformed") from exc
        if not valid:
            raise GatewayError(ReasonCode.INVALID_SIGNATURE, "Holder Proof signature is invalid")
        if current_time < request.issued_at:
            raise GatewayError(ReasonCode.REQUEST_STALE, "retrieval request is from the future")

    @staticmethod
    def _validate_operation(
        target: _RetrievalTarget,
        operation: Literal["result", "receipt"],
    ) -> None:
        if operation == "result":
            if target.state not in FINAL_RESULT_STATES:
                raise GatewayError(
                    ReasonCode.RESULT_ACCESS_DENIED,
                    "execution has no retrievable final result",
                )
            return
        if target.state not in FINAL_RECEIPT_STATES or target.signed_receipt is None:
            raise GatewayError(
                ReasonCode.RESULT_ACCESS_DENIED,
                "execution has no retrievable signed receipt",
            )

    @staticmethod
    def _record_request(
        connection: psycopg.Connection,
        *,
        request: ResultRetrievalRequestModel,
        request_hash: str,
        target_type: str,
        target_id: str,
        target: _RetrievalTarget | None,
        outcome: str,
        reason_code: str,
        current_time: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO result_retrieval_requests (
                request_id, request_hash, task_id, target_type, target_id,
                execution_id, receipt_id, outcome, reason_code, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                request.request_id,
                request_hash,
                request.task_id,
                target_type,
                target_id,
                None if target is None else target.execution_id,
                None if target is None else target.receipt_id,
                outcome,
                reason_code,
                current_time,
            ),
        )

    @staticmethod
    def _enqueue_audit(
        connection: psycopg.Connection,
        *,
        request: ResultRetrievalRequestModel,
        request_hash: str,
        target_type: str,
        target_id: str,
        execution_id: str | None,
        outcome: str,
        reason_code: str,
        current_time: int,
    ) -> None:
        event_type = (
            "RESULT_RETRIEVAL_ALLOWED"
            if outcome == "ALLOWED"
            else "RESULT_RETRIEVAL_DENIED"
        )
        event_id = new_id("EVENT-RETRIEVAL")
        payload = {
            "schema_version": "1.0",
            "event_type": event_type,
            "retrieval_request_id": request.request_id,
            "request_hash": request_hash,
            "target_type": target_type,
            "target_id": target_id,
            "execution_id": execution_id,
            "reason_code": reason_code,
        }
        connection.execute(
            """
            INSERT INTO audit_outbox (
                outbox_event_id, execution_id, event_type, evidence_reference,
                payload_hash, payload, status, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, 'PENDING', %s)
            ON CONFLICT (outbox_event_id) DO NOTHING
            """,
            (
                f"OUTBOX-{event_id}",
                execution_id,
                event_type,
                request.request_id,
                sm3_hex(canonicalize(payload)),
                Jsonb(payload),
                current_time,
            ),
        )
