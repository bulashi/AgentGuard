from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psycopg
from jsonschema import ValidationError

from backend.business_action.policy import (
    NOTIFICATION_SERVICE,
    NOTIFICATION_TOOL,
    REFUND_SERVICE,
    REFUND_SUCCESS_NOTIFICATION_SLOT,
    REFUND_TOOL,
    TrustedTaskContext,
    notification_scope,
)
from backend.common.enums import KeyMaterialState, KeyPurpose, KeyState
from backend.common.error_codes import ReasonCode
from backend.common.ids import new_id
from backend.common.schema import SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.domains import BUSINESS_IDEMPOTENCY, HOLDER_PROOF
from backend.crypto.sm import domain_message, sm3_hex, verify_payload
from backend.delegation.verifier import ChainVerificationError, CredentialChainVerifier
from backend.gateway.contracts import RequestEnvelopeModel, ValidatedToolCommandModel
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect

READ_ONLY_TOOLS = {
    ("ticket-service", "ticket.read"): {"ticket_id"},
    ("knowledge-service", "knowledge.read_associated"): {"ticket_id"},
}
SIDE_EFFECT_TOOLS = {
    (REFUND_SERVICE, REFUND_TOOL): {"ticket_id", "customer_id", "amount_fen"},
    (NOTIFICATION_SERVICE, NOTIFICATION_TOOL): {
        "customer_id",
        "template_id",
        "related_business_effect_id",
    },
}


class GatewayError(RuntimeError):
    def __init__(
        self,
        reason_code: ReasonCode,
        message: str,
        *,
        status_code: int = 403,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


@dataclass(frozen=True)
class _TaskContext:
    task_id: str
    tenant_id: str
    ticket_id: str
    customer_id: str
    expires_at: int
    status: str


class SecureGatewayService:
    def __init__(
        self,
        *,
        database_url: str,
        audience: str = "secure-tool-gateway",
        freshness_window_seconds: int = 60,
        allowed_clock_skew_seconds: int = 5,
        schema_store: SchemaStore | None = None,
    ) -> None:
        self.database_url = database_url
        self.audience = audience
        self.freshness_window_seconds = freshness_window_seconds
        self.allowed_clock_skew_seconds = allowed_clock_skew_seconds
        self.schemas = schema_store or SchemaStore()
        self.chain_verifier = CredentialChainVerifier(database_url, self.schemas)

    def validate_request(
        self, request: RequestEnvelopeModel, *, current_time: int
    ) -> dict[str, Any]:
        raw_request = request.model_dump(mode="json")
        try:
            self.schemas.validate("request-envelope.schema.json", raw_request)
        except ValidationError as exc:
            raise GatewayError(
                ReasonCode.REQUEST_SCHEMA_INVALID,
                "request does not match the frozen RequestEnvelope schema",
                status_code=400,
            ) from exc

        if not (
            current_time - self.freshness_window_seconds
            <= request.issued_at
            <= current_time + self.allowed_clock_skew_seconds
        ):
            raise GatewayError(
                ReasonCode.REQUEST_STALE,
                "request issued_at is outside the trusted gateway freshness window",
            )

        request_hash = sm3_hex(canonicalize(raw_request))
        parameter_hash = sm3_hex(canonicalize(request.canonical_parameters))
        with connect(self.database_url) as connection:
            chain = self._verify_chain_and_binding(connection, request, current_time)
            leaf_payload = chain[-1]["payload"]
            task = self._load_task(connection, request.task_id, current_time)
            self._verify_holder_proof(
                connection,
                request,
                chain,
                leaf_payload,
                parameter_hash=parameter_hash,
                current_time=current_time,
            )
            self._verify_request_identity(request, leaf_payload, task)
            capability = self._resolve_capability(leaf_payload, request)
            self._verify_parameters(
                connection,
                request,
                task,
                capability,
            )
            self._verify_business_action(connection, request, task)

        execution_id = new_id("EXEC")
        business_idempotency_key = self._business_idempotency_key(
            task.tenant_id,
            task.task_id,
            request.tool_service,
            request.tool_name,
            request.business_action_id,
        )
        command = ValidatedToolCommandModel(
            schema_version="1.0",
            execution_id=execution_id,
            tenant_id=task.tenant_id,
            task_id=task.task_id,
            tool_service=request.tool_service,
            tool_name=request.tool_name,
            tool_version=request.tool_version,
            validated_parameters=request.canonical_parameters,
            business_action_id=request.business_action_id,
            business_idempotency_key=business_idempotency_key,
            parameter_hash=parameter_hash,
        )
        try:
            self.schemas.validate(
                "validated-tool-command.schema.json",
                command.model_dump(mode="json"),
            )
        except ValidationError as exc:
            raise GatewayError(
                ReasonCode.REQUEST_SCHEMA_INVALID,
                "validated command violates the frozen schema",
            ) from exc
        return {
            "execution_id": execution_id,
            "state": "RECEIVED",
            "decision": "ALLOW",
            "reason_code": ReasonCode.ALLOWED.value,
            "request_hash": request_hash,
            "credential_chain_hash": self._credential_chain_hash(chain),
            "validated_command": command.model_dump(mode="json"),
        }

    def _verify_chain_and_binding(
        self,
        connection: psycopg.Connection,
        request: RequestEnvelopeModel,
        current_time: int,
        *,
        lock: bool = False,
    ) -> list[dict[str, Any]]:
        leaf = request.credential_chain[-1]
        try:
            leaf_payload = leaf["payload"]
            leaf_credential_id = str(leaf_payload["credential_id"])
            chain = self.chain_verifier.verify_chain_with_connection(
                connection,
                leaf_credential_id,
                current_time=current_time,
                lock=lock,
            )
        except (KeyError, TypeError, ChainVerificationError, KeyRegistryError) as exc:
            reason = getattr(exc, "reason_code", ReasonCode.INVALID_SIGNATURE)
            raise GatewayError(reason, "credential chain verification failed") from exc
        if canonicalize(chain) != canonicalize(request.credential_chain):
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "submitted credential chain differs from trusted persisted chain",
            )
        if chain[-1]["payload"]["holder"]["key_id"] != request.holder_key_id:
            raise GatewayError(
                ReasonCode.WRONG_HOLDER,
                "request holder key does not match the leaf credential holder",
            )
        if any(item["payload"]["verifier_audience"] != self.audience for item in chain):
            raise GatewayError(
                ReasonCode.WRONG_AUDIENCE,
                "credential audience is not the Secure Gateway",
            )
        return chain

    @staticmethod
    def _credential_chain_hash(chain: list[dict[str, Any]]) -> str:
        return sm3_hex(canonicalize(chain))

    def _load_task(
        self,
        connection: psycopg.Connection,
        task_id: str,
        current_time: int,
        *,
        lock: bool = False,
    ) -> _TaskContext:
        lock_clause = " FOR UPDATE" if lock else ""
        row = connection.execute(
            f"""
            SELECT task_id, tenant_id, ticket_id, customer_id, expires_at, status
            FROM tasks WHERE task_id = %s
            {lock_clause}
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            raise GatewayError(ReasonCode.CROSS_TASK, "task does not exist")
        task = _TaskContext(
            task_id=str(row[0]),
            tenant_id=str(row[1]),
            ticket_id=str(row[2]),
            customer_id=str(row[3]),
            expires_at=int(row[4]),
            status=str(row[5]),
        )
        if task.status != "AUTHORIZED":
            raise GatewayError(ReasonCode.CROSS_TASK, "task is not authorized")
        if current_time > task.expires_at:
            raise GatewayError(ReasonCode.CREDENTIAL_EXPIRED, "task is expired")
        return task

    def _verify_request_identity(
        self,
        request: RequestEnvelopeModel,
        leaf_payload: dict[str, Any],
        task: _TaskContext,
    ) -> None:
        if leaf_payload["task_id"] != request.task_id or task.task_id != request.task_id:
            raise GatewayError(ReasonCode.CROSS_TASK, "request task does not match credential")
        if leaf_payload["tenant_id"] != task.tenant_id:
            raise GatewayError(ReasonCode.CROSS_TENANT, "credential tenant does not match task")

    def _verify_holder_proof(
        self,
        connection: psycopg.Connection,
        request: RequestEnvelopeModel,
        chain: list[dict[str, Any]],
        leaf_payload: dict[str, Any],
        *,
        parameter_hash: str,
        current_time: int,
        lock: bool = False,
    ) -> None:
        proof = request.holder_proof
        proof_payload = proof.get("payload")
        signature = proof.get("signature")
        if not isinstance(proof_payload, dict) or not isinstance(signature, dict):
            raise GatewayError(ReasonCode.REQUEST_SCHEMA_INVALID, "malformed holder proof")
        expected = {
            "schema_version": "1.0",
            "credential_chain_hash": self._credential_chain_hash(chain),
            "task_id": request.task_id,
            "tool_service": request.tool_service,
            "tool_name": request.tool_name,
            "tool_version": request.tool_version,
            "canonical_parameter_hash": parameter_hash,
            "request_id": request.request_id,
            "issued_at": request.issued_at,
            "business_action_id": request.business_action_id,
        }
        if proof_payload != expected:
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "Holder Proof does not bind the complete request context",
            )
        if signature.get("key_id") != leaf_payload["holder"]["key_id"]:
            raise GatewayError(
                ReasonCode.WRONG_HOLDER,
                "Holder Proof key is not the leaf holder key",
            )
        if signature.get("signed_at") != request.issued_at:
            raise GatewayError(
                ReasonCode.INVALID_SIGNATURE,
                "Holder Proof signed_at must equal the bound request issued_at",
            )
        try:
            holder_key = PostgresKeyRegistry.get_with_connection(
                connection, leaf_payload["holder"]["key_id"], lock=lock
            )
        except KeyRegistryError as exc:
            raise GatewayError(exc.reason_code, str(exc)) from exc
        if holder_key.subject_id != leaf_payload["holder"]["agent_id"]:
            raise GatewayError(
                ReasonCode.WRONG_HOLDER,
                "Holder Proof signer key subject does not match the leaf holder",
            )
        if (
            holder_key.subject_type != "AGENT"
            or holder_key.purpose is not KeyPurpose.AGENT_HOLDER_SIGNING
        ):
            raise GatewayError(
                ReasonCode.WRONG_HOLDER,
                "Holder Proof signer key is not an agent holder key",
            )
        key_state_reason = {
            KeyState.RETIRED: ReasonCode.KEY_RETIRED_FOR_SIGNING,
            KeyState.REVOKED: ReasonCode.KEY_REVOKED,
            KeyState.COMPROMISED: ReasonCode.KEY_COMPROMISED,
        }.get(holder_key.status)
        if key_state_reason is not None:
            raise GatewayError(
                key_state_reason,
                "Holder Proof signer key is not active",
            )
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
            raise GatewayError(ReasonCode.REQUEST_STALE, "request is from the future")

    def _resolve_capability(
        self, leaf_payload: dict[str, Any], request: RequestEnvelopeModel
    ) -> dict[str, Any]:
        for capability in leaf_payload["capabilities"]:
            if (
                capability["service"] == request.tool_service
                and capability["tool"] == request.tool_name
                and capability["version"] == request.tool_version
            ):
                return capability
        raise GatewayError(ReasonCode.TOOL_NOT_ALLOWED, "tool is not in the leaf capability set")

    def _verify_parameters(
        self,
        connection: psycopg.Connection,
        request: RequestEnvelopeModel,
        task: _TaskContext,
        capability: dict[str, Any],
    ) -> None:
        identity = (request.tool_service, request.tool_name)
        expected_keys = READ_ONLY_TOOLS.get(identity) or SIDE_EFFECT_TOOLS.get(identity)
        if expected_keys is None:
            raise GatewayError(ReasonCode.TOOL_NOT_ALLOWED, "unsupported protected tool")
        parameters = request.canonical_parameters
        if set(parameters) != expected_keys:
            raise GatewayError(
                ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                "parameter keys do not match the protected tool contract",
            )
        if "ticket_id" in parameters and parameters["ticket_id"] != task.ticket_id:
            raise GatewayError(ReasonCode.RESOURCE_NOT_ALLOWED, "ticket is outside the task")
        if "customer_id" in parameters and parameters["customer_id"] != task.customer_id:
            raise GatewayError(ReasonCode.RESOURCE_NOT_ALLOWED, "customer is outside the task")
        resources = capability["resources"]
        if "ticket_id" in parameters and parameters["ticket_id"] not in resources.get(
            "ticket_ids", []
        ):
            raise GatewayError(ReasonCode.RESOURCE_NOT_ALLOWED, "ticket is outside the credential")
        if "customer_id" in parameters and parameters["customer_id"] not in resources.get(
            "customer_ids", []
        ):
            raise GatewayError(
                ReasonCode.RESOURCE_NOT_ALLOWED,
                "customer is outside the credential",
            )
        constraints = capability.get("constraints", {})
        if "amount_fen" in parameters:
            amount = parameters["amount_fen"]
            if type(amount) is not int or amount <= 0:
                raise GatewayError(
                    ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                    "refund amount must be a positive integer",
                )
            maximum = constraints.get("single_max_fen")
            if maximum is not None and amount > maximum:
                raise GatewayError(
                    ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                    "refund amount exceeds the credential single-action limit",
                )
        if "template_id" in parameters:
            allowed_templates = constraints.get("template_ids", [])
            if parameters["template_id"] not in allowed_templates:
                raise GatewayError(
                    ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                    "notification template is outside the credential",
                )
        if request.tool_name == "knowledge.read_associated":
            associated = connection.execute(
                """
                SELECT 1 FROM ticket_document_relations
                WHERE ticket_id = %s
                """,
                (parameters["ticket_id"],),
            ).fetchone()
            if associated is None:
                raise GatewayError(
                    ReasonCode.RESOURCE_NOT_ALLOWED,
                    "ticket has no trusted knowledge association",
                )

    @staticmethod
    def _verify_business_action(
        connection: psycopg.Connection,
        request: RequestEnvelopeModel,
        task: _TaskContext,
        *,
        lock: bool = False,
    ) -> None:
        side_effect = (request.tool_service, request.tool_name) in SIDE_EFFECT_TOOLS
        if side_effect and request.business_action_id is None:
            raise GatewayError(
                ReasonCode.BUSINESS_ACTION_INVALID,
                "side-effect execution requires a resolved business action",
            )
        if not side_effect and request.business_action_id is not None:
            raise GatewayError(
                ReasonCode.BUSINESS_ACTION_INVALID,
                "read-only execution cannot carry a business action",
            )
        if request.business_action_id is None:
            return
        lock_clause = " FOR UPDATE" if lock else ""
        row = connection.execute(
            f"""
            SELECT tenant_id, task_id, tool_service, tool_name, status
            FROM business_actions WHERE business_action_id = %s
            {lock_clause}
            """,
            (request.business_action_id,),
        ).fetchone()
        if row is None:
            raise GatewayError(ReasonCode.BUSINESS_ACTION_INVALID, "business action does not exist")
        if tuple(str(value) for value in row[:4]) != (
            task.tenant_id,
            task.task_id,
            request.tool_service,
            request.tool_name,
        ):
            raise GatewayError(
                ReasonCode.BUSINESS_ACTION_CONFLICT,
                "business action is bound to a different trusted context",
                status_code=409,
            )
        if str(row[4]) not in {"ACTIVE", "COMMITTED"}:
            raise GatewayError(
                ReasonCode.BUSINESS_ACTION_INVALID,
                "business action is not usable",
            )
        if (request.tool_service, request.tool_name) == (NOTIFICATION_SERVICE, NOTIFICATION_TOOL):
            parameters = request.canonical_parameters
            scope = connection.execute(
                "SELECT action_scope_key, trusted_action_slot FROM business_actions "
                "WHERE business_action_id = %s",
                (request.business_action_id,),
            ).fetchone()
            context = TrustedTaskContext(
                task.tenant_id, task.task_id, task.ticket_id, task.customer_id
            )
            expected_scope, _ = notification_scope(
                context,
                template_id=parameters["template_id"],
                related_business_effect_id=parameters["related_business_effect_id"],
            )
            if scope is None or tuple(str(value) for value in scope) != (
                expected_scope, REFUND_SUCCESS_NOTIFICATION_SLOT
            ):
                raise GatewayError(
                    ReasonCode.BUSINESS_ACTION_CONFLICT,
                    "notification action scope differs from the actual refund or template",
                    status_code=409,
                )
            refund_lock = " FOR SHARE" if lock else ""
            refund = connection.execute(
                "SELECT tenant_id, task_id, ticket_id, customer_id, status FROM refunds "
                f"WHERE refund_id = %s{refund_lock}",
                (parameters["related_business_effect_id"],),
            ).fetchone()
            if refund is None or tuple(str(value) for value in refund) != (
                task.tenant_id, task.task_id, task.ticket_id, task.customer_id, "COMMITTED"
            ):
                raise GatewayError(
                    ReasonCode.BUSINESS_ACTION_INVALID,
                    "notification requires the task's matching committed refund",
                )

    @staticmethod
    def _business_idempotency_key(
        tenant_id: str,
        task_id: str,
        tool_service: str,
        tool_name: str,
        business_action_id: str | None,
    ) -> str | None:
        if business_action_id is None:
            return None
        payload = {
            "tenant_id": tenant_id,
            "task_id": task_id,
            "tool_service": tool_service,
            "tool_name": tool_name,
            "business_action_id": business_action_id,
        }
        return sm3_hex(domain_message(BUSINESS_IDEMPOTENCY, payload))
