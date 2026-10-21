"""Read-only authorization before an Agent consumes planning resources."""

from __future__ import annotations

from typing import Any

from backend.agent_runtime.contracts import AgentRunRequest
from backend.common.enums import KeyPurpose
from backend.common.error_codes import ReasonCode
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.delegation.verifier import ChainVerificationError
from backend.gateway.service import GatewayError, SecureGatewayService
from backend.identity.key_registry import KeyRegistryError, PostgresKeyRegistry
from backend.state.database import connect

ROLE_TOOLS = {
    "agent-coordinator": {
        ("knowledge-service", "knowledge.read_associated"),
        ("ticket-service", "ticket.read"),
        ("refund-service", "refund.create"),
        ("notification-service", "notification.send_template"),
    },
    "agent-knowledge": {("knowledge-service", "knowledge.read_associated")},
    "agent-case": {
        ("ticket-service", "ticket.read"),
        ("refund-service", "refund.create"),
        ("notification-service", "notification.send_template"),
    },
    "agent-refund": {("refund-service", "refund.create")},
}


def authorize_runtime(
    gateway: SecureGatewayService,
    request: AgentRunRequest,
    *,
    caller: str,
    current_time: int,
) -> dict[str, Any]:
    if caller not in ROLE_TOOLS:
        raise GatewayError(ReasonCode.WRONG_HOLDER, "runtime caller is not a controlled Agent")
    try:
        leaf_id = str(request.credential_chain[-1]["payload"]["credential_id"])
        with connect(gateway.database_url) as connection:
            chain = gateway.chain_verifier.verify_chain_with_connection(
                connection,
                leaf_id,
                current_time=current_time,
                lock=False,
            )
            if canonicalize(chain) != canonicalize(request.credential_chain):
                raise GatewayError(
                    ReasonCode.INVALID_SIGNATURE,
                    "runtime chain differs from the trusted chain",
                )
            leaf = chain[-1]["payload"]
            root = chain[0]["payload"]
            if leaf["holder"]["agent_id"] != caller:
                raise GatewayError(ReasonCode.WRONG_HOLDER, "runtime caller does not hold the leaf")
            if any(item["payload"]["verifier_audience"] != gateway.audience for item in chain):
                raise GatewayError(ReasonCode.WRONG_AUDIENCE, "runtime chain has another audience")
            task = gateway._load_task(connection, str(leaf["task_id"]), current_time)
            if any(
                item["payload"]["task_id"] != task.task_id
                or item["payload"]["tenant_id"] != task.tenant_id
                for item in chain
            ):
                raise GatewayError(ReasonCode.CROSS_TASK, "runtime chain is outside the task")
            context = request.context
            if context.ticket_id != task.ticket_id or context.customer_id != task.customer_id:
                raise GatewayError(
                    ReasonCode.RESOURCE_NOT_ALLOWED, "runtime context is outside the task"
                )
            PostgresKeyRegistry.resolve_for_signing_with_connection(
                connection,
                str(leaf["holder"]["key_id"]),
                expected_subject_id=caller,
                expected_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
            )
            if context.refund_amount_fen > root["quotas"].get("refund_total_fen", 0):
                raise GatewayError(
                    ReasonCode.BUDGET_EXCEEDED, "runtime amount exceeds root authorization"
                )
            capabilities = {
                (cap["service"], cap["tool"]): cap
                for cap in leaf["capabilities"]
                if cap["version"] == "v1"
            }
            for identity in ROLE_TOOLS[caller]:
                capability = capabilities.get(identity)
                if capability is None:
                    raise GatewayError(
                        ReasonCode.TOOL_NOT_ALLOWED, "runtime role lacks a required capability"
                    )
                resources = capability["resources"]
                if identity[0] != "notification-service" and task.ticket_id not in resources.get(
                    "ticket_ids", []
                ):
                    raise GatewayError(
                        ReasonCode.RESOURCE_NOT_ALLOWED, "runtime ticket is outside leaf scope"
                    )
                if identity[0] in {
                    "refund-service",
                    "notification-service",
                } and task.customer_id not in resources.get("customer_ids", []):
                    raise GatewayError(
                        ReasonCode.RESOURCE_NOT_ALLOWED, "runtime customer is outside leaf scope"
                    )
                if identity[0] == "refund-service" and context.refund_amount_fen > min(
                    leaf["quotas"].get("refund_total_fen", 0),
                    capability["constraints"].get("single_max_fen", 0),
                ):
                    raise GatewayError(
                        ReasonCode.BUDGET_EXCEEDED, "runtime amount exceeds leaf authorization"
                    )
                if identity[0] == "notification-service" and "REFUND_SUCCESS" not in capability[
                    "constraints"
                ].get("template_ids", []):
                    raise GatewayError(
                        ReasonCode.PARAMETER_CONSTRAINT_VIOLATION,
                        "runtime template is outside leaf scope",
                    )
            if context.runtime_mode == "cloud":
                allowed = connection.execute(
                    "SELECT cloud_shareable FROM tickets "
                    "WHERE ticket_id = %s AND tenant_id = %s AND customer_id = %s",
                    (task.ticket_id, task.tenant_id, task.customer_id),
                ).fetchone()
                if not context.cloud_data_confirmed or allowed is None or allowed[0] is not True:
                    raise GatewayError(
                        ReasonCode.RESOURCE_NOT_ALLOWED,
                        "task data is not approved for cloud planning",
                    )
    except (ChainVerificationError, KeyRegistryError) as exc:
        raise GatewayError(exc.reason_code, "runtime authorization is invalid") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise GatewayError(
            ReasonCode.INVALID_SIGNATURE, "runtime authorization is malformed"
        ) from exc
    return {
        "authorized": True,
        "task_id": task.task_id,
        "agent_id": caller,
        "credential_chain_hash": sm3_hex(canonicalize(chain)),
    }
