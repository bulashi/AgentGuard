"""Task-scoped revocation sidecar; shared app/service wiring belongs to the parent.

Call authenticated_operator from the POST route with a server-configured operator ID,
then pass its result to revoke_credential. The browser body has no identity field.
The snapshot must add credentials[].revoked_by for persisted/idempotent evidence.
Optional dispatch_cancellations rows retain the 0024 table's column names and evidence.
Receipt/audit links are resolved from this same snapshot; missing links remain pending.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import Request
from pydantic import ValidationError

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.common.internal_auth import InternalAuthenticator, InternalAuthError
from backend.common.time import now_unix
from backend.config.settings import Settings
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import parse_strict_json
from backend.revocation.contracts import RevocationResponse
from backend.ui_api.operator_session import COOKIE_NAME, OperatorSessionGuard
from backend.ui_api.revocation_contracts import UiRevocationResponse, UiRevokeCredentialRequest
from backend.ui_api.service import UiApiError, UiService


def _identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and re.fullmatch(IDENTIFIER_PATTERN, value) is not None
    )


def authenticated_operator(request: Request, settings: Settings, *, operator_id: str) -> str:
    """Authenticate the local launch session, not an individual Windows/SSO user."""
    if settings.operator_auth_required is not True or not _identifier(operator_id):
        raise UiApiError(
            "OPERATOR_SESSION_REQUIRED", "Operator authentication is required", status_code=401
        )
    host = request.headers.get("host", "")
    origin = request.headers.get("origin")
    try:
        parsed = urlsplit("http://" + host)
        local = parsed.hostname in {"127.0.0.1", "localhost", "::1"} and not any(
            (parsed.username, parsed.password, parsed.path, parsed.query, parsed.fragment)
        )
    except ValueError:
        local = False
    if (
        not local
        or (origin is not None and origin.lower() != request.url.scheme + "://" + host.lower())
        or request.headers.get("sec-fetch-site", "none") not in {"same-origin", "none"}
    ):
        raise UiApiError(
            "OPERATOR_ORIGIN_DENIED", "Local same-origin operation required", status_code=403
        )
    try:
        guard = OperatorSessionGuard(None, required=True, secret=settings.operator_session_secret)
        valid = guard.valid_cookie(request.cookies.get(COOKIE_NAME, ""), now_unix())
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise UiApiError(
            "OPERATOR_SESSION_REQUIRED", "A valid operator session is required", status_code=401
        )
    return operator_id


def _credential_scope(
    snapshot: dict[str, Any] | None,
    task_id: str,
    credential_id: str,
) -> tuple[dict[str, Any], int]:
    if snapshot is None:
        raise UiApiError("CROSS_TASK", "Task was not found", status_code=404)
    if not isinstance(snapshot, dict):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "Task snapshot is unavailable")
    task = snapshot.get("task")
    if not isinstance(task, dict) or task.get("task_id") != task_id:
        raise UiApiError("CROSS_TASK", "Snapshot does not belong to this task", status_code=409)
    credentials = snapshot.get("credentials")
    if not isinstance(credentials, list):
        raise UiApiError("CONTROLLED_RESULT_INVALID", "Credential snapshot is unavailable")
    by_id: dict[str, dict[str, Any]] = {}
    for item in credentials:
        if (
            not isinstance(item, dict)
            or not _identifier(item.get("credential_id"))
            or item["credential_id"] in by_id
            or ("task_id" in item and item["task_id"] != task_id)
        ):
            raise UiApiError("CONTROLLED_RESULT_INVALID", "Credential snapshot is inconsistent")
        by_id[item["credential_id"]] = item
    if credential_id not in by_id:
        raise UiApiError("CROSS_TASK", "Credential does not belong to this task", status_code=404)
    descendants = 0
    for item in by_id.values():
        current = item
        visited: set[str] = set()
        affected = False
        while True:
            identifier = current["credential_id"]
            if identifier in visited:
                raise UiApiError(
                    "CONTROLLED_RESULT_INVALID", "Credential ancestry contains a cycle"
                )
            visited.add(identifier)
            affected = affected or identifier == credential_id
            parent = current.get("parent_credential_id")
            if current.get("credential_type") == "ROOT" and parent is None:
                break
            if (
                current.get("credential_type") != "DELEGATION"
                or not _identifier(parent)
                or parent not in by_id
            ):
                raise UiApiError("CONTROLLED_RESULT_INVALID", "Credential ancestry is incomplete")
            current = by_id[parent]
        descendants += int(affected and item["credential_id"] != credential_id)
    return by_id[credential_id], descendants


def _saved_revocation(credential: dict[str, Any]) -> RevocationResponse:
    try:
        return RevocationResponse.model_validate(
            {
                "credential_id": credential["credential_id"],
                "revoked_at": credential["revoked_at"],
                "revocation_reason": credential["revocation_reason"],
                "revoked_by": credential["revoked_by"],
                "status": "REVOKED",
            }
        )
    except (KeyError, ValidationError) as exc:
        raise UiApiError(
            "REVOCATION_RESULT_UNCONFIRMED",
            "Saved revocation evidence is incomplete; refresh records",
            status_code=503,
        ) from exc


def _unique_records(
    snapshot: dict[str, Any], key: str, identifier: str
) -> dict[str, dict[str, Any]]:
    records = snapshot.get(key, [])
    if not isinstance(records, list):
        return {}
    by_id: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if isinstance(record, dict) and _identifier(record.get(identifier)):
            by_id.setdefault(record[identifier], []).append(record)
    return {key: values[0] for key, values in by_id.items() if len(values) == 1}


def _projection(
    snapshot: dict[str, Any],
    task_id: str,
    credential_id: str,
    saved: RevocationResponse,
    *,
    already_revoked: bool,
) -> dict[str, Any]:
    credential, descendants = _credential_scope(snapshot, task_id, credential_id)
    executions = _unique_records(snapshot, "executions", "execution_id")
    receipts = _unique_records(snapshot, "receipts", "receipt_id")
    events = _unique_records(snapshot, "audit_events", "event_id")
    cancellations = []
    rows = _unique_records(snapshot, "dispatch_cancellations", "execution_id")
    for row in rows.values():
        evidence = row.get("evidence")
        if (
            not isinstance(evidence, dict)
            or not _identifier(row.get("cancellation_id"))
            or not _identifier(row.get("denial_execution_id"))
            or evidence.get("record_type") != "DISPATCH_CANCELLED_V1"
            or evidence.get("task_id") != task_id
            or evidence.get("admission_decision") != "ALLOW"
            or evidence.get("dispatch_decision") != "DENY"
            or evidence.get("reason_code") not in ("ANCESTOR_REVOKED", "KEY_REVOKED")
            or not isinstance(evidence.get("revocations"), list)
            or not any(
                isinstance(item, dict)
                and item.get("credential_id") == credential_id
                and item.get("revoked_at") == saved.revoked_at
                and item.get("revoked_by") == saved.revoked_by
                and item.get("reason") == saved.revocation_reason
                for item in evidence["revocations"]
            )
            or any(
                evidence.get(key) != row.get(key)
                for key in (
                    "cancellation_id",
                    "execution_id",
                    "denial_execution_id",
                    "request_hash",
                    "credential_chain_hash",
                    "cancelled_at",
                    "reason_code",
                )
            )
        ):
            continue
        original = executions.get(row["execution_id"])
        denied = executions.get(row["denial_execution_id"])
        if not (
            original
            and original.get("state") == "RELEASED"
            and original.get("decision") == "ALLOW"
            and denied
            and denied.get("state") == "DENIED"
            and denied.get("decision") == "DENY"
            and denied.get("reason_code") == evidence["reason_code"]
            and all(
                original.get(key) == denied.get(key) == evidence.get(key)
                and isinstance(evidence.get(key), str)
                and re.fullmatch(r"[0-9a-f]{64}", evidence[key])
                for key in ("request_hash", "credential_chain_hash")
            )
        ):
            continue
        matching_receipts = [
            item
            for item in receipts.values()
            if item.get("execution_id") == denied["execution_id"]
            and item.get("decision") == "DENY"
            and item.get("reason_code") == evidence["reason_code"]
        ]
        cancellations.append(
            {
                "cancellation_id": row["cancellation_id"],
                "reason_code": evidence["reason_code"],
                "original_execution_id": original["execution_id"],
                "denied_execution_id": denied["execution_id"],
                "denied_receipt_id": matching_receipts[0]["receipt_id"]
                if len(matching_receipts) == 1
                else None,
                "audit_event_ids": sorted(
                    event["event_id"]
                    for event in events.values()
                    if event.get("execution_id") == original["execution_id"]
                    and event.get("event_type") == "EXECUTION_RELEASED"
                    and event.get("evidence_reference") == row["cancellation_id"]
                    and event.get("payload_hash") == sm3_hex(canonicalize(evidence))
                ),
            }
        )
    revocation_hash = sm3_hex(
        canonicalize(
            {
                "schema_version": "1.0",
                "record_type": "CREDENTIAL_REVOKED_V1",
                "credential_id": credential_id,
                "credential_type": credential["credential_type"],
                "parent_credential_id": credential["parent_credential_id"],
                "task_id": task_id,
                "revoked_at": saved.revoked_at,
                "revoked_by": saved.revoked_by,
                "reason": saved.revocation_reason,
            }
        )
    )
    audit_event_ids = sorted(
        event["event_id"]
        for event in events.values()
        if event.get("schema_version") == "4.0"
        and event.get("event_type") == "CREDENTIAL_REVOKED"
        and event.get("execution_id") is None
        and event.get("evidence_reference") == credential_id
        and event.get("payload_hash") == revocation_hash
        and event.get("evidence_binding_valid") is not False
    )
    try:
        result = UiRevocationResponse.model_validate(
            {
                "task_id": task_id,
                **saved.model_dump(mode="json"),
                "already_revoked": already_revoked,
                "descendant_count": descendants,
                "audit_status": "RECORDED"
                if audit_event_ids or any(row["audit_event_ids"] for row in cancellations)
                else "PENDING",
                "audit_event_ids": audit_event_ids,
                "cancellations": cancellations,
                "execution_observation": {
                    "released_count": sum(
                        row.get("state") == "RELEASED" for row in executions.values()
                    ),
                    "dispatched_or_unknown_count": sum(
                        row.get("state") in {"DISPATCHED", "UNKNOWN", "RECONCILING"}
                        for row in executions.values()
                    ),
                    "admitted_count": sum(
                        row.get("state") == "ADMITTED" for row in executions.values()
                    ),
                },
            }
        )
    except ValidationError as exc:
        raise UiApiError("CONTROLLED_RESULT_INVALID", "Revocation projection is invalid") from exc
    return result.model_dump(mode="json")


def revoke_credential(
    ui: UiService,
    task_id: str,
    credential_id: str,
    request: UiRevokeCredentialRequest,
    *,
    operator_id: str,
    revocation_url: str,
) -> dict[str, Any]:
    """operator_id is supplied only by the authenticated server route dependency."""
    if not _identifier(task_id) or not _identifier(credential_id):
        raise UiApiError(
            "REQUEST_SCHEMA_INVALID", "Invalid task or credential identifier", status_code=400
        )
    if not _identifier(operator_id):
        raise UiApiError(
            "OPERATOR_SESSION_REQUIRED", "Trusted operator identity is required", status_code=401
        )
    snapshot = ui.store.task_snapshot(task_id)
    credential, _ = _credential_scope(snapshot, task_id, credential_id)
    if credential.get("revoked_at") is not None:
        return _projection(
            snapshot,
            task_id,
            credential_id,
            _saved_revocation(credential),
            already_revoked=True,
        )
    if not revocation_url:
        raise UiApiError(
            "UPSTREAM_UNAVAILABLE", "Revocation authority URL is missing", status_code=503
        )
    path = f"/credentials/{credential_id}/revoke"
    try:
        if ui.settings.internal_auth_required is not True:
            raise ValueError("authenticated revocation is required")
        body = canonicalize({"reason": request.reason, "revoked_by": operator_id})
        auth = InternalAuthenticator.from_settings(ui.settings, service_id="ui-api")
        headers = auth.request_headers(
            recipient="revocation-authority",
            method="POST",
            path=path,
            body=body,
        )
    except (InternalAuthError, ValueError, UnicodeError):
        raise UiApiError(
            "INTERNAL_AUTH_UNAVAILABLE",
            "Revocation service authentication is unavailable",
            status_code=503,
        ) from None
    try:
        with httpx.Client(
            base_url=revocation_url,
            timeout=ui.settings.ui_request_timeout_seconds,
            trust_env=False,
        ) as client:
            response = client.post(path, content=body, headers=headers)
    except httpx.HTTPError:
        raise UiApiError(
            "REVOCATION_RESULT_UNCONFIRMED",
            "Revocation outcome is unknown; refresh saved records",
            status_code=503,
        ) from None
    try:
        parsed = parse_strict_json(response.content)
    except (ValueError, UnicodeError):
        raise UiApiError(
            "CONTROLLED_RESULT_INVALID", "Revocation authority returned invalid JSON"
        ) from None
    if response.status_code != 200:
        source = parsed.get("detail", parsed) if isinstance(parsed, dict) else {}
        reason = source.get("reason_code") if isinstance(source, dict) else None
        reason = (
            reason
            if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason)
            else "UPSTREAM_REJECTED"
        )
        if response.status_code == 409 and reason == "IDEMPOTENCY_CONFLICT":
            snapshot = ui.store.task_snapshot(task_id)
            credential, _ = _credential_scope(snapshot, task_id, credential_id)
            if credential.get("revoked_at") is not None:
                return _projection(
                    snapshot,
                    task_id,
                    credential_id,
                    _saved_revocation(credential),
                    already_revoked=True,
                )
        raise UiApiError(
            reason,
            "Revocation authority rejected the request; refresh saved records",
            status_code=response.status_code,
        )
    try:
        saved = RevocationResponse.model_validate(parsed)
        if (
            saved.credential_id != credential_id
            or saved.status != "REVOKED"
            or saved.revoked_by != operator_id
            or saved.revocation_reason != request.reason
            or saved.revoked_at > MAX_SAFE_INTEGER
        ):
            raise ValueError("revocation reply mismatch")
    except (ValidationError, ValueError):
        raise UiApiError(
            "CONTROLLED_RESULT_INVALID", "Revocation reply does not match the requested action"
        ) from None
    snapshot = ui.store.task_snapshot(task_id)
    credential, _ = _credential_scope(snapshot, task_id, credential_id)
    if _saved_revocation(credential) != saved:
        raise UiApiError(
            "REVOCATION_RESULT_UNCONFIRMED",
            "Authority reply and saved revocation differ; refresh records",
            status_code=503,
        )
    return _projection(snapshot, task_id, credential_id, saved, already_revoked=False)
