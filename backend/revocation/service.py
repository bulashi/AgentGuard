from __future__ import annotations

from typing import Any

from backend.common.error_codes import ReasonCode
from backend.common.time import now_unix
from backend.revocation.audit import enqueue_revocation
from backend.revocation.contracts import RevokeCredentialRequest
from backend.revocation.dispatch_guard import cancel_revoked_admissions
from backend.state.database import connect


class RevocationError(RuntimeError):
    def __init__(self, reason_code: ReasonCode, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


class RevocationService:
    """Apply a credential revocation at a database-defined linearization point."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def revoke(
        self,
        credential_id: str,
        request: RevokeCredentialRequest,
        *,
        current_time: int | None = None,
    ) -> dict[str, Any]:
        timestamp = now_unix() if current_time is None else current_time
        with connect(self.database_url) as connection, connection.transaction():
            credential = connection.execute(
                """
                SELECT credential_id
                FROM credentials
                WHERE credential_id = %s
                FOR UPDATE
                """,
                (credential_id,),
            ).fetchone()
            if credential is None:
                raise RevocationError(
                    ReasonCode.CROSS_TASK,
                    "credential does not exist",
                    status_code=404,
                )

            existing = connection.execute(
                """
                SELECT revoked_at, revocation_reason, revoked_by
                FROM credential_revocations
                WHERE credential_id = %s
                FOR UPDATE
                """,
                (credential_id,),
            ).fetchone()
            if existing is not None:
                if str(existing[1]) != request.reason or str(existing[2]) != request.revoked_by:
                    raise RevocationError(
                        ReasonCode.IDEMPOTENCY_CONFLICT,
                        "credential already has different revocation evidence",
                        status_code=409,
                    )
                response = self._response(
                    credential_id,
                    revoked_at=int(existing[0]),
                    reason=str(existing[1]),
                    revoked_by=str(existing[2]),
                )

            else:
                connection.execute(
                    """
                    INSERT INTO credential_revocations (
                        credential_id, revoked_at, revocation_reason, revoked_by
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (credential_id, timestamp, request.reason, request.revoked_by),
                )
                response = self._response(
                    credential_id, revoked_at=timestamp, reason=request.reason, revoked_by=request.revoked_by,
                )
            enqueue_revocation(connection, credential_id)
        # Revocation commits first; each pending execution has its own chain/settlement transaction.
        # A dispatched/unknown execution is never cancelled or released by this sweep.
        try:
            cancel_revoked_admissions(self.database_url, credential_id)
        except Exception as error:
            raise RevocationError(
                ReasonCode.TOOL_EXECUTION_UNKNOWN,
                "revocation committed; pending dispatch cancellation requires reconciliation",
                status_code=503,
            ) from error
        return response

    @staticmethod
    def _response(
        credential_id: str,
        *,
        revoked_at: int,
        reason: str,
        revoked_by: str,
    ) -> dict[str, Any]:
        return {
            "credential_id": credential_id,
            "revoked_at": revoked_at,
            "revocation_reason": reason,
            "revoked_by": revoked_by,
            "status": "REVOKED",
        }
