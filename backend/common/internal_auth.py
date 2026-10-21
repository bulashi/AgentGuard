from __future__ import annotations

import hmac
import re
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Set
from pathlib import Path
from typing import Any, Protocol

from fastapi import HTTPException, Request

from backend.common.error_codes import ReasonCode
from backend.common.time import now_unix
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import sm3_hex
from backend.crypto.strict_json import StrictJsonError, parse_strict_json

PROOF_HEADER = "X-AgentGuard-Internal-Proof"
CALLER_HEADER = "X-AgentGuard-Internal"
AUTH_VERSION = "AGENTGUARD_INTERNAL_AUTH_V1"
AUTH_DOMAIN = b"AGENTGUARD|INTERNAL_SERVICE_AUTH|V1\x00"
_SERVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_PROOF_FIELDS = {
    "version", "caller", "recipient", "method", "path", "body_sm3", "issued_at",
    "nonce", "mac_sm3",
}


class InternalAuthError(Exception):
    def __init__(self, reason_code: ReasonCode, *, status_code: int = 403) -> None:
        super().__init__(reason_code.value)
        self.reason_code = reason_code
        self.status_code = status_code


class NonceStore(Protocol):
    def claim(
        self, *, caller: str, recipient: str, nonce: str, expires_at: int, current_time: int,
    ) -> bool: ...


class SqliteNonceStore:
    """Atomic replay claims shared by local workers and retained across restarts.

    The file belongs to trusted service state, not a disposable download cache.
    This does not isolate processes running under the same Windows account.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def claim(
        self, *, caller: str, recipient: str, nonce: str, expires_at: int, current_time: int,
    ) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS internal_auth_nonces ("
                "caller TEXT NOT NULL, recipient TEXT NOT NULL, nonce TEXT NOT NULL, "
                "expires_at INTEGER NOT NULL, PRIMARY KEY (caller, recipient, nonce))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS internal_auth_clock ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "highest_time INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO internal_auth_clock (singleton, highest_time) VALUES (1, ?) "
                "ON CONFLICT (singleton) DO UPDATE "
                "SET highest_time = max(highest_time, excluded.highest_time)", (current_time,),
            )
            effective_time = connection.execute(
                "SELECT highest_time FROM internal_auth_clock WHERE singleton = 1"
            ).fetchone()[0]
            if expires_at < effective_time:
                raise InternalAuthError(ReasonCode.REQUEST_STALE)
            connection.execute(
                "DELETE FROM internal_auth_nonces WHERE expires_at < ?", (effective_time,),
            )
            result = connection.execute(
                "INSERT INTO internal_auth_nonces (caller, recipient, nonce, expires_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT (caller, recipient, nonce) DO NOTHING",
                (caller, recipient, nonce, expires_at),
            )
            return result.rowcount == 1


class InternalAuthenticator:
    def __init__(
        self, *, service_id: str, keys_json: str, required: bool = True,
        nonce_store: NonceStore | None = None, freshness_window_seconds: int = 60,
        allowed_clock_skew_seconds: int = 5, clock: Callable[[], int] | None = None,
    ) -> None:
        if (
            not isinstance(service_id, str) or _SERVICE_ID.fullmatch(service_id) is None
            or type(required) is not bool or type(freshness_window_seconds) is not int
            or not 1 <= freshness_window_seconds <= 3600
            or type(allowed_clock_skew_seconds) is not int
            or not 0 <= allowed_clock_skew_seconds <= 60
        ):
            raise ValueError("invalid internal authentication configuration")
        self.service_id = service_id
        self.required = required
        self.freshness_window_seconds = freshness_window_seconds
        self.allowed_clock_skew_seconds = allowed_clock_skew_seconds
        self._clock = clock or now_unix
        self._keys = self._parse_keys(keys_json)
        self._nonce_store = nonce_store or SqliteNonceStore(
            Path(__file__).resolve().parents[2] / ".native" / "internal-auth"
            / f"{service_id}-nonces.sqlite3"
        )

    @staticmethod
    def _parse_keys(keys_json: str) -> dict[str, bytes]:
        try:
            if not isinstance(keys_json, str):
                raise ValueError
            document = parse_strict_json(keys_json.encode("utf-8"))
            if not isinstance(document, dict):
                raise ValueError
            keys: dict[str, bytes] = {}
            for edge, value in document.items():
                parts = edge.split("->")
                if (
                    len(parts) != 2
                    or any(_SERVICE_ID.fullmatch(part) is None for part in parts)
                    or not isinstance(value, str) or _HEX_32.fullmatch(value) is None
                ):
                    raise ValueError
                keys[edge] = bytes.fromhex(value)
            return keys
        except (ValueError, TypeError, UnicodeError, StrictJsonError):
            # Configuration errors must never include secret values or parser excerpts.
            raise ValueError("invalid internal authentication key configuration") from None

    @classmethod
    def from_settings(cls, settings: Any, *, service_id: str) -> InternalAuthenticator:
        try:
            required = settings.internal_auth_required
            keys_json = settings.internal_auth_keys
            configured_id = settings.internal_auth_service_id
        except AttributeError:
            raise ValueError("internal authentication settings must be explicit") from None
        if configured_id and configured_id != service_id:
            raise ValueError("internal authentication service identity mismatch")
        return cls(
            service_id=service_id, keys_json=keys_json, required=required,
            nonce_store=SqliteNonceStore(
                Path(settings.internal_auth_nonce_root) / f"{service_id}-nonces.sqlite3"
            ) if getattr(settings, "internal_auth_nonce_root", "") else None,
            freshness_window_seconds=settings.freshness_window_seconds,
            allowed_clock_skew_seconds=settings.allowed_clock_skew_seconds,
        )

    def _key(self, caller: str, recipient: str) -> bytes:
        key = self._keys.get(f"{caller}->{recipient}")
        if key is None:
            raise InternalAuthError(ReasonCode.TOOL_NOT_ALLOWED)
        return key

    @staticmethod
    def _mac(key: bytes, proof: dict[str, Any]) -> str:
        return hmac.new(key, AUTH_DOMAIN + canonicalize(proof), "sm3").hexdigest()

    def request_headers(
        self, *, recipient: str, method: str, path: str, body: bytes,
        issued_at: int | None = None, nonce: str | None = None,
    ) -> dict[str, str]:
        headers = {CALLER_HEADER: self.service_id, "Content-Type": "application/json"}
        if not self.required:
            return headers
        timestamp = self._clock() if issued_at is None else issued_at
        request_nonce = secrets.token_hex(16) if nonce is None else nonce
        if (
            _SERVICE_ID.fullmatch(recipient) is None or not path.startswith("/")
            or "?" in path or "#" in path or type(timestamp) is not int
            or not 0 <= timestamp <= 9_007_199_254_740_991
            or _NONCE.fullmatch(request_nonce) is None
        ):
            raise ValueError("invalid internal authentication request")
        proof: dict[str, Any] = {
            "version": AUTH_VERSION, "caller": self.service_id, "recipient": recipient,
            "method": method.upper(), "path": path, "body_sm3": sm3_hex(body),
            "issued_at": timestamp, "nonce": request_nonce,
        }
        proof["mac_sm3"] = self._mac(self._key(self.service_id, recipient), proof)
        headers[PROOF_HEADER] = canonicalize(proof).decode("ascii")
        return headers

    def verify_headers(
        self, *, headers: Mapping[str, str], method: str, path: str, body: bytes,
        allowed_callers: Set[str],
    ) -> str:
        normalized = {key.lower(): value for key, value in headers.items()}
        raw_proof = normalized.get(PROOF_HEADER.lower())
        caller_header = normalized.get(CALLER_HEADER.lower())
        if not self.required and raw_proof is None:
            if caller_header in allowed_callers:
                return str(caller_header)
            raise InternalAuthError(ReasonCode.TOOL_NOT_ALLOWED)
        proof, current = self._verified_proof(
            headers=headers, method=method, path=path, allowed_callers=allowed_callers,
        )
        if not hmac.compare_digest(proof["body_sm3"], sm3_hex(body)):
            raise InternalAuthError(ReasonCode.INVALID_SIGNATURE)
        try:
            claimed = self._nonce_store.claim(
                caller=proof["caller"], recipient=self.service_id, nonce=proof["nonce"],
                expires_at=proof["issued_at"] + self.freshness_window_seconds
                + self.allowed_clock_skew_seconds, current_time=current,
            )
        except (OSError, sqlite3.Error):
            raise InternalAuthError(ReasonCode.TOOL_EXECUTION_UNKNOWN, status_code=503) from None
        if not claimed:
            raise InternalAuthError(ReasonCode.REPLAY_DETECTED, status_code=409)
        return str(proof["caller"])

    def _verified_proof(
        self, *, headers: Mapping[str, str], method: str, path: str, allowed_callers: Set[str],
    ) -> tuple[dict[str, Any], int]:
        normalized = {key.lower(): value for key, value in headers.items()}
        raw_proof = normalized.get(PROOF_HEADER.lower())
        caller_header = normalized.get(CALLER_HEADER.lower())
        try:
            if not isinstance(raw_proof, str) or len(raw_proof) > 4096:
                raise ValueError
            proof = parse_strict_json(raw_proof.encode("utf-8"))
            if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
                raise ValueError
            caller = proof["caller"]
            timestamp = proof["issued_at"]
            if (
                proof["version"] != AUTH_VERSION or not isinstance(caller, str)
                or caller not in allowed_callers or caller_header != caller
                or proof["recipient"] != self.service_id or proof["method"] != method
                or proof["path"] != path or type(timestamp) is not int
                or not 0 <= timestamp <= 9_007_199_254_740_991
                or not isinstance(proof["nonce"], str)
                or _NONCE.fullmatch(proof["nonce"]) is None
                or not isinstance(proof["mac_sm3"], str)
                or _HEX_32.fullmatch(proof["mac_sm3"]) is None
                or not isinstance(proof["body_sm3"], str)
                or _HEX_32.fullmatch(proof["body_sm3"]) is None
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeError, StrictJsonError):
            raise InternalAuthError(ReasonCode.TOOL_NOT_ALLOWED) from None
        current = self._clock()
        if (
            current - timestamp > self.freshness_window_seconds
            or timestamp - current > self.allowed_clock_skew_seconds
        ):
            raise InternalAuthError(ReasonCode.REQUEST_STALE)
        supplied_mac = proof.pop("mac_sm3")
        expected_mac = self._mac(self._key(caller, self.service_id), proof)
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise InternalAuthError(ReasonCode.INVALID_SIGNATURE)
        return proof, current

    async def authenticate_request(
        self, request: Request, *, allowed_callers: Set[str],
        allow_unsigned_in_test_mode: bool = False, max_body_bytes: int | None = None,
    ) -> str:
        try:
            if (
                request.url.query
                or len(request.headers.getlist(CALLER_HEADER)) > 1
                or len(request.headers.getlist(PROOF_HEADER)) > 1
            ):
                raise InternalAuthError(ReasonCode.TOOL_NOT_ALLOWED)
            if (
                not self.required and allow_unsigned_in_test_mode
                and CALLER_HEADER not in request.headers and PROOF_HEADER not in request.headers
            ):
                return "UNAUTHENTICATED_TEST_MODE"
            if self.required or PROOF_HEADER in request.headers:
                # Authenticate metadata before reading a raw coauthorization bundle.
                self._verified_proof(
                    headers=request.headers, method=request.method, path=request.url.path,
                    allowed_callers=allowed_callers,
                )
            body = await request.body()
            if max_body_bytes is not None and len(body) > max_body_bytes:
                raise InternalAuthError(ReasonCode.REQUEST_SCHEMA_INVALID, status_code=413)
            return self.verify_headers(
                headers=request.headers, method=request.method, path=request.url.path,
                body=body, allowed_callers=allowed_callers,
            )
        except InternalAuthError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail={"reason_code": exc.reason_code.value},
            ) from None
