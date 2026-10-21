"""Current-user DPAPI records and explicit, atomic native database-config migration."""

from __future__ import annotations

import base64
import binascii
import ctypes
import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import ClassVar

from scripts.native_windows_api import (
    WindowsIsolationError,
    no_links,
    require_windows,
    set_acl,
    token_identity,
)

PASSWORD_FIELDS = (
    "admin_password",
    "main_password",
    "audit_password",
    "ui_password",
    "workflow_password",
)
PREFIX = "dpapi-user-v1:"
STORAGE_FIELD = "native_secret_storage"
MAX_RECORD = 196_608


class DATA_BLOB(ctypes.Structure):
    _fields_: ClassVar = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


class UserDpapi:
    """No machine-scope switch or plaintext fallback is available."""

    def _convert(self, value: bytes, purpose: str, *, decrypt: bool) -> bytes:
        require_windows()
        if not isinstance(value, bytes) or not 0 < len(value) <= MAX_RECORD:
            raise WindowsIsolationError("DPAPI_RECORD_SIZE")
        if not isinstance(purpose, str) or not 0 < len(purpose) <= 256 or "\x00" in purpose:
            raise WindowsIsolationError("DPAPI_PURPOSE_INVALID")
        source = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        entropy_value = ("AgentGuard.Native.v1:" + purpose).encode("utf-8")
        entropy = (ctypes.c_ubyte * len(entropy_value)).from_buffer_copy(entropy_value)
        input_blob, entropy_blob = DATA_BLOB(len(value), source), DATA_BLOB(len(entropy), entropy)
        output_blob = DATA_BLOB()
        library = ctypes.WinDLL("crypt32", use_last_error=True)
        operation = library.CryptUnprotectData if decrypt else library.CryptProtectData
        operation.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p,
            ctypes.POINTER(DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DATA_BLOB),
        ]
        operation.restype = ctypes.c_int
        try:
            # CRYPTPROTECT_UI_FORBIDDEN only. CRYPTPROTECT_LOCAL_MACHINE is never used.
            if not operation(
                ctypes.byref(input_blob),
                None,
                ctypes.byref(entropy_blob),
                None,
                None,
                1,
                ctypes.byref(output_blob),
            ):
                raise WindowsIsolationError(
                    "DPAPI_UNPROTECT" if decrypt else "DPAPI_PROTECT", ctypes.get_last_error()
                )
            if not 0 < output_blob.size <= MAX_RECORD:
                raise WindowsIsolationError("DPAPI_RECORD_SIZE")
            return ctypes.string_at(output_blob.data, output_blob.size)
        finally:
            ctypes.memset(source, 0, len(source))
            if output_blob.data:
                ctypes.memset(output_blob.data, 0, output_blob.size)
                free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
                free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
                free(output_blob.data)

    def protect(self, value: bytes, *, purpose: str) -> str:
        return PREFIX + base64.b64encode(self._convert(value, purpose, decrypt=False)).decode(
            "ascii"
        )

    def unprotect(self, value: str, *, purpose: str) -> bytes:
        if (
            not isinstance(value, str)
            or not value.startswith(PREFIX)
            or len(value) > MAX_RECORD * 2
        ):
            raise WindowsIsolationError("DPAPI_RECORD_FORMAT")
        try:
            protected = base64.b64decode(value[len(PREFIX) :], validate=True)
        except (ValueError, binascii.Error):
            raise WindowsIsolationError("DPAPI_RECORD_FORMAT") from None
        return self._convert(protected, purpose, decrypt=True)


def _unique_object(items: list[tuple]) -> dict:
    result = {}
    for name, value in items:
        if name in result:
            raise WindowsIsolationError("CONFIG_DUPLICATE_FIELD")
        result[name] = value
    return result


def parse_document(value: bytes) -> dict:
    if not 0 < len(value) <= MAX_RECORD:
        raise WindowsIsolationError("CONFIG_RECORD_SIZE")
    try:
        result = json.loads(value.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError):
        raise WindowsIsolationError("CONFIG_INVALID_JSON") from None
    if not isinstance(result, dict):
        raise WindowsIsolationError("CONFIG_INVALID_JSON")
    return result


def decode_database_document(
    value: dict, *, cipher: UserDpapi | None = None, owner_sid: str | None = None
) -> dict:
    if not isinstance(value, dict):
        raise WindowsIsolationError("CONFIG_INVALID_JSON")
    result = dict(value)
    metadata = result.pop(STORAGE_FIELD, None)
    protected_fields = [
        name
        for name in PASSWORD_FIELDS
        if isinstance(result.get(name), str) and result[name].startswith(PREFIX)
    ]
    if metadata is None:
        if protected_fields:
            raise WindowsIsolationError("CONFIG_PROTECTION_METADATA_MISSING")
        return result
    expected_sid = owner_sid or token_identity()["user_sid"]
    if metadata != {"schema_version": 1, "kind": "dpapi-current-user", "owner_sid": expected_sid}:
        raise WindowsIsolationError("CONFIG_PROTECTION_OWNER_OR_VERSION")
    cipher = cipher or UserDpapi()
    for name in PASSWORD_FIELDS:
        if name not in result:
            continue
        if name not in protected_fields:
            raise WindowsIsolationError("CONFIG_MIXED_SECRET_STORAGE")
        try:
            result[name] = cipher.unprotect(result[name], purpose="database:" + name).decode(
                "utf-8"
            )
        except UnicodeError:
            raise WindowsIsolationError("CONFIG_PASSWORD_ENCODING") from None
        if not result[name] or "\x00" in result[name]:
            raise WindowsIsolationError("CONFIG_PASSWORD_INVALID")
    return result


def encode_database_document(
    value: dict, *, cipher: UserDpapi | None = None, owner_sid: str | None = None
) -> dict:
    sid = owner_sid or token_identity()["user_sid"]
    cipher = cipher or UserDpapi()
    decoded = decode_database_document(value, cipher=cipher, owner_sid=sid)
    if any(name.endswith("_password") and name not in PASSWORD_FIELDS for name in decoded):
        raise WindowsIsolationError("CONFIG_UNKNOWN_PASSWORD_FIELD")
    if (
        not isinstance(decoded.get("postgres_port"), int)
        or isinstance(decoded["postgres_port"], bool)
        or not 1 <= decoded["postgres_port"] <= 65535
    ):
        raise WindowsIsolationError("CONFIG_POSTGRES_PORT_INVALID")
    result = dict(decoded)
    for name in PASSWORD_FIELDS:
        if name not in decoded:
            continue
        if not isinstance(decoded[name], str) or not decoded[name] or "\x00" in decoded[name]:
            raise WindowsIsolationError("CONFIG_PASSWORD_INVALID")
        result[name] = cipher.protect(decoded[name].encode("utf-8"), purpose="database:" + name)
    result[STORAGE_FIELD] = {"schema_version": 1, "kind": "dpapi-current-user", "owner_sid": sid}
    if decode_database_document(result, cipher=cipher, owner_sid=sid) != decoded:
        raise WindowsIsolationError("CONFIG_DPAPI_ROUNDTRIP_MISMATCH")
    return result


def read_database_config(path: Path, *, cipher: UserDpapi | None = None) -> dict:
    no_links(path)
    return decode_database_document(parse_document(path.read_bytes()), cipher=cipher)


@contextmanager
def config_lock(path: Path):
    no_links(path)
    lock = path.with_name(path.name + ".dpapi.lock")
    no_links(lock)
    with lock.open("a+b") as handle:
        if os.fstat(handle.fileno()).st_nlink != 1:
            raise WindowsIsolationError("CONFIG_LOCK_LINKED")
        if not handle.tell():
            handle.write(b"\0")
            handle.flush()
        if os.name != "nt":
            # Injected test ciphers can exercise migration logic on non-Windows hosts.
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return
        import msvcrt

        deadline = time.monotonic() + 10
        while True:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise WindowsIsolationError("CONFIG_LOCK_TIMEOUT") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def atomic_private_write(
    path: Path,
    content: bytes,
    *,
    expected: bytes | None,
    readers: tuple[str, ...] = (),
    writers: tuple[str, ...] = (),
) -> None:
    """The caller holds its config lock. Only ciphertext is written to the sibling temporary."""
    no_links(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
    descriptor = os.open(
        temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600
    )
    try:
        if os.name == "nt":
            set_acl(temporary, readers=readers, writers=writers)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if expected is None:
            if os.name == "nt":
                os.rename(temporary, path)  # Windows refuses an existing destination.
            else:
                os.link(temporary, path)
                temporary.unlink()
        else:
            no_links(path)
            if path.stat().st_nlink != 1 or path.read_bytes() != expected:
                raise WindowsIsolationError("CONFIG_CHANGED_DURING_MIGRATION")
            os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # This is our newly created ciphertext temporary, never pre-existing evidence.
        temporary.unlink(missing_ok=True)


def save_database_config(
    path: Path, value: dict, *, expected: bytes | None, cipher: UserDpapi | None = None
) -> None:
    owner = token_identity()["user_sid"] if os.name == "nt" else "S-1-0-0"
    protected = encode_database_document(value, cipher=cipher, owner_sid=owner)
    content = json.dumps(protected, indent=2, ensure_ascii=True).encode("utf-8")
    if len(content) > MAX_RECORD:
        raise WindowsIsolationError("CONFIG_RECORD_SIZE")
    atomic_private_write(path, content, expected=expected, writers=(owner,))


def migrate_database_config(path: Path, *, cipher: UserDpapi | None = None) -> dict:
    """Explicit only: preserve values/unknown metadata; no plaintext backup is created."""
    with config_lock(path):
        original = path.read_bytes()
        stored = parse_document(original)
        decoded = decode_database_document(stored, cipher=cipher)
        if any(
            not isinstance(decoded.get(name), str) or not decoded[name] for name in PASSWORD_FIELDS
        ):
            raise WindowsIsolationError("CONFIG_PASSWORDS_INCOMPLETE")
        if STORAGE_FIELD in stored:
            return {
                "changed": False,
                "storage": "dpapi-current-user",
                "fields": len(PASSWORD_FIELDS),
            }
        save_database_config(path, decoded, expected=original, cipher=cipher)
        if read_database_config(path, cipher=cipher) != decoded:
            raise WindowsIsolationError("CONFIG_MIGRATION_READBACK_MISMATCH")
        return {"changed": True, "storage": "dpapi-current-user", "fields": len(PASSWORD_FIELDS)}
