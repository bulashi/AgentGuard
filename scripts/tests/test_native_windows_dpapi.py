from __future__ import annotations

import json
import os

import pytest

from scripts import native_windows_dpapi as dpapi
from scripts.native_windows_api import WindowsIsolationError, token_identity


class TestCipher:
    __test__ = False

    def __init__(self):
        self.records = {}

    def protect(self, value: bytes, *, purpose: str) -> str:
        record = dpapi.PREFIX + "test-record-" + str(len(self.records))
        self.records[record] = (purpose, value)
        return record

    def unprotect(self, value: str, *, purpose: str) -> bytes:
        if value not in self.records or self.records[value][0] != purpose:
            raise WindowsIsolationError("DPAPI_UNPROTECT")
        return self.records[value][1]


@pytest.fixture
def plaintext():
    return {
        **{name: "synthetic-" + name for name in dpapi.PASSWORD_FIELDS},
        "postgres_port": 15432,
        "future_metadata": {"preserve": True},
    }


@pytest.fixture
def cipher(monkeypatch):
    if os.name != "nt":
        monkeypatch.setattr(dpapi, "token_identity", lambda: {"user_sid": "S-1-0-0"})
    return TestCipher()


def test_database_document_roundtrip_and_no_password_values(plaintext, cipher):
    sid = token_identity()["user_sid"] if os.name == "nt" else "S-1-0-0"
    encoded = dpapi.encode_database_document(plaintext, cipher=cipher, owner_sid=sid)
    assert encoded[dpapi.STORAGE_FIELD] == {
        "schema_version": 1,
        "kind": "dpapi-current-user",
        "owner_sid": sid,
    }
    assert set(encoded) == set(plaintext) | {dpapi.STORAGE_FIELD}
    stored = json.dumps(encoded)
    assert all(
        value not in stored for name, value in plaintext.items() if name.endswith("_password")
    )
    assert dpapi.decode_database_document(encoded, cipher=cipher, owner_sid=sid) == plaintext


def test_explicit_migration_preserves_values_and_is_idempotent(tmp_path, plaintext, cipher):
    path = tmp_path / "config.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(plaintext).encode())
    result = dpapi.migrate_database_config(path, cipher=cipher)
    assert result == {"changed": True, "storage": "dpapi-current-user", "fields": 5}
    stored = path.read_bytes()
    assert dpapi.read_database_config(path, cipher=cipher) == plaintext
    assert all(
        value.encode() not in stored
        for name, value in plaintext.items()
        if name.endswith("_password")
    )
    assert dpapi.migrate_database_config(path, cipher=cipher)["changed"] is False
    assert path.read_bytes() == stored
    assert not list(tmp_path.glob("*.pending"))


def test_read_legacy_config_does_not_migrate(tmp_path, plaintext, cipher):
    path = tmp_path / "config.json"
    original = json.dumps(plaintext).encode()
    path.write_bytes(original)
    assert dpapi.read_database_config(path, cipher=cipher) == plaintext
    assert path.read_bytes() == original
    assert not (tmp_path / "config.json.dpapi.lock").exists()


def test_failed_atomic_replace_preserves_original(tmp_path, plaintext, cipher, monkeypatch):
    path = tmp_path / "config.json"
    original = json.dumps(plaintext).encode()
    path.write_bytes(original)

    def fail(*_):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(dpapi.os, "replace", fail)
    with pytest.raises(OSError):
        dpapi.migrate_database_config(path, cipher=cipher)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob("*.pending"))


def test_changed_source_is_never_overwritten(tmp_path, plaintext, cipher):
    path = tmp_path / "config.json"
    original = json.dumps(plaintext).encode()
    current = json.dumps(plaintext | {"another_writer": True}).encode()
    path.write_bytes(current)
    with pytest.raises(WindowsIsolationError, match="CONFIG_CHANGED_DURING_MIGRATION"):
        dpapi.save_database_config(path, plaintext, expected=original, cipher=cipher)
    assert path.read_bytes() == current
    assert not list(tmp_path.glob("*.pending"))


def test_missing_password_refuses_migration_without_invention(tmp_path, plaintext, cipher):
    path = tmp_path / "config.json"
    del plaintext["workflow_password"]
    original = json.dumps(plaintext).encode()
    path.write_bytes(original)
    with pytest.raises(WindowsIsolationError, match="CONFIG_PASSWORDS_INCOMPLETE"):
        dpapi.migrate_database_config(path, cipher=cipher)
    assert path.read_bytes() == original


@pytest.mark.parametrize("alteration", ["owner", "version", "kind", "mixed", "no_metadata"])
def test_corrupt_or_mixed_protection_is_fail_closed(plaintext, cipher, alteration):
    sid = token_identity()["user_sid"] if os.name == "nt" else "S-1-0-0"
    encoded = dpapi.encode_database_document(plaintext, cipher=cipher, owner_sid=sid)
    if alteration == "mixed":
        encoded["main_password"] = "plaintext"
    elif alteration == "no_metadata":
        del encoded[dpapi.STORAGE_FIELD]
    else:
        field = {"owner": "owner_sid", "version": "schema_version", "kind": "kind"}[alteration]
        encoded[dpapi.STORAGE_FIELD][field] = "invalid"
    with pytest.raises(WindowsIsolationError):
        dpapi.decode_database_document(encoded, cipher=cipher, owner_sid=sid)


def test_no_unknown_password_field_can_escape_encryption(plaintext, cipher):
    with pytest.raises(WindowsIsolationError, match="CONFIG_UNKNOWN_PASSWORD_FIELD"):
        dpapi.encode_database_document(
            plaintext | {"future_password": "synthetic"}, cipher=cipher, owner_sid="S-1-0-0"
        )


@pytest.mark.parametrize("value", [True, 0, 65536, "15432", None])
def test_invalid_port_rejects_before_writing(plaintext, cipher, value):
    plaintext["postgres_port"] = value
    with pytest.raises(WindowsIsolationError, match="CONFIG_POSTGRES_PORT_INVALID"):
        dpapi.encode_database_document(plaintext, cipher=cipher, owner_sid="S-1-0-0")


def test_duplicate_json_fields_are_rejected():
    with pytest.raises(WindowsIsolationError, match="CONFIG_DUPLICATE_FIELD"):
        dpapi.parse_document(b'{"main_password":"a","main_password":"b"}')


def test_native_runtime_consumes_raw_protected_config(plaintext, cipher, monkeypatch, tmp_path):
    from scripts import native_runtime

    sid = token_identity()["user_sid"] if os.name == "nt" else "S-1-0-0"
    encoded = dpapi.encode_database_document(plaintext, cipher=cipher, owner_sid=sid)
    monkeypatch.setattr(dpapi, "UserDpapi", lambda: cipher)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(encoded), encoding="utf-8")
    monkeypatch.setattr(native_runtime, "CONFIG", path)
    assert native_runtime.read_json(path) == plaintext
    assert native_runtime.database_urls(encoded) == native_runtime.database_urls(plaintext)
    assert json.loads(path.read_text())["main_password"].startswith(dpapi.PREFIX)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows DPAPI is required")
def test_actual_user_dpapi_and_entropy_binding():
    cipher = dpapi.UserDpapi()
    source = b"synthetic-user-dpapi-roundtrip"
    protected = cipher.protect(source, purpose="unit-roundtrip")
    assert protected.startswith(dpapi.PREFIX)
    assert cipher.unprotect(protected, purpose="unit-roundtrip") == source
    with pytest.raises(WindowsIsolationError, match="DPAPI_UNPROTECT"):
        cipher.unprotect(protected, purpose="different-purpose")


@pytest.mark.skipif(os.name != "nt", reason="actual Windows DPAPI is required")
def test_actual_database_migration_and_current_user_acl(tmp_path, plaintext):
    from scripts.native_windows_api import assert_private_acl

    path = tmp_path / "config.json"
    path.write_text(json.dumps(plaintext), encoding="utf-8")
    assert dpapi.migrate_database_config(path)["changed"]
    assert dpapi.read_database_config(path) == plaintext
    assert_private_acl(path, writers=(token_identity()["user_sid"],))


def test_hardlinked_config_is_never_replaced(tmp_path, plaintext, cipher):
    path = tmp_path / "config.json"
    original = json.dumps(plaintext).encode()
    path.write_bytes(original)
    alias = tmp_path / "alias.json"
    try:
        os.link(path, alias)
    except OSError:
        pytest.skip("the test volume does not support hardlinks")
    with pytest.raises(WindowsIsolationError, match="CONFIG_CHANGED_DURING_MIGRATION"):
        dpapi.migrate_database_config(path, cipher=cipher)
    assert path.read_bytes() == original == alias.read_bytes()


def test_read_rejects_reparse_input_without_following_it(tmp_path, plaintext, cipher):
    source, link = tmp_path / "source.json", tmp_path / "link.json"
    source.write_text(json.dumps(plaintext), encoding="utf-8")
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("the caller cannot create test symlinks")
    with pytest.raises(WindowsIsolationError, match="REPARSE_POINT_REJECTED"):
        dpapi.read_database_config(link, cipher=cipher)
