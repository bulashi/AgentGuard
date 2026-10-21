from __future__ import annotations

import socket

import pytest

from scripts import native_windows_probe as probe
from scripts import native_windows_service as service
from scripts.native_windows_api import (
    ADMINISTRATORS_SID,
    SYSTEM_SID,
    Scm,
    WindowsIsolationError,
)


@pytest.mark.parametrize("responses", [[0, 1060], [1072, 1060], [1060]])
def test_cleanup_waits_for_actual_service_absence(monkeypatch, responses):
    remaining = iter(responses)

    class TestScm:
        def configuration(self, _):
            code = next(remaining)
            if code:
                raise WindowsIsolationError("SERVICE_OPEN", code)
            return {}

    monkeypatch.setattr(probe.time, "sleep", lambda _: None)
    probe._confirm_deleted(TestScm(), "AgentGuardProbe_1234567890abcdef_probe-a")


def test_cleanup_does_not_treat_access_denied_as_deletion():
    class TestScm:
        def configuration(self, _):
            raise WindowsIsolationError("SERVICE_OPEN", 5)

    with pytest.raises(WindowsIsolationError) as raised:
        probe._confirm_deleted(TestScm(), "AgentGuardProbe_1234567890abcdef_probe-a")
    assert raised.value.winerror == 5


def test_cleanup_timeout_is_explicit_failure(monkeypatch):
    clock = iter((0, 0, 11))
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(probe.time, "sleep", lambda _: None)

    class TestScm:
        def configuration(self, _):
            return {}

    with pytest.raises(WindowsIsolationError, match="PROBE_SERVICE_DELETE_NOT_CONFIRMED"):
        probe._confirm_deleted(TestScm(), "AgentGuardProbe_1234567890abcdef_probe-a")


@pytest.mark.parametrize("alteration", [None, "foreign", "limited", "deny", "inherit-only"])
def test_service_control_acl_requires_only_admin_and_system(alteration):
    entries = [
        {"sid": sid, "mask": 0x10000000, "allow": True, "flags": 0}
        for sid in (ADMINISTRATORS_SID, SYSTEM_SID)
    ]
    if alteration == "foreign":
        entries.append({"sid": "S-1-5-80-1-2-3-4-5", "mask": 0x10000000, "allow": True, "flags": 0})
    elif alteration == "limited":
        entries[0]["mask"] = 4
    elif alteration == "deny":
        entries[0]["allow"] = False
    elif alteration == "inherit-only":
        entries[0]["flags"] = 8
    subject = Scm.__new__(Scm)
    subject.control_acl = lambda _: {"entries": entries}
    if alteration is None:
        subject.assert_control_acl("AgentGuardProbe_1234567890abcdef_probe-a")
    else:
        with pytest.raises(WindowsIsolationError, match="SERVICE_CONTROL_ACL_MISMATCH"):
            subject.assert_control_acl("AgentGuardProbe_1234567890abcdef_probe-a")


def test_probe_blocks_and_counts_python_network_attempts(monkeypatch):
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, getattr(socket, name))
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, getattr(socket.socket, name))
    attempts = service.block_probe_network()
    assert attempts["count"] == 0
    with pytest.raises(WindowsIsolationError, match="PROBE_NETWORK_FORBIDDEN"):
        socket.getaddrinfo("scm-probe.invalid", 443)
    with socket.socket() as handle:
        with pytest.raises(WindowsIsolationError, match="PROBE_NETWORK_FORBIDDEN"):
            handle.connect(("127.0.0.1", 1))
    assert attempts["count"] == 2
