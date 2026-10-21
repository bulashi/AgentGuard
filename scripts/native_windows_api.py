"""Small Win32 surface for scoped SCM identities, ACLs and local provisioning IPC."""

from __future__ import annotations

import ctypes
import os
import re
import struct
import time
from contextlib import contextmanager
from pathlib import Path
from typing import ClassVar

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_DEMAND_START = 3
SERVICE_QUERY_CONFIG = 1
SERVICE_CHANGE_CONFIG = 2
SERVICE_QUERY_STATUS = 4
SERVICE_START = 0x10
SERVICE_STOP = 0x20
DELETE = 0x10000
SERVICE_SID_TYPE_UNRESTRICTED = 1
SERVICE_ACCESS = (
    SERVICE_QUERY_CONFIG
    | SERVICE_CHANGE_CONFIG
    | SERVICE_QUERY_STATUS
    | SERVICE_START
    | SERVICE_STOP
    | DELETE
    | 0x40000  # WRITE_DAC is required to protect the newly created service control object.
)
NAME = re.compile(r"AgentGuard(?:Probe|Svc)_[a-f0-9]{16}_[a-z0-9-]{1,48}\Z")
READ_EXECUTE = 0x1200A9
FULL_CONTROL = 0x1F01FF
WRITE_RIGHTS = 0xD0000 | 0x116 | 0x50000000
MAX_MESSAGE = 262_144


class WindowsIsolationError(RuntimeError):
    """Messages are fixed reason codes; never include API inputs or secret values."""

    def __init__(self, code: str, winerror: int = 0):
        super().__init__(code)
        self.code = code
        self.winerror = int(winerror) & 0xFFFFFFFF


def require_windows() -> None:
    if os.name != "nt":
        raise WindowsIsolationError("WINDOWS_REQUIRED")


def _dll(name: str):
    require_windows()
    return ctypes.WinDLL(name, use_last_error=True)


def _function(dll, name: str, arguments: list, result=ctypes.c_int):
    operation = getattr(dll, name)
    operation.argtypes = arguments
    operation.restype = result
    return operation


def _check(value, code: str):
    if not value:
        raise WindowsIsolationError(code, ctypes.get_last_error())
    return value


def close_handle(handle) -> None:
    _check(_function(_dll("kernel32"), "CloseHandle", [ctypes.c_void_p])(handle), "HANDLE_CLOSE")


def _sid_string(pointer) -> str:
    result = ctypes.c_void_p()
    _check(
        _function(_dll("advapi32"), "ConvertSidToStringSidW", [ctypes.c_void_p, ctypes.c_void_p])(
            pointer, ctypes.byref(result)
        ),
        "SID_CONVERSION",
    )
    try:
        return ctypes.wstring_at(result)
    finally:
        _function(_dll("kernel32"), "LocalFree", [ctypes.c_void_p], ctypes.c_void_p)(result)


def probe_read_file(path: Path, *, maximum: int = 32) -> bytes:
    """Use Win32 errors for the access probe; Python's CRT open reports only errno on Windows."""
    if not 1 <= maximum <= 4096:
        raise WindowsIsolationError("PROBE_READ_SIZE")
    kernel = _dll("kernel32")
    handle = _function(
        kernel,
        "CreateFileW",
        [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ],
        ctypes.c_void_p,
    )(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise WindowsIsolationError("PROBE_FILE_OPEN", ctypes.get_last_error())
    try:
        size, buffer = ctypes.c_uint32(), ctypes.create_string_buffer(maximum)
        _check(
            _function(
                kernel,
                "ReadFile",
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ],
            )(handle, buffer, maximum, ctypes.byref(size), None),
            "PROBE_FILE_READ",
        )
        return buffer.raw[: size.value]
    finally:
        close_handle(handle)


def account_sid(account: str) -> str:
    operation = _function(
        _dll("advapi32"),
        "LookupAccountNameW",
        [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ],
    )
    sid_size, domain_size, kind = ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32()
    operation(
        None,
        account,
        None,
        ctypes.byref(sid_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(kind),
    )
    if not sid_size.value or sid_size.value > 256 or domain_size.value > 4096:
        raise WindowsIsolationError("SERVICE_SID_LOOKUP", ctypes.get_last_error())
    sid = ctypes.create_string_buffer(sid_size.value)
    domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
    _check(
        operation(
            None,
            account,
            sid,
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(kind),
        ),
        "SERVICE_SID_LOOKUP",
    )
    return _sid_string(sid)


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_: ClassVar = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_uint32)]


def _token_information(token, kind: int):
    size = ctypes.c_uint32()
    operation = _function(
        _dll("advapi32"),
        "GetTokenInformation",
        [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p],
    )
    operation(token, kind, None, 0, ctypes.byref(size))
    if not 0 < size.value <= 1_048_576:
        raise WindowsIsolationError("TOKEN_INFORMATION", ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(size.value)
    _check(operation(token, kind, buffer, size, ctypes.byref(size)), "TOKEN_INFORMATION")
    return buffer


def token_identity(pid: int | None = None) -> dict:
    kernel, advapi = _dll("kernel32"), _dll("advapi32")
    process = None
    token = ctypes.c_void_p()
    if pid is None:
        handle = _function(kernel, "GetCurrentProcess", [], ctypes.c_void_p)()
    else:
        process = _check(
            _function(
                kernel,
                "OpenProcess",
                [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32],
                ctypes.c_void_p,
            )(0x1000, False, pid),
            "PROCESS_QUERY",
        )
        handle = process
    try:
        _check(
            _function(
                advapi, "OpenProcessToken", [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
            )(handle, 8, ctypes.byref(token)),
            "TOKEN_OPEN",
        )
        user = SID_AND_ATTRIBUTES.from_buffer(_token_information(token, 1))
        user_sid = _sid_string(user.sid)
        groups_buffer = _token_information(token, 2)
        count = ctypes.c_uint32.from_buffer(groups_buffer).value
        offset = ctypes.sizeof(ctypes.c_void_p)
        groups = (SID_AND_ATTRIBUTES * count).from_buffer(groups_buffer, offset)
        enabled = [
            _sid_string(item.sid)
            for item in groups
            if item.attributes & 4 and not item.attributes & 0x10
        ]
        return {
            "user_sid": user_sid,
            "enabled_groups": enabled,
            "elevated_admin": ADMINISTRATORS_SID in enabled,
            "system": user_sid == SYSTEM_SID,
        }
    finally:
        if token:
            close_handle(token)
        if process:
            close_handle(process)


def require_admin() -> dict:
    identity = token_identity()
    if not identity["elevated_admin"] and not identity["system"]:
        raise WindowsIsolationError("ELEVATED_ADMIN_REQUIRED")
    return identity


def require_service_identity(service_name: str) -> dict:
    validate_service_name(service_name)
    identity = token_identity()
    expected = account_sid("NT SERVICE\\" + service_name)
    if identity["user_sid"] != expected or identity["elevated_admin"] or identity["system"]:
        raise WindowsIsolationError("VIRTUAL_SERVICE_TOKEN_MISMATCH")
    return identity


def no_links(path: Path, *, within: Path | None = None) -> Path:
    path = path.absolute()
    if any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)):
        raise WindowsIsolationError("REPARSE_POINT_REJECTED")
    resolved = path.resolve()
    if within is not None and not resolved.is_relative_to(within.resolve()):
        raise WindowsIsolationError("PATH_OUTSIDE_OWNED_ROOT")
    return resolved


@contextmanager
def security_descriptor(sddl: str):
    descriptor = ctypes.c_void_p()
    _check(
        _function(
            _dll("advapi32"),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p],
        )(sddl, 1, ctypes.byref(descriptor), None),
        "ACL_DESCRIPTOR",
    )
    try:
        yield descriptor
    finally:
        _function(_dll("kernel32"), "LocalFree", [ctypes.c_void_p], ctypes.c_void_p)(descriptor)


def acl_sddl(readers: tuple[str, ...] = (), writers: tuple[str, ...] = ()) -> str:
    subjects = {SYSTEM_SID: "FA", ADMINISTRATORS_SID: "FA"}
    for sid in readers:
        subjects.setdefault(sid, "FRFX")
    for sid in writers:
        subjects[sid] = "FA"
    if any(not re.fullmatch(r"S-1-(?:\d+-)*\d+", sid) for sid in subjects):
        raise WindowsIsolationError("ACL_SID_INVALID")
    return "D:P" + "".join(f"(A;OICI;{rights};;;{sid})" for sid, rights in subjects.items())


def set_acl(path: Path, *, readers: tuple[str, ...] = (), writers: tuple[str, ...] = ()) -> None:
    no_links(path)
    with security_descriptor(acl_sddl(readers, writers)) as descriptor:
        _check(
            _function(
                _dll("advapi32"),
                "SetFileSecurityW",
                [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p],
            )(str(path), 4 | 0x80000000, descriptor),
            "ACL_APPLY",
        )


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_: ClassVar = [
        ("count", ctypes.c_uint32),
        ("used", ctypes.c_uint32),
        ("free", ctypes.c_uint32),
    ]


def _descriptor_acl(descriptor) -> dict:
    advapi = _dll("advapi32")
    owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    present, defaulted = ctypes.c_int(), ctypes.c_int()
    _check(
        _function(
            advapi,
            "GetSecurityDescriptorOwner",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
        )(descriptor, ctypes.byref(owner), ctypes.byref(defaulted)),
        "ACL_READ",
    )
    _check(
        _function(
            advapi,
            "GetSecurityDescriptorDacl",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
        )(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)),
        "ACL_READ",
    )
    if not present.value or not dacl:
        raise WindowsIsolationError("NULL_DACL_REJECTED")
    information = ACL_SIZE_INFORMATION()
    _check(
        _function(
            advapi,
            "GetAclInformation",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32],
        )(dacl, ctypes.byref(information), ctypes.sizeof(information), 2),
        "ACL_READ",
    )
    entries = []
    for index in range(information.count):
        pointer = ctypes.c_void_p()
        _check(
            _function(advapi, "GetAce", [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p])(
                dacl, index, ctypes.byref(pointer)
            ),
            "ACL_READ",
        )
        kind, flags, _, mask = struct.unpack("<BBHI", ctypes.string_at(pointer, 8))
        if kind not in (0, 1):
            raise WindowsIsolationError("UNSUPPORTED_ACL_ENTRY")
        entries.append(
            {
                "sid": _sid_string(pointer.value + 8),
                "mask": mask,
                "flags": flags,
                "allow": kind == 0,
            }
        )
    control, revision = ctypes.c_uint16(), ctypes.c_uint32()
    _check(
        _function(
            advapi,
            "GetSecurityDescriptorControl",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
        )(descriptor, ctypes.byref(control), ctypes.byref(revision)),
        "ACL_READ",
    )
    return {
        "owner": _sid_string(owner) if owner else None,
        "protected": bool(control.value & 0x1000),
        "entries": entries,
    }


def acl_entries(path: Path) -> dict:
    no_links(path)
    descriptor = ctypes.c_void_p()
    status = _function(
        _dll("advapi32"),
        "GetNamedSecurityInfoW",
        [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ],
        ctypes.c_uint32,
    )(str(path), 1, 1 | 4, None, None, None, None, ctypes.byref(descriptor))
    if status:
        raise WindowsIsolationError("ACL_READ", status)
    try:
        return _descriptor_acl(descriptor)
    finally:
        _function(_dll("kernel32"), "LocalFree", [ctypes.c_void_p], ctypes.c_void_p)(descriptor)


def assert_private_acl(
    path: Path, *, readers: tuple[str, ...] = (), writers: tuple[str, ...] = ()
) -> dict:
    actual = acl_entries(path)
    permitted = {SYSTEM_SID: FULL_CONTROL, ADMINISTRATORS_SID: FULL_CONTROL}
    permitted.update(dict.fromkeys(readers, READ_EXECUTE))
    permitted.update(dict.fromkeys(writers, FULL_CONTROL))
    seen = {}
    for entry in actual["entries"]:
        if not entry["allow"] or entry["flags"] & 8:
            raise WindowsIsolationError("PRIVATE_ACL_MISMATCH")
        seen[entry["sid"]] = seen.get(entry["sid"], 0) | entry["mask"]
    if not actual["protected"] or seen != permitted:
        raise WindowsIsolationError("PRIVATE_ACL_MISMATCH")
    return actual


def assert_trusted_code(path: Path, *, administrator_sid: str) -> None:
    trusted = {SYSTEM_SID, ADMINISTRATORS_SID, administrator_sid}
    for subject in (no_links(path), *path.absolute().parents):
        if not subject.exists():
            raise WindowsIsolationError("CODE_PATH_MISSING")
        actual = acl_entries(subject)
        if actual["owner"] not in trusted:
            raise WindowsIsolationError("UNTRUSTED_CODE_OWNER")
        if any(
            entry["allow"]
            and not entry["flags"] & 8
            and entry["sid"] not in trusted
            and entry["mask"] & WRITE_RIGHTS
            for entry in actual["entries"]
        ):
            raise WindowsIsolationError("CODE_WRITABLE_BY_UNTRUSTED_IDENTITY")


def validate_service_name(name: str) -> None:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise WindowsIsolationError("SCOPED_SERVICE_NAME_REQUIRED")


class SERVICE_STATUS(ctypes.Structure):
    _fields_: ClassVar = [
        (name, ctypes.c_uint32)
        for name in (
            "service_type",
            "state",
            "controls",
            "win32_exit",
            "service_exit",
            "checkpoint",
            "hint",
        )
    ]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_: ClassVar = [
        *SERVICE_STATUS._fields_,
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]


class QUERY_SERVICE_CONFIG(ctypes.Structure):
    _fields_: ClassVar = [
        ("service_type", ctypes.c_uint32),
        ("start_type", ctypes.c_uint32),
        ("error_control", ctypes.c_uint32),
        ("binary", ctypes.c_wchar_p),
        ("group", ctypes.c_wchar_p),
        ("tag", ctypes.c_uint32),
        ("dependencies", ctypes.c_wchar_p),
        ("account", ctypes.c_wchar_p),
        ("display", ctypes.c_wchar_p),
    ]


class Scm:
    def __init__(self, *, create: bool = False):
        self.advapi = _dll("advapi32")
        self.handle = _check(
            _function(
                self.advapi,
                "OpenSCManagerW",
                [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32],
                ctypes.c_void_p,
            )(None, None, 1 | (2 if create else 0)),
            "SCM_OPEN",
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._close(self.handle)

    def _close(self, handle):
        _check(_function(self.advapi, "CloseServiceHandle", [ctypes.c_void_p])(handle), "SCM_CLOSE")

    @contextmanager
    def service(self, name: str, access: int = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS):
        validate_service_name(name)
        handle = _check(
            _function(
                self.advapi,
                "OpenServiceW",
                [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32],
                ctypes.c_void_p,
            )(self.handle, name, access),
            "SERVICE_OPEN",
        )
        try:
            yield handle
        finally:
            self._close(handle)

    def create(self, name: str, command: str) -> None:
        validate_service_name(name)
        if not command or "\x00" in command:
            raise WindowsIsolationError("SERVICE_COMMAND_INVALID")
        handle = _check(
            _function(
                self.advapi,
                "CreateServiceW",
                [
                    ctypes.c_void_p,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_void_p,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                ],
                ctypes.c_void_p,
            )(
                self.handle,
                name,
                name,
                SERVICE_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                1,
                command,
                None,
                None,
                None,
                "NT SERVICE\\" + name,
                None,
            ),
            "SERVICE_CREATE",
        )
        try:
            change = _function(
                self.advapi,
                "ChangeServiceConfig2W",
                [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p],
            )
            sid_type = ctypes.c_uint32(SERVICE_SID_TYPE_UNRESTRICTED)
            _check(change(handle, 5, ctypes.byref(sid_type)), "SERVICE_SID_CONFIG")
            privileges = ctypes.create_unicode_buffer("SeChangeNotifyPrivilege\0\0")
            pointer = ctypes.c_void_p(ctypes.addressof(privileges))
            _check(change(handle, 6, ctypes.byref(pointer)), "SERVICE_PRIVILEGE_CONFIG")
            with security_descriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)") as descriptor:
                _check(
                    _function(
                        self.advapi,
                        "SetServiceObjectSecurity",
                        [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p],
                    )(handle, 4, descriptor),
                    "SERVICE_CONTROL_ACL",
                )
        except Exception:
            # This handle was returned by CreateService, so only this newly created object is owned.
            _function(self.advapi, "DeleteService", [ctypes.c_void_p])(handle)
            raise
        finally:
            self._close(handle)

    def configuration(self, name: str) -> dict:
        with self.service(name, SERVICE_QUERY_CONFIG) as handle:
            size = ctypes.c_uint32()
            query = _function(
                self.advapi,
                "QueryServiceConfigW",
                [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p],
            )
            query(handle, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 65_536:
                raise WindowsIsolationError("SERVICE_CONFIG_QUERY", ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(size.value)
            _check(query(handle, buffer, size, ctypes.byref(size)), "SERVICE_CONFIG_QUERY")
            value = QUERY_SERVICE_CONFIG.from_buffer(buffer)
            query_optional = _function(
                self.advapi,
                "QueryServiceConfig2W",
                [
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ],
            )

            def optional(level: int):
                needed = ctypes.c_uint32()
                query_optional(handle, level, None, 0, ctypes.byref(needed))
                if not 0 < needed.value <= 65_536:
                    raise WindowsIsolationError("SERVICE_CONFIG_QUERY")
                data = ctypes.create_string_buffer(needed.value)
                _check(
                    query_optional(handle, level, data, needed, ctypes.byref(needed)),
                    "SERVICE_CONFIG_QUERY",
                )
                return data

            sid_type = ctypes.c_uint32.from_buffer(optional(5)).value
            privilege_buffer = optional(6)
            pointer = ctypes.c_void_p.from_buffer(privilege_buffer).value
            if pointer is None:
                privileges = []
            else:
                available = ctypes.addressof(privilege_buffer) + len(privilege_buffer) - pointer
                if not 0 < available <= len(privilege_buffer):
                    raise WindowsIsolationError("SERVICE_CONFIG_QUERY")
                privileges = ctypes.wstring_at(pointer, available // ctypes.sizeof(ctypes.c_wchar))
                privileges = privileges.split("\0\0", 1)[0].split("\0")
            return {
                "binary": value.binary,
                "account": value.account,
                "service_type": value.service_type,
                "start_type": value.start_type,
                "sid_type": sid_type,
                "required_privileges": privileges,
            }

    def assert_owned(self, name: str, command: str) -> None:
        value = self.configuration(name)
        if (
            value["binary"] != command
            or value["account"].casefold() != ("NT SERVICE\\" + name).casefold()
            or value["service_type"] != SERVICE_WIN32_OWN_PROCESS
            or value["start_type"] != SERVICE_DEMAND_START
            or value["sid_type"] != SERVICE_SID_TYPE_UNRESTRICTED
            or value["required_privileges"] != ["SeChangeNotifyPrivilege"]
        ):
            raise WindowsIsolationError("SERVICE_OWNERSHIP_MISMATCH")
        self.assert_control_acl(name)

    def control_acl(self, name: str) -> dict:
        with self.service(name, 0x20000) as handle:
            query = _function(
                self.advapi,
                "QueryServiceObjectSecurity",
                [
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ],
            )
            size = ctypes.c_uint32()
            query(handle, 1 | 4, None, 0, ctypes.byref(size))
            if not 0 < size.value <= 65_536:
                raise WindowsIsolationError("SERVICE_CONTROL_ACL_READ", ctypes.get_last_error())
            descriptor = ctypes.create_string_buffer(size.value)
            _check(
                query(handle, 1 | 4, descriptor, size, ctypes.byref(size)),
                "SERVICE_CONTROL_ACL_READ",
            )
            return _descriptor_acl(descriptor)

    def assert_control_acl(self, name: str) -> None:
        actual = self.control_acl(name)
        entries = actual["entries"]
        if (
            len(entries) != 2
            or {entry["sid"] for entry in entries} != {SYSTEM_SID, ADMINISTRATORS_SID}
            or any(
                not entry["allow"]
                or entry["flags"] & 8
                or entry["mask"] not in {0x10000000, 0xF01FF}
                for entry in entries
            )
        ):
            raise WindowsIsolationError("SERVICE_CONTROL_ACL_MISMATCH")

    def status(self, name: str) -> dict:
        with self.service(name, SERVICE_QUERY_STATUS) as handle:
            value, size = SERVICE_STATUS_PROCESS(), ctypes.c_uint32()
            _check(
                _function(
                    self.advapi,
                    "QueryServiceStatusEx",
                    [
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.c_void_p,
                    ],
                )(handle, 0, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)),
                "SERVICE_STATUS_QUERY",
            )
            return {
                key: int(getattr(value, key))
                for key in ("state", "pid", "win32_exit", "service_exit")
            }

    def start(self, name: str, command: str, arguments: tuple[str, ...] = ()) -> None:
        self.assert_owned(name, command)
        with self.service(name, SERVICE_START) as handle:
            values = (ctypes.c_wchar_p * len(arguments))(*arguments) if arguments else None
            _check(
                _function(
                    self.advapi,
                    "StartServiceW",
                    [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p],
                )(handle, len(arguments), values),
                "SERVICE_START",
            )

    def wait(self, name: str, desired: int, *, timeout: float = 30) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.status(name)
            if status["state"] == desired:
                if status["win32_exit"] or status["service_exit"]:
                    raise WindowsIsolationError("SERVICE_REPORTED_FAILURE", status["service_exit"])
                return status
            if desired == SERVICE_RUNNING and status["state"] == SERVICE_STOPPED:
                raise WindowsIsolationError("SERVICE_STOPPED_BEFORE_READY", status["service_exit"])
            time.sleep(0.1)
        raise WindowsIsolationError("SERVICE_STATUS_TIMEOUT")

    def stop(self, name: str, command: str) -> None:
        self.assert_owned(name, command)
        if self.status(name)["state"] == SERVICE_STOPPED:
            return
        with self.service(name, SERVICE_STOP) as handle:
            status = SERVICE_STATUS()
            result = _function(
                self.advapi, "ControlService", [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
            )(handle, 1, ctypes.byref(status))
            if not result and ctypes.get_last_error() != 1062:
                raise WindowsIsolationError("SERVICE_STOP", ctypes.get_last_error())
        self.wait(name, SERVICE_STOPPED)

    def delete_ephemeral(self, name: str, command: str) -> None:
        if not name.startswith("AgentGuardProbe_"):
            raise WindowsIsolationError("EPHEMERAL_SERVICE_REQUIRED")
        self.assert_owned(name, command)
        if self.status(name)["state"] != SERVICE_STOPPED:
            raise WindowsIsolationError("EPHEMERAL_SERVICE_STILL_RUNNING")
        with self.service(name, DELETE) as handle:
            _check(
                _function(self.advapi, "DeleteService", [ctypes.c_void_p])(handle),
                "EPHEMERAL_SERVICE_DELETE",
            )


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_: ClassVar = [
        ("size", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int),
    ]


def pipe_name(service_name: str) -> str:
    validate_service_name(service_name)
    return "\\\\.\\pipe\\" + service_name + "_provision"


def _read_message(handle, *, timeout: float = 25) -> bytes:
    size = ctypes.c_uint32()
    buffer = ctypes.create_string_buffer(MAX_MESSAGE)
    operation = _function(
        _dll("kernel32"),
        "ReadFile",
        [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p],
    )
    deadline = time.monotonic() + timeout
    while not operation(handle, buffer, len(buffer), ctypes.byref(size), None):
        code = ctypes.get_last_error()
        if code != 232 or time.monotonic() >= deadline:
            raise WindowsIsolationError("PIPE_READ", code)
        time.sleep(0.05)
    if not size.value:
        raise WindowsIsolationError("PIPE_EMPTY_MESSAGE")
    return buffer.raw[: size.value]


def _write_message(handle, value: bytes) -> None:
    if not isinstance(value, bytes) or not 0 < len(value) < MAX_MESSAGE:
        raise WindowsIsolationError("PIPE_MESSAGE_SIZE")
    written = ctypes.c_uint32()
    _check(
        _function(
            _dll("kernel32"),
            "WriteFile",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p],
        )(handle, value, len(value), ctypes.byref(written), None),
        "PIPE_WRITE",
    )
    if written.value != len(value):
        raise WindowsIsolationError("PIPE_PARTIAL_WRITE")


def receive_provisioning(service_name: str, persist, *, timeout: float = 25) -> None:
    identity = require_service_identity(service_name)
    kernel = _dll("kernel32")
    # FILE_FLAG_FIRST_PIPE_INSTANCE prevents an earlier pipe from being silently reused.
    with security_descriptor(acl_sddl(writers=(identity["user_sid"],))) as descriptor:
        attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, False)
        handle = _function(
            kernel,
            "CreateNamedPipeW",
            [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ],
            ctypes.c_void_p,
        )(
            pipe_name(service_name),
            3 | 0x80000,
            4 | 2 | 1 | 8,
            1,
            MAX_MESSAGE,
            MAX_MESSAGE,
            1000,
            ctypes.byref(attributes),
        )
    if handle == ctypes.c_void_p(-1).value:
        raise WindowsIsolationError("PIPE_CREATE", ctypes.get_last_error())
    try:
        deadline = time.monotonic() + timeout
        connect = _function(kernel, "ConnectNamedPipe", [ctypes.c_void_p, ctypes.c_void_p])
        while not connect(handle, None):
            code = ctypes.get_last_error()
            if code == 535:  # ERROR_PIPE_CONNECTED
                break
            if code not in (536, 232) or time.monotonic() >= deadline:
                raise WindowsIsolationError("PIPE_CONNECT", code)
            time.sleep(0.05)
        mode = ctypes.c_uint32(2 | 1)
        _check(
            _function(
                kernel,
                "SetNamedPipeHandleState",
                [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
            )(handle, ctypes.byref(mode), None, None),
            "PIPE_MODE",
        )
        sender = ctypes.c_uint32()
        _check(
            _function(kernel, "GetNamedPipeClientProcessId", [ctypes.c_void_p, ctypes.c_void_p])(
                handle, ctypes.byref(sender)
            ),
            "PIPE_CLIENT_ID",
        )
        # The protected pipe DACL admits only admins/SYSTEM and this single service identity.
        # A foreign service cannot connect. Querying an admin process token would require
        # privileges deliberately absent from this service's token.
        persist(_read_message(handle))
        _write_message(handle, b"SEALED")
        if _read_message(handle) != b"ACCEPTED":
            raise WindowsIsolationError("PIPE_SEAL_RECEIPT_ACK_MISMATCH")
    finally:
        _function(kernel, "DisconnectNamedPipe", [ctypes.c_void_p])(handle)
        close_handle(handle)


def send_provisioning(
    service_name: str, expected_pid: int, value: bytes, *, timeout: float = 25
) -> None:
    require_admin()
    kernel = _dll("kernel32")
    deadline = time.monotonic() + timeout
    handle = None
    while time.monotonic() < deadline:
        handle = _function(
            kernel,
            "CreateFileW",
            [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ],
            ctypes.c_void_p,
        )(pipe_name(service_name), 0xC0000000, 0, None, 3, 0, None)
        if handle != ctypes.c_void_p(-1).value:
            break
        if ctypes.get_last_error() not in (2, 231):
            raise WindowsIsolationError("PIPE_OPEN", ctypes.get_last_error())
        time.sleep(0.05)
    else:
        raise WindowsIsolationError("PIPE_OPEN_TIMEOUT")
    try:
        server = ctypes.c_uint32()
        _check(
            _function(kernel, "GetNamedPipeServerProcessId", [ctypes.c_void_p, ctypes.c_void_p])(
                handle, ctypes.byref(server)
            ),
            "PIPE_SERVER_ID",
        )
        if server.value != expected_pid or token_identity(server.value)["user_sid"] != account_sid(
            "NT SERVICE\\" + service_name
        ):
            raise WindowsIsolationError("PIPE_SERVER_IDENTITY_MISMATCH")
        mode = ctypes.c_uint32(2 | 1)
        _check(
            _function(
                kernel,
                "SetNamedPipeHandleState",
                [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
            )(handle, ctypes.byref(mode), None, None),
            "PIPE_MODE",
        )
        _write_message(handle, value)
        if _read_message(handle) != b"SEALED":
            raise WindowsIsolationError("PIPE_SEAL_ACK_MISMATCH")
        _write_message(handle, b"ACCEPTED")
    finally:
        close_handle(handle)
