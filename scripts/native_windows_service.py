"""Standard-library SCM service entry point. SCM command lines contain no credentials."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import logging
import os
import sys
import threading
import uuid
from pathlib import Path
from typing import ClassVar

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.native_windows_api import (
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STATUS,
    SERVICE_STOP_PENDING,
    SERVICE_STOPPED,
    SERVICE_WIN32_OWN_PROCESS,
    WindowsIsolationError,
    assert_private_acl,
    no_links,
    probe_read_file,
    receive_provisioning,
    require_service_identity,
    require_windows,
)
from scripts.native_windows_dpapi import UserDpapi, atomic_private_write, parse_document
from scripts.native_windows_isolation import (
    child_environment,
    load_config,
    read_manifest,
    seal_config,
    validate_service_environment,
)


def receipt(record: dict, value: dict, *, label: str) -> Path:
    path = Path(record["state_root"]) / (label + "-" + uuid.uuid4().hex + ".json")
    atomic_private_write(
        path,
        json.dumps(value, ensure_ascii=True, indent=2).encode("ascii"),
        expected=None,
        writers=(record["sid"],),
    )
    return path


def block_probe_network() -> dict[str, int]:
    import socket

    attempts = {"count": 0}

    def denied(*_args, **_kwargs):
        attempts["count"] += 1
        raise WindowsIsolationError("PROBE_NETWORK_FORBIDDEN")

    # A probe process never serves an application. Reject DNS and socket traffic before
    # importing dependency/provider modules, not just when making its test assertions.
    socket.getaddrinfo = socket.gethostbyname = socket.gethostbyname_ex = denied
    socket.socket.connect = socket.socket.connect_ex = socket.socket.sendto = denied
    return attempts


def probe_reads(manifest: dict, record: dict, config: dict, network_attempts: dict) -> dict:
    root = Path(manifest["root"])
    identity = require_service_identity(record["service_name"])
    specification = manifest["probe_checks"][record["role"]]
    own = no_links(Path(specification["own_file"]), within=root)
    # Metadata traversal into the foreign private tree is itself denied; attempt the actual read.
    foreign = Path(specification["foreign_file"]).absolute()
    if not foreign.is_relative_to(root):
        raise WindowsIsolationError("PROBE_FOREIGN_FILE_OUTSIDE_ROOT")
    own_read = hashlib.sha256(probe_read_file(own)).hexdigest() == specification["own_sha256"]
    try:
        probe_read_file(foreign)
        foreign_denied, foreign_error = False, 0
    except WindowsIsolationError as exc:
        foreign_error = exc.winerror
        foreign_denied = foreign_error == 5
    other = parse_document((Path(record["private_root"]) / "foreign.dpapi").read_bytes())
    try:
        UserDpapi().unprotect(
            other["protected"], purpose="service:" + specification["foreign_service"]
        )
        dpapi_foreign_denied, dpapi_error = False, 0
    except WindowsIsolationError as exc:
        dpapi_foreign_denied, dpapi_error = exc.code == "DPAPI_UNPROTECT", exc.winerror
    imports = {}
    import_root = manifest.get("probe_import_root")
    if import_root:
        sys.path.insert(0, str(no_links(Path(import_root))))
        for package in ("uvicorn", "fastapi", "psycopg", "psutil", "gmssl"):
            try:
                importlib.import_module(package)
                imports[package] = "PASS"
            except Exception as exc:
                imports[package] = type(exc).__name__
    legacy_runtime = manifest.get("legacy_runtime_file")
    legacy_denied = None
    if legacy_runtime:
        try:
            probe_read_file(Path(legacy_runtime), maximum=1)
            legacy_denied = False
        except WindowsIsolationError as exc:
            legacy_denied = exc.winerror == 5
    legacy_private_reads = {}
    for label, path in manifest.get("legacy_private_files", {}).items():
        try:
            probe_read_file(Path(path), maximum=1)
            legacy_private_reads[label] = False
        except WindowsIsolationError as exc:
            legacy_private_reads[label] = exc.winerror == 5
    correct_config = config.get("role") == record["role"] and bool(config.get("test_secret"))
    from scripts.native_windows_profiles import activate_model_snapshot

    activate_model_snapshot(
        record | {"role": manifest["probe_model_roles"][record["role"]]}, config
    )
    from backend.config.model_profiles import (
        ModelConfigurationError,
        ModelProfileStore,
        WindowsCredentialCipher,
    )

    model_path = Path(record["private_root"]) / "model-configurations.json"
    models = ModelProfileStore(model_path)
    own_profile = models.configured()
    own_provider = (
        own_profile is not None
        and own_profile[0]["id"] == "primary"
        and own_profile[1] == config["model_snapshot"]["profiles"]["primary"]["api_key"]
    )
    foreign_models = parse_document(
        (Path(record["private_root"]) / "foreign-model-configurations.json").read_bytes()
    )
    try:
        WindowsCredentialCipher().decrypt(foreign_models["items"]["primary"]["credential"])
        foreign_provider_denied = False
    except ModelConfigurationError as exc:
        foreign_provider_denied = exc.reason_code == "MODEL_CREDENTIAL_UNAVAILABLE"
    try:
        models.select("primary")
        immutable_models = False
    except ModelConfigurationError as exc:
        immutable_models = (
            exc.reason_code == "MODEL_SNAPSHOT_REPROVISION_REQUIRED" and exc.status_code == 409
        )
    scoped_home = os.environ.get("USERPROFILE") == str(
        Path(record["state_root"]) / "home"
    ) and os.environ.get("TEMP") == str(Path(record["state_root"]) / "tmp")
    return {
        "schema_version": 1,
        "role": record["role"],
        "service_name": record["service_name"],
        "pid": os.getpid(),
        "user_sid": identity["user_sid"],
        "admin": identity["elevated_admin"],
        "system": identity["system"],
        "own_read_succeeded": own_read,
        "foreign_read_denied": foreign_denied,
        "foreign_read_winerror": foreign_error,
        "own_dpapi_config_read": correct_config,
        "foreign_dpapi_decrypt_denied": dpapi_foreign_denied,
        "dpapi_winerror": dpapi_error,
        "runtime_imports": imports,
        "legacy_python_base_read_denied": legacy_denied,
        "legacy_private_read_denied": legacy_private_reads,
        "own_provider_secret_available": own_provider,
        "foreign_provider_dpapi_denied": foreign_provider_denied,
        "model_snapshot_mutation_rejected": immutable_models,
        "service_home_temp_scoped": scoped_home,
        "provider_network_calls": network_attempts["count"],
        "result": "PASS"
        if own_read
        and foreign_denied
        and correct_config
        and dpapi_foreign_denied
        and own_provider
        and foreign_provider_denied
        and immutable_models
        and scoped_home
        and legacy_denied is True
        and bool(legacy_private_reads)
        and all(legacy_private_reads.values())
        and bool(imports)
        and network_attempts["count"] == 0
        and all(value == "PASS" for value in imports.values())
        else "FAIL",
    }


def run_application(
    manifest: dict, record: dict, config: dict, stopped: threading.Event, report_running
) -> None:
    role, root = record["role"], Path(manifest["root"])
    environment = config.get("environment")
    validate_service_environment(role, environment, root)
    state_root = Path(record["state_root"])
    assert_private_acl(state_root, writers=(record["sid"],))
    clean_values = child_environment(
        environment, state_root, project_root=Path(manifest["project_root"])
    )
    os.environ.clear()
    os.environ.update(clean_values)
    os.chdir(manifest["project_root"])
    sys.path.insert(0, manifest["project_root"])
    from scripts.native_windows_profiles import activate_model_snapshot

    activate_model_snapshot(record, config)
    # Logging an arbitrary application exception can include DSNs; receipts use fixed reason codes.
    logging.disable(logging.CRITICAL)
    receipt(
        record,
        {
            "schema_version": 1,
            "role": role,
            "pid": os.getpid(),
            "user_sid": record["sid"],
            "private_configuration_ready": True,
            "result": "STARTING",
        },
        label="startup",
    )
    if role == "web-ui":
        from scripts.native_web import NativeWebServer

        with NativeWebServer(
            Path(manifest["project_root"]) / "frontend/dist", record["port"]
        ) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            report_running()
            stopped.wait()
            server.shutdown()
            worker.join(timeout=10)
        return
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(
            record["module"],
            host="127.0.0.1",
            port=record["port"],
            log_config=None,
            access_log=False,
            workers=1,
            timeout_graceful_shutdown=10,
        )
    )

    def stop_when_requested():
        stopped.wait()
        server.should_exit = True

    threading.Thread(target=stop_when_requested, daemon=True).start()
    report_running()
    server.run()
    if not stopped.is_set():
        raise WindowsIsolationError("SCM_APPLICATION_EXITED_UNEXPECTEDLY")


def dispatch(root: Path, service_name: str) -> int:
    require_windows()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    stopped = threading.Event()
    exit_result = {"value": 0}
    status_handle = ctypes.c_void_p()
    status_lock = threading.Lock()
    main_type = ctypes.WINFUNCTYPE(None, ctypes.c_uint32, ctypes.POINTER(ctypes.c_wchar_p))
    handler_type = ctypes.WINFUNCTYPE(
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p
    )
    register = advapi.RegisterServiceCtrlHandlerExW
    register.argtypes = [ctypes.c_wchar_p, handler_type, ctypes.c_void_p]
    register.restype = ctypes.c_void_p
    set_status = advapi.SetServiceStatus
    set_status.argtypes, set_status.restype = (
        [ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS)],
        ctypes.c_int,
    )

    def report(state: int, error: int = 0):
        with status_lock:
            value = SERVICE_STATUS(
                SERVICE_WIN32_OWN_PROCESS,
                state,
                1 | 4 if state == SERVICE_RUNNING else 0,
                1066 if error else 0,
                error,
                1 if state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING) else 0,
                30_000 if state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING) else 0,
            )
            if not set_status(status_handle, ctypes.byref(value)):
                raise WindowsIsolationError("SERVICE_REPORT_STATUS", ctypes.get_last_error())

    @handler_type
    def handler(control, _event, _data, _context):
        if control in (1, 5):
            report(SERVICE_STOP_PENDING)
            stopped.set()
        return 0

    @main_type
    def service_main(count, arguments):
        record = None
        status_handle.value = register(service_name, handler, None)
        if not status_handle.value:
            exit_result["value"] = 2
            return
        report(SERVICE_START_PENDING)
        try:
            # A fixed-path, secret-free boot receipt also covers failures before manifest loading.
            role = service_name.rsplit("_", 1)[-1]
            from scripts.native_windows_api import account_sid

            record = {
                "role": role,
                "service_name": service_name,
                "sid": account_sid("NT SERVICE\\" + service_name),
                "state_root": str(root / "services" / role / "state"),
            }
            require_service_identity(service_name)
            manifest = read_manifest(root, current_role=role)
            matches = [
                value
                for value in manifest["services"].values()
                if value["service_name"] == service_name
            ]
            if len(matches) != 1:
                raise WindowsIsolationError("SERVICE_NOT_IN_OWNED_MANIFEST")
            record = matches[0]
            assert_private_acl(Path(record["private_root"]), writers=(record["sid"],))
            clean_values = child_environment(
                {}, Path(record["state_root"]), project_root=Path(manifest["project_root"])
            )
            os.environ.clear()
            os.environ.update(clean_values)
            network_attempts = None
            if manifest["kind"] == "probe":
                # Only the probe imports the existing read-only dependency tree; production
                # requires a separately staged, trusted runtime before its installer proceeds.
                sys.path.append(manifest["project_root"])
                sys.path.append(manifest["probe_import_root"])
                network_attempts = block_probe_network()
            operation = arguments[1] if count == 2 else "run" if count == 1 else "invalid"
            if operation == "provision":
                receive_provisioning(
                    service_name, lambda content: seal_config(manifest, record, content)
                )
                receipt(
                    record,
                    {
                        "schema_version": 1,
                        "role": record["role"],
                        "pid": os.getpid(),
                        "user_sid": record["sid"],
                        "result": "SEALED",
                        "probe_network_attempts": (
                            network_attempts["count"] if network_attempts is not None else None
                        ),
                    },
                    label="provision",
                )
            elif operation == "run":
                config = load_config(record)
                if manifest["kind"] == "probe":
                    report(SERVICE_RUNNING)
                    value = probe_reads(manifest, record, config, network_attempts)
                    receipt(record, value, label="probe")
                    if value["result"] != "PASS":
                        raise WindowsIsolationError("PROBE_ASSERTION_FAILED")
                else:
                    run_application(
                        manifest, record, config, stopped, lambda: report(SERVICE_RUNNING)
                    )
            else:
                raise WindowsIsolationError("SERVICE_START_ARGUMENT_REJECTED")
        except BaseException as exc:
            exit_result["value"] = 2
            if record is not None:
                try:
                    value = {
                        "schema_version": 1,
                        "role": record["role"],
                        "result": "FAIL",
                        "error_type": type(exc).__name__,
                    }
                    if isinstance(exc, WindowsIsolationError):
                        value.update({"reason": exc.code, "winerror": exc.winerror})
                    receipt(record, value, label="failure")
                except BaseException:
                    pass
        finally:
            report(SERVICE_STOPPED, 1 if exit_result["value"] else 0)

    class SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_: ClassVar = [("name", ctypes.c_wchar_p), ("main", main_type)]

    table = (SERVICE_TABLE_ENTRY * 2)(
        SERVICE_TABLE_ENTRY(service_name, service_main), SERVICE_TABLE_ENTRY(None, main_type())
    )
    start = advapi.StartServiceCtrlDispatcherW
    start.argtypes, start.restype = [ctypes.POINTER(SERVICE_TABLE_ENTRY)], ctypes.c_int
    if not start(table):
        raise WindowsIsolationError("SERVICE_DISPATCHER_CONNECT", ctypes.get_last_error())
    return exit_result["value"]


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentGuard SCM-only Python service host")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--service-name", required=True)
    args = parser.parse_args()
    # SCM has no interactive console. Discard arbitrary library output, including tracebacks.
    with open(os.devnull, "w", encoding="utf-8") as output:
        sys.stdout, sys.stderr = output, output
        try:
            return dispatch(no_links(args.root), args.service_name)
        except BaseException:
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
