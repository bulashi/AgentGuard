"""Actual opt-in SCM probe. Only this run's fresh services can be removed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scripts.native_windows_api import (
    SERVICE_START_PENDING,
    SERVICE_STOPPED,
    Scm,
    WindowsIsolationError,
    account_sid,
    assert_private_acl,
    no_links,
    require_admin,
    set_acl,
)
from scripts.native_windows_dpapi import atomic_private_write, parse_document
from scripts.native_windows_isolation import (
    PROBE_ROLES,
    provision_identity,
    service_command,
    service_names,
)

MODULES = (
    "native_windows_api.py",
    "native_windows_dpapi.py",
    "native_windows_isolation.py",
    "native_windows_profiles.py",
    "native_windows_service.py",
)


def file_hash(path: Path) -> str:
    no_links(path)
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main_boundary(project_root: Path) -> dict:
    paths = [
        project_root / ".native" / name
        for name in (
            "config.json",
            "processes.json",
            "internal-service-keys.dpapi",
            "operator-session.dpapi",
            "model-configurations.json",
        )
    ]
    keys = project_root / ".native/keys/private"
    if keys.is_dir():
        paths.extend(keys.glob("*.private"))
    return {
        str(path.relative_to(project_root)): {
            "sha256": file_hash(path),
            "size": path.stat().st_size,
        }
        for path in paths
        if path.is_file()
    }


def _copy_verified(source: Path, destination: Path, hashes: dict, *, base: Path) -> None:
    no_links(source)
    if not source.is_file() or destination.exists():
        raise WindowsIsolationError("PROBE_COPY_REQUIRES_FRESH_FILE")
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        shutil.copyfileobj(input_file, output_file)
    expected, actual = file_hash(source), file_hash(destination)
    if expected != actual:
        raise WindowsIsolationError("PROBE_RUNTIME_COPY_HASH_MISMATCH")
    hashes[str(destination.relative_to(base))] = expected


def _copy_tree(source: Path, destination: Path, hashes: dict, *, base: Path) -> None:
    no_links(source)
    destination.mkdir()
    for entry in sorted(source.iterdir()):
        if entry.name in {"__pycache__", "site-packages", "test", "tests", "ensurepip", "idlelib"}:
            continue
        no_links(entry)
        if entry.is_dir():
            _copy_tree(entry, destination / entry.name, hashes, base=base)
        elif entry.is_file():
            _copy_verified(entry, destination / entry.name, hashes, base=base)
        else:
            raise WindowsIsolationError("PROBE_RUNTIME_FILE_TYPE")


def stage_python(root: Path, project_root: Path) -> tuple[Path, Path, dict]:
    """Copy the already installed CPython bytes; never change its source ACL or install packages."""
    base = no_links(Path(sys.base_prefix))
    target, code = root / "python", root / "code"
    target.mkdir()
    (code / "scripts").mkdir(parents=True)
    hashes = {}
    for name in (
        "python.exe",
        "python3.dll",
        "python312.dll",
        "python313.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "LICENSE.txt",
    ):
        source = base / name
        if source.is_file():
            _copy_verified(source, target / name, hashes, base=root)
    for name in ("Lib", "DLLs"):
        source = base / name
        if source.is_dir():
            _copy_tree(source, target / name, hashes, base=root)
    for name in MODULES:
        _copy_verified(project_root / "scripts" / name, code / "scripts" / name, hashes, base=root)
    if not (target / "python.exe").is_file():
        raise WindowsIsolationError("PROBE_INSTALLED_PYTHON_MISSING")
    return target / "python.exe", code / "scripts/native_windows_service.py", hashes


def _wait_stopped(scm: Scm, record: dict, *, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = scm.status(record["service_name"])
        if status["state"] == SERVICE_STOPPED:
            return status
        time.sleep(0.1)
    raise WindowsIsolationError("PROBE_SERVICE_TIMEOUT")


def _confirm_deleted(scm: Scm, name: str, *, timeout: float = 10) -> None:
    # DeleteService is asynchronous until the process and outstanding handles have closed.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            scm.configuration(name)
        except WindowsIsolationError as exc:
            if exc.winerror == 1060:
                return
            if exc.winerror != 1072:
                raise
        time.sleep(0.1)
    raise WindowsIsolationError("PROBE_SERVICE_DELETE_NOT_CONFIRMED")


def run_probe(project_root: Path, *, verify_requested: bool) -> dict:
    if not verify_requested:
        raise WindowsIsolationError("EXPLICIT_SCOPED_SCM_PROBE_REQUIRED")
    identity = require_admin()
    project_root = no_links(project_root)
    before = main_boundary(project_root)
    deployment_id = uuid.uuid4().hex[:16]
    root = project_root / (".native-windows-probe-" + deployment_id)
    if root.exists():
        raise WindowsIsolationError("FRESH_PROBE_ROOT_REQUIRED")
    root.mkdir()
    set_acl(root)
    receipt = {
        "schema_version": 1,
        "run_id": deployment_id,
        "root": str(root),
        "started_at": datetime.now(UTC).isoformat(),
        "result": "FAIL",
        "installer_identity": identity,
        "boundary": "virtual_service_accounts_admin_system_trusted",
        "main_runtime_changed": None,
        "external_custody_proven": False,
        "clean_other_pc_proven": False,
        "services": [],
        "cleanup": [],
    }
    created = []
    names = service_names(deployment_id, PROBE_ROLES, probe=True)
    try:
        python, host, hashes = stage_python(root, project_root)
        atomic_private_write(
            root / "runtime-copy-sha256.json",
            json.dumps(hashes, indent=2).encode("ascii"),
            expected=None,
        )
        receipt["python_staging"] = {
            "version": sys.version.split()[0],
            "source_base": sys.base_prefix,
            "files": len(hashes),
            "all_copies_sha256_equal": True,
        }
        manifest = {
            "schema_version": 1,
            "kind": "probe",
            "deployment_id": deployment_id,
            "root": str(root),
            "project_root": str(project_root),
            "python": str(python),
            "host": str(host),
            "services": {},
            "probe_checks": {},
            "probe_import_root": str(project_root / ".venv/Lib/site-packages"),
            "probe_model_roles": dict(
                zip(PROBE_ROLES, ("coordinator-agent", "refund-agent"), strict=True)
            ),
            "legacy_runtime_file": str(Path(sys.base_prefix) / "python312.dll"),
            "legacy_private_files": {
                name: str(project_root / ".native" / name)
                for name in (
                    "config.json",
                    "model-configurations.json",
                    "internal-service-keys.dpapi",
                    "operator-session.dpapi",
                )
                if (project_root / ".native" / name).is_file()
            }
            | {
                "signing_key:" + path.stem: str(path)
                for path in sorted((project_root / ".native/keys/private").glob("*.private"))
            },
        }
        with Scm(create=True) as scm:
            for role in PROBE_ROLES:
                command = service_command(python, host, root, names[role])
                scm.create(names[role], command)
                # Register ownership immediately after CreateService, before any other IO.
                created.append({"service_name": names[role], "command": command})
                sid = account_sid("NT SERVICE\\" + names[role])
                service_root = root / "services" / role
                service_root.mkdir(parents=True)
                set_acl(service_root, readers=(sid,))
                private, state = service_root / "private", service_root / "state"
                for path in (private, state):
                    path.mkdir()
                    set_acl(path, writers=(sid,))
                for relative in (
                    "tmp",
                    "home",
                    "home/AppData",
                    "home/AppData/Roaming",
                    "home/AppData/Local",
                ):
                    (state / relative).mkdir()
                    set_acl(state / relative, writers=(sid,))
                principal = root / "principals" / role
                principal.mkdir(parents=True)
                set_acl(principal, readers=(sid,))
                token = os.urandom(32)  # Synthetic probe bytes, never application key material.
                own_file = principal / "probe.private"
                atomic_private_write(own_file, token, expected=None, readers=(sid,))
                record = {
                    "role": role,
                    "service_name": names[role],
                    "sid": sid,
                    "command": command,
                    "private_root": str(private),
                    "state_root": str(state),
                    "config_path": str(private / "config.dpapi"),
                }
                manifest["services"][role] = record
                manifest["probe_checks"][role] = {
                    "own_file": str(own_file),
                    "own_sha256": hashlib.sha256(token).hexdigest(),
                }
            sids = tuple(record["sid"] for record in manifest["services"].values())
            for path in (
                root,
                root / "services",
                root / "principals",
                root / "python",
                root / "code",
            ):
                set_acl(path, readers=sids)
            # Seal every staged child for the two scoped readers.
            for directory in (root / "python", root / "code"):
                for path in directory.rglob("*"):
                    set_acl(path, readers=sids)
            for role in PROBE_ROLES:
                foreign = PROBE_ROLES[1] if role == PROBE_ROLES[0] else PROBE_ROLES[0]
                manifest["probe_checks"][role].update(
                    {
                        "foreign_file": manifest["probe_checks"][foreign]["own_file"],
                        "foreign_service": names[foreign],
                    }
                )
            atomic_private_write(
                root / "manifest.json",
                json.dumps(manifest).encode("ascii"),
                expected=None,
                readers=sids,
            )
            for role in PROBE_ROLES:
                test_secret = uuid.uuid4().hex
                private = Path(manifest["services"][role]["private_root"])
                provision_identity(
                    scm,
                    manifest["services"][role],
                    {
                        "schema_version": 1,
                        "role": role,
                        "test_secret": test_secret,
                        "environment": {
                            "AGENTGUARD_MODEL_CONFIGURATIONS_PATH": str(
                                private / "model-configurations.json"
                            ),
                        },
                        "model_snapshot": {
                            "schema_version": 1,
                            "source_sha256": hashlib.sha256(b"synthetic-SCM-probe").hexdigest(),
                            "default_id": "primary",
                            "profiles": {
                                "primary": {
                                    "name": "Scoped SCM probe",
                                    "provider_id": "probe",
                                    "base_url": "https://scm-probe.invalid",
                                    "api_mode": "chat_completions",
                                    "model": "probe-deterministic",
                                    "timeout_seconds": 5,
                                    "enabled": True,
                                    "api_key": "synthetic-" + test_secret,
                                },
                            },
                        },
                    },
                )
            for role in PROBE_ROLES:
                foreign = PROBE_ROLES[1] if role == PROBE_ROLES[0] else PROBE_ROLES[0]
                record = manifest["services"][role]
                # Readable foreign ciphertext tests DPAPI independently of the file ACL.
                foreign_config = Path(manifest["services"][foreign]["config_path"]).read_bytes()
                atomic_private_write(
                    Path(record["private_root"]) / "foreign.dpapi",
                    foreign_config,
                    expected=None,
                    writers=(record["sid"],),
                )
                foreign_models = (
                    Path(manifest["services"][foreign]["private_root"])
                    / "model-configurations.json"
                ).read_bytes()
                atomic_private_write(
                    Path(record["private_root"]) / "foreign-model-configurations.json",
                    foreign_models,
                    expected=None,
                    writers=(record["sid"],),
                )
                assert_private_acl(Path(record["config_path"]), writers=(record["sid"],))
                scm.start(record["service_name"], record["command"])
                status = _wait_stopped(scm, record)
                evidence = sorted(Path(record["state_root"]).glob("probe-*.json"))
                failure = sorted(Path(record["state_root"]).glob("failure-*.json"))
                if len(evidence) != 1:
                    if failure:
                        receipt["services"].append(parse_document(failure[-1].read_bytes()))
                    raise WindowsIsolationError(
                        "PROBE_SERVICE_RECEIPT_MISSING", status["service_exit"]
                    )
                value = parse_document(evidence[0].read_bytes())
                value["scm_configuration"] = scm.configuration(record["service_name"])
                value["scm_control_acl"] = scm.control_acl(record["service_name"])
                value["receipt_path"] = str(evidence[0])
                value["private_key_acl"] = assert_private_acl(
                    Path(manifest["probe_checks"][role]["own_file"]), readers=(record["sid"],)
                )
                receipt["services"].append(value)
                if value["result"] != "PASS" or status["service_exit"] or status["win32_exit"]:
                    raise WindowsIsolationError("PROBE_ASSERTION_FAILED", status["service_exit"])
        receipt["result"] = "PASS"
    except WindowsIsolationError as exc:
        receipt["failure"] = {"reason": exc.code, "winerror": exc.winerror}
    except Exception as exc:
        receipt["failure"] = {"error_type": type(exc).__name__}
    finally:
        with Scm() as scm:
            for owned in reversed(created):
                item = {
                    "service_name": owned["service_name"],
                    "ownership_checked": False,
                    "deleted": False,
                }
                try:
                    scm.assert_owned(owned["service_name"], owned["command"])
                    item["ownership_checked"] = True
                    status = scm.status(owned["service_name"])
                    if status["state"] != SERVICE_STOPPED:
                        if status["state"] == SERVICE_START_PENDING:
                            # Provisioning is bounded; START_PENDING accepts no stop control.
                            _wait_stopped(scm, owned, timeout=35)
                        else:
                            scm.stop(owned["service_name"], owned["command"])
                    scm.delete_ephemeral(owned["service_name"], owned["command"])
                    _confirm_deleted(scm, owned["service_name"])
                    item["deleted"] = True
                except WindowsIsolationError as exc:
                    item["reason"], item["winerror"] = exc.code, exc.winerror
                    receipt["result"] = "FAIL"
                receipt["cleanup"].append(item)
        after = main_boundary(project_root)
        receipt["main_runtime_changed"] = before != after
        receipt["main_boundary_before"] = before
        receipt["main_boundary_after"] = after
        if receipt["main_runtime_changed"]:
            receipt["result"] = "FAIL"
        receipt["finished_at"] = datetime.now(UTC).isoformat()
        receipt_path = root / "probe-receipt.json"
        atomic_private_write(
            receipt_path,
            json.dumps(receipt, ensure_ascii=True, indent=2).encode("ascii"),
            expected=None,
        )
        receipt["receipt_path"] = str(receipt_path)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fresh scoped Windows virtual service isolation probe"
    )
    parser.add_argument("--verify-isolation", action="store_true")
    args = parser.parse_args()
    try:
        value = run_probe(
            Path(__file__).resolve().parents[1], verify_requested=args.verify_isolation
        )
        print(
            json.dumps(
                {
                    "result": value["result"],
                    "receipt": value["receipt_path"],
                    "services": len(value["services"]),
                    "main_runtime_changed": value["main_runtime_changed"],
                    "cleanup_pass": all(item["deleted"] for item in value["cleanup"]),
                    "failure": value.get("failure"),
                },
                ensure_ascii=True,
            )
        )
        return 0 if value["result"] == "PASS" else 2
    except WindowsIsolationError as exc:
        print(json.dumps({"result": "FAIL", "reason": exc.code, "winerror": exc.winerror}))
        return 2
    except Exception as exc:
        print(json.dumps({"result": "FAIL", "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
