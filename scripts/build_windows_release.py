from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tomllib
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import ClassVar

from scripts.native_web import is_link

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "release-manifest.json"
ROOT_FILES = {
    "README.md",
    "README.en.md",
    "pyproject.toml",
    "requirements.lock",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    ".gitignore",
    "启动AgentGuard.cmd",
    "配置智能体.cmd",
    "停止本机.cmd",
}
DOC_FILES = {
    "第三方组件与许可说明.md",
    "Windows本机运行.md",
    "一键启动与评委使用说明.md",
    "项目说明书.md",
    "注入编辑与证据口径修复-20261010.md",
    "业务流程与安全功能说明.md",
    "智能体提示词与业务资料.md",
    "需求追踪矩阵.md",
    "安全分析.md",
    "威胁模型.md",
    "复现说明.md",
    "创新边界.md",
    "交付物清单.md",
    "基准评测协议.md",
    "本机云端基准评测说明.md",
    "形式化一致性模型说明.md",
    "独立主体共同授权增量契约.md",
    "独立审批人离线签名说明.md",
    "独立审计锚点保管与核验.md",
    "共同审批网页操作说明.md",
    "共同授权证据离线核验说明.md",
    "共同授权主链验收方案.md",
    "逐事件检查点绑定扩展说明.md",
    "本轮修复计划与验收清单.md",
    "本轮完整验收报告.md",
    "阶段验收.md",
    "本轮清理记录.md",
    "演示说明.md",
    "分层工作台使用说明.md",
    "收口实施与验收清单.md",
    "收口验收报告.md",
    "源码使用与第三方许可说明.md",
    "派发前撤销与控制台使用说明.md",
    "本机撤销功能验收报告.md",
    "评审修复与赛题覆盖报告-20261009.md",
    "评测与交付同步报告-20261009.md",
    "RUNNING.zh-CN.md",
    "RUNNING.en.md",
    "ARCHITECTURE.md",
}
SOURCE_TREES = {
    "backend": {".py"},
    "scripts": {".py", ".ps1", ".vbs", ".cmd", ".json", ".ts"},
    "protocol": {".json", ".yaml", ".yml"},
    "database": {".sql"},
    "attacks": {".json", ".py"},
    "frontend/src": {".ts", ".tsx", ".js", ".css", ".svg", ".png", ".jpg", ".webp"},
    "frontend/e2e": {".ts", ".tsx", ".js"},
    "frontend/public": {".svg", ".png", ".jpg", ".webp", ".ico", ".html"},
    "frontend/dist": {
        ".html",
        ".js",
        ".css",
        ".svg",
        ".png",
        ".jpg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".wasm",
        ".json",
    },
    "docs/assets": {".png"},
    "third_party_licenses": {".txt", ".md", ".json", ".license"},
}
FRONTEND_FILES = {
    "index.html",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "tsconfig.app.json",
    "tsconfig.node.json",
    "vite.config.ts",
    "eslint.config.js",
}
REQUIRED_FILES = {
    "README.md",
    "README.en.md",
    "requirements.lock",
    "pyproject.toml",
    "启动AgentGuard.cmd",
    "配置智能体.cmd",
    "scripts/native_runtime.py",
    "scripts/native_config.py",
    "scripts/native_database.py",
    "scripts/native_web.py",
    "scripts/start-cloud-native.ps1",
    "scripts/agentguard-desktop.ps1",
    "scripts/agentguard-desktop.vbs",
    "scripts/native-dependencies.lock.json",
    "scripts/generate_dev_keys.py",
    "scripts/register_dev_keys.py",
    "scripts/seed_demo.py",
    "scripts/migrate.py",
    "protocol/manifest.json",
    "protocol/openapi.yaml",
    "database/migrations/main/0001_initial.sql",
    "database/migrations/audit/0001_initial.sql",
    "frontend/dist/index.html",
    "docs/第三方组件与许可说明.md",
    "docs/RUNNING.zh-CN.md",
    "docs/RUNNING.en.md",
    "docs/ARCHITECTURE.md",
    "docs/assets/architecture.zh-CN.png",
    "docs/assets/execution-flow.zh-CN.png",
    "docs/assets/audit-evidence.zh-CN.png",
    "docs/assets/deployment.zh-CN.png",
}
FORBIDDEN_PARTS = {
    "node_modules",
    "__pycache__",
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    ".cache",
    "evidence",
    "artifacts",
    ".playwright-cli",
    "output",
    "keys",
    "secrets",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".private", ".key", ".pem", ".dpapi", ".env", ".log"}
KEY_PATTERN = re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")


class ReleaseError(RuntimeError):
    pass


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def allowed_source(relative: PurePosixPath) -> bool:
    return (
        not any(part.lower() in FORBIDDEN_PARTS for part in relative.parts)
        and (
            relative.suffix.lower() not in FORBIDDEN_SUFFIXES
            or str(relative) == ".runtime/python/Lib/site-packages/certifi/cacert.pem"
        )
        and all(part not in {".", ".."} for part in relative.parts)
    )


def checked_file(path: Path, root: Path) -> Path:
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ReleaseError("a release input is missing or escapes its approved root")
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current /= part
        if is_link(current):
            raise ReleaseError(f"linked release input is not allowed: {relative.as_posix()}")
    return path


def project_files(root: Path) -> dict[str, Path]:
    selected = {}
    for name in ROOT_FILES:
        if (root / name).is_file():
            selected[name] = checked_file(root / name, root)
    for tree, suffixes in SOURCE_TREES.items():
        for path in (root / tree).rglob("*"):
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if path.is_file() and allowed_source(relative) and path.suffix.lower() in suffixes:
                selected[str(relative)] = checked_file(path, root)
    for name in FRONTEND_FILES:
        path = root / "frontend" / name
        if path.is_file():
            selected[f"frontend/{name}"] = checked_file(path, root)
    for name in DOC_FILES:
        path = root / "docs" / name
        if path.is_file():
            selected[f"docs/{name}"] = checked_file(path, root)
    missing = sorted(REQUIRED_FILES - selected.keys())
    if missing:
        raise ReleaseError("missing required release inputs: " + ", ".join(missing))
    if not any(name.startswith("backend/tests/") for name in selected):
        raise ReleaseError("the public test sources are missing")
    return dict(sorted(selected.items()))


def runtime_distributions(root: Path) -> list[importlib.metadata.Distribution]:
    # Resolve only production dependency edges, including their declared extras.
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = {
        canonicalize_name(match[1]): match[2]
        for line in (root / "requirements.lock").read_text(encoding="utf-8").splitlines()
        if (match := re.fullmatch(r"([A-Za-z0-9_-]+)==([^\s;]+)(?:\s*;.*)?", line.strip()))
    }
    requested: dict[str, set[str]] = {}
    completed: dict[str, set[str]] = {}
    distributions = {}
    pending = [Requirement(value) for value in project["project"]["dependencies"]]
    environment = default_environment()
    while pending:
        requirement = pending.pop()
        if requirement.marker and not requirement.marker.evaluate(environment | {"extra": ""}):
            continue
        name = canonicalize_name(requirement.name)
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            raise ReleaseError(f"a locked runtime dependency is not installed: {name}") from None
        if distribution.version != lock.get(name) or not requirement.specifier.contains(
            distribution.version
        ):
            raise ReleaseError(
                f"installed runtime dependency differs from requirements.lock: {name}"
            )
        requested.setdefault(name, set()).update(requirement.extras)
        extras = requested[name] | {""}
        if extras.issubset(completed.get(name, set())):
            continue
        completed[name] = set(extras)
        distributions[name] = distribution
        for text in distribution.requires or []:
            dependency = Requirement(text)
            if dependency.marker is None or any(
                dependency.marker.evaluate(environment | {"extra": extra}) for extra in extras
            ):
                dependency.marker = None
                pending.append(dependency)
    return [distributions[name] for name in sorted(distributions)]


def python_files(base: Path, site: Path, distributions: list) -> dict[str, Path]:
    selected = {}
    required = {
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        "python312.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "LICENSE.txt",
    }
    for name in sorted(required):
        selected[f".runtime/python/{name}"] = checked_file(base / name, base)
    omitted = {
        "__pycache__",
        "site-packages",
        "test",
        "tests",
        "idlelib",
        "tkinter",
        "turtledemo",
        "ensurepip",
    }
    for path in (base / "Lib").rglob("*"):
        relative = path.relative_to(base)
        if (
            path.is_file()
            and not set(relative.parts) & omitted
            and path.suffix not in {".pyc", ".pyo"}
            and path.name != "turtle.py"
        ):
            selected[f".runtime/python/{relative.as_posix()}"] = checked_file(path, base)
    for path in (base / "DLLs").iterdir():
        if (
            path.is_file()
            and path.suffix in {".dll", ".pyd"}
            and not path.name.startswith(("_test", "_ctypes_test", "_tkinter", "tcl", "tk86"))
        ):
            selected[f".runtime/python/DLLs/{path.name}"] = checked_file(path, base)
    for distribution in distributions:
        if not distribution.files:
            raise ReleaseError("runtime distribution has no installed file inventory")
        for entry in distribution.files:
            relative = PurePosixPath(str(entry).replace("\\", "/"))
            if ".." in relative.parts or relative.is_absolute():
                continue  # Console entry points are not used; modules run through python.exe.
            if "__pycache__" in relative.parts or relative.suffix in {".pyc", ".pyo"}:
                continue
            if relative.suffix == ".pth":
                raise ReleaseError("an executable .pth needs an explicit portable-runtime review")
            source = Path(distribution.locate_file(entry))
            source = checked_file(source, site)
            selected[f".runtime/python/Lib/site-packages/{relative}"] = source
    if ".runtime/python/Lib/encodings/__init__.py" not in selected:
        raise ReleaseError("the bundled Python standard library is incomplete")
    return dict(sorted(selected.items()))


def locked_postgres(root: Path) -> tuple[dict, Path]:
    spec = json.loads((root / "scripts/native-dependencies.lock.json").read_text(encoding="utf-8"))[
        "postgresql"
    ]
    name = spec["archive"]
    if Path(name).name != name or not name.endswith(".zip"):
        raise ReleaseError("unsafe PostgreSQL archive name in the dependency lock")
    archive = checked_file(root / ".native/downloads" / name, root)
    if digest(archive) != spec["sha256"]:
        raise ReleaseError("PostgreSQL installer SHA256 differs from the dependency lock")
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            path = PurePosixPath(item.filename.replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts or ":" in item.filename:
                raise ReleaseError("the PostgreSQL installer contains an unsafe path")
        executable = "pgsql/bin/pg_ctl.exe"
        if (
            executable not in source.namelist()
            or "pgsql/server_license.txt" not in source.namelist()
        ):
            raise ReleaseError("unexpected PostgreSQL installer layout or missing license")
    return spec, archive


def frontend_licenses(root: Path) -> tuple[dict[str, Path], dict[str, str], list[dict]]:
    lock = json.loads((root / "frontend/package-lock.json").read_text(encoding="utf-8"))
    selected = {}
    versions = {}
    declarations = []
    modules = root / "frontend/node_modules"
    for name, specification in lock.get("packages", {}).items():
        if not name or specification.get("dev") or not name.startswith("node_modules/"):
            continue
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ReleaseError("unsafe frontend dependency path")
        directory = root / "frontend" / name
        metadata = checked_file(directory / "package.json", modules)
        package = json.loads(metadata.read_text(encoding="utf-8"))
        if package.get("version") != specification.get("version"):
            raise ReleaseError("frontend dependency version differs from package-lock.json")
        identity = package.get("name", name.removeprefix("node_modules/"))
        if not isinstance(identity, str) or not re.fullmatch(
            r"@?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", identity
        ):
            raise ReleaseError("unsafe frontend package identity")
        version = package["version"]
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", version):
            raise ReleaseError("unsafe frontend dependency version")
        versions[identity] = version
        folder = identity.replace("@", "").replace("/", "__") + "-" + version
        licenses = [
            path
            for path in directory.iterdir()
            if path.is_file()
            and path.name.lower().startswith(("license", "licence", "notice", "copying"))
        ]
        if not licenses and (identity, version) == ("@ant-design/icons-svg", "4.6.0"):
            shared = checked_file(modules / "@ant-design/icons/LICENSE", modules)
            if digest(shared) != "5d367fb0a07340571542eb4ee8eb1add62d37b71bad6786a57c2e9a86bf76c70":
                raise ReleaseError(
                    "the shared Ant Design license differs from its version-pinned source"
                )
            licenses = [shared]
        if not licenses and (identity, version) == ("toggle-selection", "1.0.6"):
            if package.get("license") != "MIT":
                raise ReleaseError("toggle-selection has a different license declaration")
            selected[f".runtime/licenses/frontend/{folder}/PACKAGE-METADATA.json"] = metadata
            declarations.append(
                {
                    "name": identity,
                    "version": version,
                    "license": "MIT",
                    "boundary": (
                        "original release declares MIT but has no LICENSE text; not fabricated"
                    ),
                    "source": (
                        "https://github.com/sudodoki/toggle-selection/blob/"
                        "466460c75ca40630d8de940490718247fce79a3e/package.json"
                    ),
                }
            )
            continue
        if not licenses:
            raise ReleaseError(
                "a frontend runtime dependency is missing its installed license file: " + identity
            )
        for path in licenses:
            selected[f".runtime/licenses/frontend/{folder}/{path.name}"] = checked_file(
                path, modules
            )
    if not versions:
        raise ReleaseError("the frontend production dependency inventory is missing")
    return selected, dict(sorted(versions.items())), declarations


def known_secrets(root: Path) -> list[bytes]:
    values = [
        value.encode()
        for name, value in os.environ.items()
        if (name.upper().endswith("_API_KEY") or name.upper().endswith("_PASSWORD"))
        and len(value) >= 8
    ]
    config = root / ".native/config.json"
    if config.is_file():
        from scripts.native_windows_dpapi import read_database_config

        for name, value in read_database_config(config).items():
            if "password" in name.lower() and isinstance(value, str) and len(value) >= 8:
                values.append(value.encode())
    for folder in (root / "keys/private", root / ".native/keys/private"):
        for path in folder.glob("*.private"):
            values.append(path.read_bytes().strip())
    # Compare credentials in memory only; never print or place them in a report.
    credentials = root / ".native/model-configurations.json"
    if credentials.is_file():
        from backend.config.model_profiles import WindowsCredentialCipher

        cipher = WindowsCredentialCipher()
        for row in (
            json.loads(credentials.read_text(encoding="utf-8-sig")).get("items", {}).values()
        ):
            if row.get("credential"):
                values.append(cipher.decrypt(row["credential"]).encode())
    legacy = root / ".native/secrets/deepseek-api-key.dpapi"
    if legacy.is_file() and os.name == "nt":
        encrypted = bytes.fromhex(legacy.read_text(encoding="ascii").strip())

        class Blob(ctypes.Structure):
            _fields_: ClassVar = [
                ("length", ctypes.c_ulong),
                ("data", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        buffer = (ctypes.c_ubyte * len(encrypted)).from_buffer_copy(encrypted)
        input_blob = Blob(len(encrypted), buffer)
        output_blob = Blob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(Blob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.POINTER(Blob),
        ]
        crypt32.CryptUnprotectData.restype = ctypes.c_int
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if not crypt32.CryptUnprotectData(
            ctypes.byref(input_blob), None, None, None, None, 1, ctypes.byref(output_blob)
        ):
            raise ReleaseError("cannot inspect this user's legacy encrypted credential safely")
        try:
            values.append(
                ctypes.string_at(output_blob.data, output_blob.length).decode("utf-16-le").encode()
            )
        finally:
            kernel32.LocalFree(output_blob.data)
    return [value for value in set(values) if len(value) >= 8]


def scan_file(path: Path, secrets: list[bytes]) -> None:
    overlap = max([256, *(len(value) for value in secrets)])
    previous = b""
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            window = previous + chunk
            if KEY_PATTERN.search(window) or any(secret in window for secret in secrets):
                raise ReleaseError(
                    "release input contains credential-like or personal secret material"
                )
            previous = window[-overlap:]


def verify_release(root: Path) -> dict:
    if (root / MANIFEST).stat().st_size > 16 * 1024 * 1024:
        raise ReleaseError("release manifest is too large")
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "agentguard-windows-release-v1":
        raise ReleaseError("unknown release manifest schema")
    recorded = manifest["files"]
    if not isinstance(recorded, dict) or len(recorded) > 100_000:
        raise ReleaseError("invalid release inventory")
    if not (
        REQUIRED_FILES | {".runtime/python/python.exe", ".runtime/python/LICENSE.txt"}
    ).issubset(recorded):
        raise ReleaseError("release inventory is missing required runtime or source files")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != recorded.keys() | {MANIFEST}:
        raise ReleaseError("release files were added or removed after the manifest was created")
    installer = ".native/downloads/" + manifest["postgresql"]["archive"]
    if (
        installer not in recorded
        or recorded[installer].get("sha256") != manifest["postgresql"]["sha256"]
    ):
        raise ReleaseError("the installer inventory does not match the PostgreSQL lock")
    bundled_lock = json.loads(
        (root / "scripts/native-dependencies.lock.json").read_text(encoding="utf-8")
    )
    if bundled_lock.get("postgresql") != manifest["postgresql"]:
        raise ReleaseError("the release manifest differs from the bundled PostgreSQL lock")
    for name, expected in recorded.items():
        if (
            not isinstance(name, str)
            or not isinstance(expected, dict)
            or type(expected.get("bytes")) is not int
            or expected["bytes"] < 0
            or not isinstance(expected.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])
        ):
            raise ReleaseError("invalid release inventory entry")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
            raise ReleaseError("unsafe release manifest path")
        if name != installer and not allowed_source(relative):
            raise ReleaseError("unexpected state, private key or cache in release")
        if relative.parts[0] == ".native" and name != installer:
            raise ReleaseError("personal native runtime state is present in release")
        path = checked_file(root / name, root)
        if path.stat().st_size != expected["bytes"] or digest(path) != expected["sha256"]:
            raise ReleaseError("release file differs from its SHA256 inventory: " + name)
        scan_file(path, [])
    encoded = json.dumps(recorded, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(encoded).hexdigest() != manifest["content_sha256"]:
        raise ReleaseError("release content inventory hash is invalid")
    return {
        "status": "PASS",
        "files": len(recorded),
        "content_sha256": manifest["content_sha256"],
        "bytes": sum(row["bytes"] for row in recorded.values()),
        "runtime_credentials": "absent",
        "native_state": "absent_except_locked_installer",
    }


def verify_runtime(root: Path) -> dict:
    executable = root / ".runtime/python/python.exe"
    imports = (
        "import sys,ssl,sqlite3,ctypes,json;from pathlib import Path;"
        "sys.path.insert(0,sys.argv[1]);"
        "import fastapi,gmssl,httpx,jsonschema,psutil,psycopg,pydantic,pydantic_settings;"
        "import rfc8785,yaml,sqlalchemy,uvicorn;"
        "import backend.ui_api.app,scripts.native_runtime;"
        "from backend.crypto.sm import sm3_hex;"
        "assert sm3_hex(b'abc')=='66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0';"
        "assert Path(sys.prefix).resolve()==Path(sys.argv[1],'.runtime/python').resolve();"
        "print(json.dumps({'status':'PASS','python':sys.version.split()[0],"
        "'prefix_is_bundled':True,'openssl':ssl.OPENSSL_VERSION,'sm3_vector':'PASS'}))"
    )
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(("AGENTGUARD_", "PYTHON"))
        and not name.upper().endswith(("_API_KEY", "_PASSWORD"))
    }
    environment["PATH"] = os.path.join(environment.get("SystemRoot", "C:\\Windows"), "System32")
    result = subprocess.run(
        [str(executable), "-I", "-B", "-c", imports, str(root.resolve())],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise ReleaseError("bundled runtime import or fixed-vector check failed")
    return json.loads(result.stdout.strip())


def build_release(root: Path, output: Path, name: str) -> dict:
    if os.name != "nt" or sys.version_info[:2] != (3, 12) or sys.maxsize < 2**32:
        raise ReleaseError(
            "build the x64 Windows release with the installed Python 3.12 environment"
        )
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name) or name.lower() in {
        "con",
        "prn",
        "nul",
        "aux",
    }:
        raise ReleaseError("invalid Windows release name")
    root = root.resolve()
    output = output.resolve()
    if not output.is_relative_to(root / "output/windows-release"):
        raise ReleaseError("release output must stay inside the project's output/windows-release")
    destination = output / name
    archive = output / (name + ".zip")
    if destination.exists() or archive.exists():
        raise ReleaseError("release output already exists; choose another name, not an overwrite")
    selected = project_files(root)
    original = {name: digest(path) for name, path in selected.items()}
    distributions = runtime_distributions(root)
    base = Path(sys.base_prefix)
    site = Path(sysconfig.get_path("purelib"))
    selected |= python_files(base, site, distributions)
    licenses, frontend_versions, license_declarations = frontend_licenses(root)
    selected |= licenses
    spec, postgres = locked_postgres(root)
    selected[".native/downloads/" + spec["archive"]] = postgres
    secrets = known_secrets(root)
    output.mkdir(parents=True, exist_ok=True)
    stage = output / ("." + name + "-" + uuid.uuid4().hex + ".tmp")
    stage.mkdir()
    package = stage / "AgentGuard"
    package.mkdir()
    try:
        files = {}
        for relative, source in sorted(selected.items()):
            if source != postgres:
                scan_file(source, secrets)
            target = package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            files[relative] = {"bytes": target.stat().st_size, "sha256": digest(target)}
            if relative in original and files[relative]["sha256"] != original[relative]:
                raise ReleaseError(
                    "project source changed while copying; freeze it and build again"
                )
        if project_files(root).keys() != original.keys() or any(
            digest(root / relative) != expected for relative, expected in original.items()
        ):
            raise ReleaseError("project source changed during the build; build a new snapshot")
        license_folder = package / ".runtime/licenses/postgresql"
        license_folder.mkdir(parents=True)
        with zipfile.ZipFile(postgres) as installer:
            (license_folder / "server_license.txt").write_bytes(
                installer.read("pgsql/server_license.txt")
            )
            name_in_archive = "pgsql/commandlinetools_3rd_party_licenses.txt"
            if name_in_archive in installer.namelist():
                (license_folder / "commandlinetools_3rd_party_licenses.txt").write_bytes(
                    installer.read(name_in_archive)
                )
        for path in license_folder.iterdir():
            files[path.relative_to(package).as_posix()] = {
                "bytes": path.stat().st_size,
                "sha256": digest(path),
            }
        encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        manifest = {
            "schema_version": "agentguard-windows-release-v1",
            "created_at": datetime.now(UTC).isoformat(),
            "python": {
                "version": sys.version.split()[0],
                "architecture": "Windows-x64",
                "runtime": ".runtime/python/python.exe",
                "license": ".runtime/python/LICENSE.txt",
                "omitted": [
                    "pip",
                    "ensurepip",
                    "IDLE",
                    "Tk",
                    "stdlib tests",
                    "development-only distributions",
                ],
            },
            "dependencies": {row.metadata["Name"]: row.version for row in distributions},
            "frontend_dependencies": frontend_versions,
            "license_declarations_only": license_declarations,
            "postgresql": spec,
            "files": dict(sorted(files.items())),
            "content_sha256": hashlib.sha256(encoded).hexdigest(),
            "personal_state": (
                "not_copied; first launch must generate new database credentials and signing keys"
            ),
            "clean_windows_acceptance": "not_verified_by_this_builder",
        }
        (package / MANIFEST).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=True), encoding="utf-8"
        )
        checked = verify_release(package)
        checked["runtime"] = verify_runtime(package)
        checked["license_declarations_only"] = license_declarations
        with zipfile.ZipFile(
            stage / archive.name,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
            allowZip64=True,
        ) as zipped:
            for path in sorted(package.rglob("*")):
                if path.is_file():
                    compression = (
                        zipfile.ZIP_STORED if path.suffix == ".zip" else zipfile.ZIP_DEFLATED
                    )
                    zipped.write(
                        path,
                        "AgentGuard/" + path.relative_to(package).as_posix(),
                        compress_type=compression,
                    )
        stage.rename(destination)
        (destination / archive.name).replace(archive)
        checked.update(
            {
                "package": str(destination / "AgentGuard"),
                "archive": str(archive),
                "archive_sha256": digest(archive),
                "archive_bytes": archive.stat().st_size,
            }
        )
        (destination / "build-report.json").write_text(
            json.dumps(checked, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        return checked
    finally:
        if stage.exists():
            if not stage.resolve().is_relative_to(output) or not stage.name.startswith(
                "." + name + "-"
            ):
                raise ReleaseError(
                    "refusing cleanup outside the allocated release staging directory"
                )
            shutil.rmtree(stage)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a credential-free x64 Windows AgentGuard release"
    )
    parser.add_argument(
        "--name", default="AgentGuard-Windows-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    parser.add_argument("--output", type=Path, default=ROOT / "output/windows-release")
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--runtime-check", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify:
            result = verify_release(args.verify.resolve())
            if args.runtime_check:
                result["runtime"] = verify_runtime(args.verify.resolve())
        else:
            result = build_release(ROOT, args.output, args.name)
        print(json.dumps(result, ensure_ascii=True, indent=2))
    except (ReleaseError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, "WINDOWS_RELEASE_FAILED: " + str(error) + "\n")


if __name__ == "__main__":
    main()
