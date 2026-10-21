from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath
from unittest.mock import Mock

import pytest

from scripts import build_windows_release as release


@pytest.fixture
def repository(tmp_path: Path):
    root = tmp_path / "project"
    for relative in release.REQUIRED_FILES | {"backend/tests/unit/test_public.py"}:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("public source\n", encoding="utf-8")
    installer = root / ".native/downloads/postgresql.zip"
    installer.parent.mkdir(parents=True)
    with zipfile.ZipFile(installer, "w") as source:
        source.writestr("pgsql/bin/pg_ctl.exe", b"fixed locked binary fixture")
        source.writestr("pgsql/server_license.txt", "PostgreSQL License")
    spec = {
        "version": "16.15-1",
        "archive": installer.name,
        "sha256": release.digest(installer),
        "directory": "postgresql-16.15-1",
        "executable": "pgsql/bin/pg_ctl.exe",
    }
    (root / "scripts/native-dependencies.lock.json").write_text(json.dumps({"postgresql": spec}))
    return root, spec


def add_file(root: Path, relative: str, body="not public") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def make_manifest(root: Path, spec: dict) -> dict:
    add_file(root, ".runtime/python/python.exe", "portable python fixture")
    add_file(root, ".runtime/python/LICENSE.txt", "Python Software Foundation License")
    files = {
        path.relative_to(root).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": release.digest(path),
        }
        for path in root.rglob("*")
        if path.is_file() and path.name != release.MANIFEST
    }
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "schema_version": "agentguard-windows-release-v1",
        "files": files,
        "postgresql": spec,
        "content_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    (root / release.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


@pytest.mark.parametrize(
    "relative",
    [
        ".native/config.json",
        ".native/secrets/key.dpapi",
        ".native/postgres/data/PG_VERSION",
        "keys/private/agent.private",
        "backend/.env",
        "backend/private.key",
        "backend/private.pem",
        "backend/__pycache__/file.pyc",
        "frontend/node_modules/third-party/index.js",
        "evidence/old.json",
        "artifacts/old.json",
        "output/old.py",
        "scripts/output/debug.py",
        "scripts/__pycache__/old.py",
        "frontend/src/keys/personal.json",
    ],
)
def test_personal_runtime_caches_keys_and_old_evidence_are_not_in_the_project_plan(
    repository, relative
):
    root, _ = repository
    add_file(root, relative)
    assert relative not in release.project_files(root)


def test_seed_sources_tests_protocol_migrations_and_frontend_build_are_included(repository):
    root, _ = repository
    paths = [
        "scripts/seed_demo.py",
        "backend/tools/app.py",
        "backend/tests/unit/test_public.py",
        "protocol/schemas/capability-credential.schema.json",
        "database/migrations/main/0023_business_eligibility.sql",
        "frontend/dist/assets/main.js",
        "frontend/src/App.tsx",
        "frontend/e2e/workflow.spec.ts",
        "frontend/package-lock.json",
    ]
    for relative in paths:
        add_file(root, relative, "public")
    assert set(paths).issubset(release.project_files(root))


def test_only_current_explicitly_allowed_documents_and_launchers_are_copied(repository):
    root, _ = repository
    allowed = "docs/第三方组件与许可说明.md"
    historical = "docs/最终交付报告.md"
    add_file(root, historical)
    add_file(root, "配置DeepSeek.cmd")
    assert allowed in release.project_files(root)
    assert historical not in release.project_files(root)
    assert "配置DeepSeek.cmd" not in release.project_files(root)


@pytest.mark.parametrize("name", ["派发前撤销与控制台使用说明.md", "本机撤销功能验收报告.md"])
def test_current_revocation_handbook_and_report_are_in_the_public_release(repository, name):
    root, _ = repository
    relative = f"docs/{name}"
    add_file(root, relative, "current public revocation documentation")
    assert relative in release.project_files(root)


@pytest.mark.parametrize(
    "missing",
    [
        "frontend/dist/index.html",
        "scripts/seed_demo.py",
        "protocol/manifest.json",
        "requirements.lock",
    ],
)
def test_missing_required_inputs_are_not_silently_omitted(repository, missing):
    root, _ = repository
    (root / missing).unlink()
    with pytest.raises(release.ReleaseError, match="missing required"):
        release.project_files(root)


def test_no_public_tests_is_a_packaging_failure(repository):
    root, _ = repository
    (root / "backend/tests/unit/test_public.py").unlink()
    with pytest.raises(release.ReleaseError, match="test sources"):
        release.project_files(root)


def test_postgresql_archive_must_match_locked_hash_and_license(repository):
    root, spec = repository
    result, installer = release.locked_postgres(root)
    assert result == spec
    assert installer.name == "postgresql.zip"
    with installer.open("ab") as target:
        target.write(b"tampered")
    with pytest.raises(release.ReleaseError, match="SHA256"):
        release.locked_postgres(root)


def test_frontend_licenses_follow_production_lock_without_copying_node_modules(repository):
    root, _ = repository
    add_file(
        root,
        "frontend/package-lock.json",
        json.dumps(
            {
                "packages": {
                    "": {"name": "app"},
                    "node_modules/react": {"version": "19.1.1"},
                    "node_modules/dev-test-runner": {"version": "1.0.0", "dev": True},
                }
            }
        ),
    )
    add_file(
        root,
        "frontend/node_modules/react/package.json",
        json.dumps({"name": "react", "version": "19.1.1"}),
    )
    add_file(root, "frontend/node_modules/react/LICENSE", "MIT license")
    files, versions, declarations = release.frontend_licenses(root)
    assert versions == {"react": "19.1.1"}
    assert list(files) == [".runtime/licenses/frontend/react-19.1.1/LICENSE"]
    assert not any("node_modules" in path for path in files)
    assert declarations == []


def test_only_the_verified_original_missing_license_package_keeps_its_declaration(repository):
    root, _ = repository
    add_file(
        root,
        "frontend/package-lock.json",
        json.dumps(
            {
                "packages": {
                    "node_modules/toggle-selection": {"version": "1.0.6"},
                }
            }
        ),
    )
    add_file(
        root,
        "frontend/node_modules/toggle-selection/package.json",
        json.dumps(
            {
                "name": "toggle-selection",
                "version": "1.0.6",
                "license": "MIT",
            }
        ),
    )
    files, versions, declarations = release.frontend_licenses(root)
    assert versions == {"toggle-selection": "1.0.6"}
    assert list(files) == [
        ".runtime/licenses/frontend/toggle-selection-1.0.6/PACKAGE-METADATA.json"
    ]
    assert declarations[0]["license"] == "MIT"
    assert "no LICENSE text" in declarations[0]["boundary"]


@pytest.mark.parametrize("failure", ["version", "license", "traversal"])
def test_frontend_license_inputs_must_be_locked_and_safe(repository, failure):
    root, _ = repository
    packages = {"node_modules/react": {"version": "19.1.1"}}
    if failure == "traversal":
        packages = {"node_modules/../outside": {"version": "19.1.1"}}
    add_file(root, "frontend/package-lock.json", json.dumps({"packages": packages}))
    add_file(
        root,
        "frontend/node_modules/react/package.json",
        json.dumps(
            {
                "name": "react",
                "version": "0.0.0" if failure == "version" else "19.1.1",
            }
        ),
    )
    if failure != "license":
        add_file(root, "frontend/node_modules/react/LICENSE", "MIT license")
    with pytest.raises(release.ReleaseError):
        release.frontend_licenses(root)


@pytest.mark.parametrize(
    "unsafe", ["../escape.exe", "/absolute.exe", "C:/outside.exe", "..\\escape.exe"]
)
def test_locked_zip_still_cannot_contain_traversal_paths(repository, unsafe):
    root, spec = repository
    installer = root / ".native/downloads/postgresql.zip"
    with zipfile.ZipFile(installer, "a") as zipped:
        zipped.writestr(unsafe, "not safe")
    spec["sha256"] = release.digest(installer)
    (root / "scripts/native-dependencies.lock.json").write_text(json.dumps({"postgresql": spec}))
    with pytest.raises(release.ReleaseError, match="unsafe path"):
        release.locked_postgres(root)


def test_secret_comparison_does_not_return_secret_value(tmp_path):
    secret = b"PERSONAL_CREDENTIAL_FOR_TEST_ONLY"
    path = tmp_path / "file.py"
    path.write_bytes(b"PUBLIC_DATA " + secret)
    with pytest.raises(release.ReleaseError) as caught:
        release.scan_file(path, [secret])
    assert secret.decode() not in str(caught.value)


def test_api_key_pattern_is_detected_across_reader_chunks(tmp_path):
    path = tmp_path / "file.js"
    key = b"sk-" + b"A" * 32
    path.write_bytes(b"." * (1024 * 1024 - 2) + key)
    with pytest.raises(release.ReleaseError, match="secret material"):
        release.scan_file(path, [])


def test_known_password_and_signing_key_are_loaded_for_comparison_not_reports(
    repository, monkeypatch
):
    root, _ = repository
    monkeypatch.setenv("TEST_RELEASE_API_KEY", "UNIT_TEST_CREDENTIAL_ONLY")
    add_file(root, ".native/config.json", json.dumps({"admin_password": "UNIT_TEST_DB_PASSWORD"}))
    add_file(root, ".native/keys/private/agent.private", "UNIT_TEST_SIGNING_KEY")
    values = release.known_secrets(root)
    assert b"UNIT_TEST_CREDENTIAL_ONLY" in values
    assert b"UNIT_TEST_DB_PASSWORD" in values
    assert b"UNIT_TEST_SIGNING_KEY" in values


def test_ca_bundle_is_public_required_material_not_a_private_signing_key():
    assert release.allowed_source(
        PurePosixPath(".runtime/python/Lib/site-packages/certifi/cacert.pem")
    )
    assert not release.allowed_source(
        PurePosixPath(".runtime/python/Lib/site-packages/personal.pem")
    )


def test_distribution_runtime_plan_retains_licenses_and_excludes_dev_packages():
    distributions = release.runtime_distributions(release.ROOT)
    versions = {row.metadata["Name"].lower(): row.version for row in distributions}
    assert versions["fastapi"] == "0.117.1"
    assert versions["psycopg-binary"] == "3.2.10"
    assert "locust" not in versions and "pytest" not in versions and "ruff" not in versions
    files = release.python_files(
        Path(sys.base_prefix), Path(sys.prefix) / "Lib/site-packages", distributions
    )
    assert ".runtime/python/LICENSE.txt" in files
    assert ".runtime/python/Lib/encodings/__init__.py" in files
    assert any(".dist-info/licenses" in name for name in files)
    assert not any(name.endswith(".pth") or "__pycache__" in name for name in files)


def test_distribution_outside_site_packages_is_rejected(tmp_path):
    base, site = tmp_path / "python", tmp_path / "site"
    for name in (
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        "python312.dll",
        "LICENSE.txt",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "Lib/encodings/__init__.py",
    ):
        add_file(base, name, "runtime")
    (base / "DLLs").mkdir()
    site.mkdir()
    outside = add_file(tmp_path, "outside.py", "not approved")
    distribution = Mock(files=["library.py"])
    distribution.locate_file.return_value = outside
    with pytest.raises(release.ReleaseError, match="escapes"):
        release.python_files(base, site, [distribution])


def test_valid_release_inventory_can_be_verified(repository):
    root, spec = repository
    make_manifest(root, spec)
    report = release.verify_release(root)
    assert report["status"] == "PASS"
    assert report["runtime_credentials"] == "absent"
    assert "archive_sha256" not in report  # Content checks are not an external publisher signature.


@pytest.mark.parametrize("change", ["modified", "missing", "new"])
def test_release_tampering_does_not_pass(repository, change):
    root, spec = repository
    make_manifest(root, spec)
    if change == "modified":
        (root / "README.md").write_text("tampered")
    elif change == "missing":
        (root / "README.md").unlink()
    else:
        add_file(root, ".native/secrets/key.dpapi")
    with pytest.raises(release.ReleaseError):
        release.verify_release(root)


@pytest.mark.parametrize(
    "state",
    [
        ".native/config.json",
        "keys/private/agent.private",
        ".runtime/python/Lib/site-packages/personal.key",
    ],
)
def test_even_a_new_matching_manifest_cannot_allow_personal_state(repository, state):
    root, spec = repository
    add_file(root, state)
    make_manifest(root, spec)
    with pytest.raises(release.ReleaseError):
        release.verify_release(root)


def test_install_archive_cannot_disagree_with_bundled_lock(repository):
    root, spec = repository
    manifest = make_manifest(root, spec)
    manifest["postgresql"] = dict(spec, version="UNLOCKED")
    (root / release.MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(release.ReleaseError, match="differs"):
        release.verify_release(root)


def test_inventory_hash_is_required(repository):
    root, spec = repository
    manifest = make_manifest(root, spec)
    manifest["content_sha256"] = "0" * 64
    (root / release.MANIFEST).write_text(json.dumps(manifest))
    with pytest.raises(release.ReleaseError, match="inventory hash"):
        release.verify_release(root)


def test_release_cannot_be_written_outside_its_output_boundary(repository):
    root, _ = repository
    with pytest.raises(release.ReleaseError, match="output must stay"):
        release.build_release(root, root.parent / "outside", "AgentGuard-Test")
    assert not (root.parent / "outside").exists()


@pytest.mark.parametrize(
    "name", ["../escape", "C:/absolute", "NUL", "CON", "a/b", "a b", ".hidden"]
)
def test_release_names_cannot_create_unintended_paths(repository, name):
    root, _ = repository
    with pytest.raises(release.ReleaseError, match="release name"):
        release.build_release(root, root / "output/windows-release", name)


def test_existing_release_is_not_overwritten(repository):
    root, _ = repository
    existing = root / "output/windows-release/AgentGuard-Existing"
    existing.mkdir(parents=True)
    marker = add_file(existing, "keep.txt", "existing user artifact")
    with pytest.raises(release.ReleaseError, match="already exists"):
        release.build_release(root, existing.parent, existing.name)
    assert marker.read_text() == "existing user artifact"
