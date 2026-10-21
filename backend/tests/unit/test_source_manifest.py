from pathlib import Path

import pytest

from scripts.source_manifest import ROOT, snapshot, verify


def test_source_snapshot_tracks_changes_and_new_files(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    source_dir = tmp_path / "backend"
    source_dir.mkdir()
    source = source_dir / "service.py"
    source.write_text("pass\n", encoding="ascii")
    manifest = snapshot(tmp_path)
    assert verify(manifest, tmp_path) == manifest
    assert list(manifest["files"]) == ["backend/service.py"]
    source.write_text("raise RuntimeError\n", encoding="ascii")
    with pytest.raises(RuntimeError, match="differ"):
        verify(manifest, tmp_path)
    source.write_text("pass\n", encoding="ascii")
    (source_dir / "new.py").write_text("pass\n", encoding="ascii")
    with pytest.raises(RuntimeError, match="differ"):
        verify(manifest, tmp_path)


def test_source_snapshot_excludes_secrets_dependencies_and_generated_output(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    for name in (".native", "keys/private", "frontend/node_modules", "frontend/dist", "evidence"):
        directory = tmp_path / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "ignored.json").write_text("{}", encoding="ascii")
    assert snapshot(tmp_path)["files"] == {}


def test_native_source_manifest_excludes_runtime_secrets_and_retired_deployment() -> None:
    paths = set(snapshot(ROOT)["files"])
    assert not any(path.startswith((".native/", "keys/private/", "node_modules/")) for path in paths)
    assert not {"Dockerfile", "compose.yaml", "compose.cloud.yaml", ".dockerignore"} & paths
