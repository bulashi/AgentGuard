from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = (
    "backend",
    "database",
    "protocol",
    "attacks",
    "scripts",
    "frontend/src",
    "frontend/e2e",
    "frontend/public",
)
SOURCE_SUFFIXES = {
    ".py",
    ".ps1",
    ".cmd",
    ".ts",
    ".tsx",
    ".js",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".css",
    ".html",
    ".svg",
    ".toml",
    ".lock",
    ".conf",
}
ROOT_FILES = {
    ".gitignore",
    "pyproject.toml",
    "requirements.lock",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
}


def snapshot(root: Path = ROOT) -> dict:
    paths = {
        path
        for name in SOURCE_DIRECTORIES
        for path in (root / name).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix in SOURCE_SUFFIXES
    }
    paths |= {
        path
        for path in root.iterdir()
        if path.is_file() and (path.name in ROOT_FILES or path.suffix == ".cmd")
    }
    paths |= {
        path
        for path in (root / "frontend").iterdir()
        if path.is_file() and path.suffix in SOURCE_SUFFIXES
    }
    files = {}
    for path in sorted(paths):
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        files[path.relative_to(root).as_posix()] = {"bytes": path.stat().st_size, "sha256": digest}
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema_version": "1.0",
        "files": files,
        "snapshot_sha256": hashlib.sha256(encoded).hexdigest(),
        "boundary": "source_and_locked_configuration_not_runtime_secrets_or_generated_evidence",
    }


def verify(manifest: dict, root: Path = ROOT) -> dict:
    current = snapshot(root)
    if current != manifest:
        raise RuntimeError("source files differ from the formally verified snapshot")
    return current


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if bool(args.output) == bool(args.verify):
        parser.error("choose exactly one of --output or --verify")
    if args.verify:
        manifest = verify(json.loads(args.verify.read_text(encoding="utf-8-sig")))
        print("SOURCE_SNAPSHOT_CURRENT=PASS")
    else:
        manifest = snapshot()
        args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"SOURCE_SNAPSHOT_SHA256={manifest['snapshot_sha256']} files={len(manifest['files'])}")


if __name__ == "__main__":
    main()
