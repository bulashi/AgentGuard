"""Compare a recorded benchmark source snapshot with the installed source."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scripts.source_manifest import snapshot


def source_provenance(summary: dict[str, Any], root: Path) -> dict[str, Any]:
    environment = summary.get("environment")
    recorded_sources = []
    if isinstance(environment, dict):
        if "source_snapshot" in environment:
            recorded_sources.append(environment["source_snapshot"])
        version = environment.get("code_version")
        if isinstance(version, dict) and "source_snapshot" in version:
            recorded_sources.append(version["source_snapshot"])
    hashes = [
        value.get("snapshot_sha256") if isinstance(value, dict) else None
        for value in recorded_sources
    ]
    valid_hashes = [
        value for value in hashes if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
    ]
    recorded_hash = (
        valid_hashes[0]
        if valid_hashes and len(valid_hashes) == len(hashes) and len(set(valid_hashes)) == 1
        else None
    )
    result = {
        "status": "UNVERIFIED",
        "recorded_snapshot_sha256": recorded_hash,
        "current_snapshot_sha256": None,
    }
    try:
        current_hash = snapshot(root)["snapshot_sha256"]
    except (OSError, ValueError, KeyError):
        return result
    result["current_snapshot_sha256"] = current_hash
    if recorded_hash is not None:
        result["status"] = "MATCH" if recorded_hash == current_hash else "SOURCE_CHANGED"
    return result
