from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.integration
def test_typescript_matches_python_canonical_vectors() -> None:
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if npm is None:
        pytest.fail("npm is required for the frozen cross-language canonical test")
    result = subprocess.run(
        [npm, "run", "protocol:check", "--silent"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified 7 canonical/SM3 vectors in TypeScript" in result.stdout
