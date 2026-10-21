from __future__ import annotations

import json
from pathlib import Path

from backend.agent_runtime.workflow_planner import runtime_profiles
from backend.config.settings import Settings

ROOT = Path(__file__).resolve().parents[3]


def test_retired_deployment_files_are_absent() -> None:
    retired = [
        ".dockerignore", ".env.example", "Dockerfile", "compose.yaml", "compose.cloud.yaml",
        "frontend/Dockerfile", "frontend/nginx.conf", "scripts/up.ps1", "scripts/down.ps1",
        "scripts/doctor.ps1", "scripts/run-benchmarks.ps1", "scripts/run_benchmarks.py",
        "scripts/diagnose_workflow_model.py", "scripts/verify-final-delivery.ps1",
        "scripts/native_test_guard/deployment.py",
        "backend/tests/integration/test_live_llm_prompt_injection.py",
        *[f"scripts/verify-phase{i}.ps1" for i in range(18)],
    ]
    assert all(not (ROOT / name).exists() for name in retired)


def test_no_project_local_model_or_wsl_payload_remains() -> None:
    retired = [
        ".native/models", ".native/home/.ollama", ".native/deps/ollama-0.12.3",
        ".native/downloads/ollama-0.12.3-windows-amd64.zip",
        ".cache/Microsoft.WSL_2.7.13.0_x64_ARM64.msixbundle",
    ]
    assert all(not (ROOT / name).exists() for name in retired)
    lock = json.loads((ROOT / "scripts/native-dependencies.lock.json").read_text(encoding="utf-8"))
    assert set(lock) == {"postgresql"}


def test_public_runtime_profiles_do_not_expose_a_retired_model() -> None:
    profiles = runtime_profiles(Settings())
    assert {profile["mode"] for profile in profiles["items"]} == {"deterministic", "cloud"}
    assert {profile["provider"] for profile in profiles["items"]} == {"rules", "deepseek"}


def test_native_launchers_and_required_runtime_sources_are_preserved() -> None:
    required = [
        "启动AgentGuard.cmd", "停止本机.cmd", "配置智能体.cmd", "scripts/agentguard-desktop.vbs",
        "scripts/native_runtime.py", "scripts/native-up.ps1", "scripts/native_config.py",
        "scripts/configure-deepseek.ps1", "requirements.lock", "frontend/package-lock.json",
        "backend/crypto/sm.py", "backend/admission/service.py", "backend/gateway/service.py",
    ]
    assert all((ROOT / name).is_file() for name in required)
